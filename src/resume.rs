//! Private, locked transfer checkpoints. Completed blobs are removed after publication or upload.
use crate::{
    Error, Result,
    config::{TransferConfig, parse_size},
    digest::Digest,
    model::Descriptor,
    storage,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    ops::Range,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Session {
    pub url: String,
    pub minimum_chunk: u64,
}
#[derive(Serialize, Deserialize)]
struct Part {
    start: u64,
    end: u64,
    offset: u64,
}
#[derive(Serialize, Deserialize)]
struct State {
    version: u32,
    digest: Digest,
    size: u64,
    parts: Vec<Part>,
    session: Option<Session>,
}
#[derive(Default)]
struct Files {
    sizes: BTreeMap<PathBuf, u64>,
    active: BTreeSet<PathBuf>,
}
pub(crate) struct Store {
    root: PathBuf,
    limit: u64,
    files: Mutex<Files>,
    _lock: File,
}
pub(crate) struct Blob {
    pub path: PathBuf,
    state_path: PathBuf,
    state: Mutex<State>,
    store: Arc<Store>,
}
pub(crate) enum Staging {
    Temporary(tempfile::NamedTempFile),
    Resumed(Arc<Blob>),
}
impl Staging {
    pub fn new(store: Option<&Arc<Store>>, descriptor: &Descriptor) -> Result<Self> {
        match store {
            Some(store) => Ok(Self::Resumed(store.blob(descriptor)?)),
            None => Ok(Self::Temporary(tempfile::NamedTempFile::new()?)),
        }
    }
    pub fn path(&self) -> &Path {
        match self {
            Self::Temporary(file) => file.path(),
            Self::Resumed(blob) => &blob.path,
        }
    }
    pub fn resume(&self) -> Option<&Blob> {
        match self {
            Self::Resumed(blob) => Some(blob),
            _ => None,
        }
    }
    pub fn complete(&self) -> Result<()> {
        match self.resume() {
            Some(blob) => blob.complete(),
            None => Ok(()),
        }
    }
}

impl Store {
    pub fn open(key: &str, config: &TransferConfig) -> Result<Arc<Self>> {
        let base = match &config.resume_dir {
            Some(path) => path.clone(),
            None => dirs::cache_dir()
                .ok_or_else(|| {
                    Error::input(
                        "cannot locate resume cache directory; configure transfer.resume_dir",
                    )
                })?
                .join("quayside/transfers"),
        };
        storage::reject_symlink(&base)?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&base)?;
        storage::restrict(&base, true)?;
        let root = base.join(Digest::sha256(key.as_bytes()).encoded());
        storage::reject_symlink(&root)?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)?;
        storage::restrict(&root, true)?;
        let lock_path = root.join("lock");
        storage::reject_symlink(&lock_path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)?;
        storage::check_private_file(&lock_path)?;
        lock.try_lock_exclusive()
            .map_err(|_| Error::conflict("another process is using this resumable transfer"))?;
        let mut files = Files::default();
        for entry in fs::read_dir(&root)? {
            let path = entry?.path();
            storage::reject_symlink(&path)?;
            if path.extension().is_some_and(|v| v == "blob") {
                storage::check_private_file(&path)?;
                files.sizes.insert(path.clone(), fs::metadata(path)?.len());
            }
        }
        Ok(Arc::new(Self {
            root,
            limit: parse_size(&config.max_temp_size)?,
            files: Mutex::new(files),
            _lock: lock,
        }))
    }

    pub fn clear(&self) -> Result<()> {
        let mut files = self.files.lock().expect("resume files lock");
        if !files.active.is_empty() {
            return Err(Error::conflict("cannot clear active transfer checkpoints"));
        }
        for path in files.sizes.keys() {
            remove(path)?;
            remove(&path.with_extension("json"))?;
        }
        files.sizes.clear();
        Ok(())
    }

    pub fn blob(self: &Arc<Self>, descriptor: &Descriptor) -> Result<Arc<Blob>> {
        let path = self.root.join(format!(
            "{}-{}.blob",
            descriptor.digest.algorithm(),
            descriptor.digest.encoded()
        ));
        let state_path = path.with_extension("json");
        let mut files = self.files.lock().expect("resume files lock");
        if files.active.contains(&path) {
            return Err(Error::conflict("blob is already active in this transfer"));
        }
        if descriptor.size > self.limit {
            return Err(Error::input("blob exceeds resume storage limit"));
        }
        files.sizes.remove(&path);
        while files
            .sizes
            .values()
            .fold(0u64, |total, size| total.saturating_add(*size))
            .saturating_add(descriptor.size)
            > self.limit
        {
            let victim = files
                .sizes
                .keys()
                .find(|p| !files.active.contains(*p))
                .cloned()
                .ok_or_else(|| Error::input("resume storage is occupied by active transfers"))?;
            remove(&victim)?;
            remove(&victim.with_extension("json"))?;
            files.sizes.remove(&victim);
        }
        storage::reject_symlink(&path)?;
        storage::reject_symlink(&state_path)?;
        let state = if state_path.exists() && path.exists() {
            storage::check_private_file(&state_path)?;
            if fs::metadata(&state_path)?.len() > 64 * 1024 {
                return Err(Error::input("resume checkpoint exceeds size limit"));
            }
            serde_json::from_slice::<State>(&fs::read(&state_path)?)
                .ok()
                .filter(|s| {
                    s.version == 1
                        && s.digest == descriptor.digest
                        && s.size == descriptor.size
                        && s.parts.len() <= 32
                        && (s.parts.is_empty()
                            || (s.parts[0].start == 0
                                && s.parts.last().is_some_and(|p| p.end == s.size)
                                && s.parts.windows(2).all(|pair| pair[0].end == pair[1].start)))
                        && s.parts
                            .iter()
                            .all(|p| p.start <= p.offset && p.offset <= p.end && p.end <= s.size)
                })
        } else {
            None
        };
        let state = match state {
            Some(state) => state,
            None => {
                remove(&path)?;
                State {
                    version: 1,
                    digest: descriptor.digest.clone(),
                    size: descriptor.size,
                    parts: vec![],
                    session: None,
                }
            }
        };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)?;
        storage::check_private_file(&path)?;
        if file.metadata()?.len() > descriptor.size {
            file.set_len(0)?;
        }
        files.sizes.insert(path.clone(), descriptor.size);
        files.active.insert(path.clone());
        drop(files);
        let blob = Arc::new(Blob {
            path,
            state_path,
            state: Mutex::new(state),
            store: self.clone(),
        });
        blob.save()?;
        Ok(blob)
    }
}

impl Blob {
    fn save(&self) -> Result<()> {
        storage::atomic_write(
            &self.state_path,
            &serde_json::to_vec(&*self.state.lock().expect("resume state lock"))?,
        )
    }
    pub fn ranges(&self, ranges: &[Range<u64>]) -> Result<()> {
        let mut state = self.state.lock().expect("resume state lock");
        let length = fs::metadata(&self.path)?.len();
        if state.parts.len() != ranges.len()
            || state
                .parts
                .iter()
                .zip(ranges)
                .any(|(p, r)| p.start != r.start || p.end != r.end || p.offset > length)
        {
            state.parts = ranges
                .iter()
                .map(|r| Part {
                    start: r.start,
                    end: r.end,
                    offset: r.start,
                })
                .collect();
            state.session = None;
            File::options().write(true).open(&self.path)?.set_len(0)?;
        }
        drop(state);
        self.save()
    }
    pub fn saved_ranges(&self) -> Vec<Range<u64>> {
        self.state
            .lock()
            .expect("resume state lock")
            .parts
            .iter()
            .map(|p| p.start..p.end)
            .collect()
    }
    pub fn downloaded(&self, size: u64) -> Result<()> {
        let file = File::options().write(true).open(&self.path)?;
        file.sync_data()?;
        let mut state = self.state.lock().expect("resume state lock");
        state.parts = vec![Part {
            start: 0,
            end: size,
            offset: size,
        }];
        storage::atomic_write(&self.state_path, &serde_json::to_vec(&*state)?)
    }
    pub fn offset(&self, start: u64) -> u64 {
        self.state
            .lock()
            .expect("resume state lock")
            .parts
            .iter()
            .find(|p| p.start == start)
            .map_or(start, |p| p.offset)
    }
    pub fn checkpoint(&self, start: u64, offset: u64) -> Result<()> {
        let mut state = self.state.lock().expect("resume state lock");
        let part = state
            .parts
            .iter_mut()
            .find(|p| p.start == start)
            .ok_or_else(|| Error::integrity("missing resume range"))?;
        if offset < start || offset > part.end {
            return Err(Error::integrity("invalid resume offset"));
        }
        part.offset = offset;
        // Keep serialization and replacement under one lock, so parallel ranges cannot write stale snapshots.
        storage::atomic_write(&self.state_path, &serde_json::to_vec(&*state)?)
    }
    pub fn session(&self) -> Option<Session> {
        self.state
            .lock()
            .expect("resume state lock")
            .session
            .clone()
    }
    pub fn set_session(&self, session: Option<Session>) -> Result<()> {
        self.state.lock().expect("resume state lock").session = session;
        self.save()
    }
    pub fn reset(&self) -> Result<()> {
        let mut state = self.state.lock().expect("resume state lock");
        state.parts.clear();
        state.session = None;
        drop(state);
        self.save()?;
        File::options().write(true).open(&self.path)?.set_len(0)?;
        Ok(())
    }
    pub fn complete(&self) -> Result<()> {
        remove(&self.path)?;
        remove(&self.state_path)?;
        self.store
            .files
            .lock()
            .expect("resume files lock")
            .sizes
            .remove(&self.path);
        Ok(())
    }
}
impl Drop for Blob {
    fn drop(&mut self) {
        self.store
            .files
            .lock()
            .expect("resume files lock")
            .active
            .remove(&self.path);
    }
}
fn remove(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn checkpoints_are_private_locked_bounded_and_survive_reopening() {
        let directory = tempfile::tempdir().unwrap();
        let config = TransferConfig {
            resume_dir: Some(directory.path().join("resume")),
            max_temp_size: "8".into(),
            ..Default::default()
        };
        let first = Descriptor::new("application/octet-stream", Digest::sha256(b"abcdefgh"), 8);
        let second = Descriptor::new("application/octet-stream", Digest::sha256(b"12345678"), 8);
        let store = Store::open("copy", &config).unwrap();
        assert!(Store::open("copy", &config).is_err());
        let blob = store.blob(&first).unwrap();
        blob.ranges(std::slice::from_ref(&(0..8))).unwrap();
        fs::write(&blob.path, b"abcd").unwrap();
        blob.checkpoint(0, 4).unwrap();
        assert_eq!(
            fs::metadata(&blob.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&blob.state_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(store.blob(&second).is_err());
        drop(blob);
        drop(store);
        let store = Store::open("copy", &config).unwrap();
        let blob = store.blob(&first).unwrap();
        assert_eq!(blob.offset(0), 4);
        let old_path = blob.path.clone();
        drop(blob);
        let replacement = store.blob(&second).unwrap();
        assert!(!old_path.exists());
        let path = replacement.path.clone();
        replacement.complete().unwrap();
        drop(replacement);
        symlink(directory.path().join("victim"), path).unwrap();
        assert!(store.blob(&second).is_err());
    }
}
