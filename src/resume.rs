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
    io_lock: Mutex<()>,
    _lock: File,
}
pub(crate) struct Blob {
    pub path: PathBuf,
    state_path: PathBuf,
    state: Mutex<State>,
    io_lock: Mutex<()>,
    store: Arc<Store>,
}
pub(crate) enum Staging {
    Temporary(tempfile::NamedTempFile),
    Resumed(Arc<Blob>),
}
impl Staging {
    pub async fn new(store: Option<&Arc<Store>>, descriptor: &Descriptor) -> Result<Self> {
        match store {
            Some(store) => Ok(Self::Resumed(store.blob(descriptor).await?)),
            None => disk(|| Ok(Self::Temporary(tempfile::NamedTempFile::new()?))).await,
        }
    }
    pub fn path(&self) -> &Path {
        match self {
            Self::Temporary(file) => file.path(),
            Self::Resumed(blob) => &blob.path,
        }
    }
    pub fn resume(&self) -> Option<&Arc<Blob>> {
        match self {
            Self::Resumed(blob) => Some(blob),
            _ => None,
        }
    }
    pub async fn complete(&self) -> Result<()> {
        match self.resume() {
            Some(blob) => blob.complete().await,
            None => Ok(()),
        }
    }
}

async fn disk<T: Send + 'static>(work: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(work).await.map_err(|_| {
        Error::new(
            crate::error::Code::Execution,
            "resume storage worker failed",
        )
    })?
}

impl Store {
    pub async fn open(key: &str, config: &TransferConfig) -> Result<Arc<Self>> {
        let key = key.to_owned();
        let config = config.clone();
        disk(move || Self::open_blocking(&key, &config)).await
    }

    fn open_blocking(key: &str, config: &TransferConfig) -> Result<Arc<Self>> {
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
            io_lock: Mutex::new(()),
            _lock: lock,
        }))
    }

    pub async fn clear(self: &Arc<Self>) -> Result<()> {
        let store = self.clone();
        disk(move || {
            let _io = store.io_lock.lock().expect("resume storage I/O lock");
            if !store
                .files
                .lock()
                .expect("resume files lock")
                .active
                .is_empty()
            {
                return Err(Error::conflict("cannot clear active transfer checkpoints"));
            }
            for entry in fs::read_dir(&store.root)? {
                let path = entry?.path();
                if path.extension().is_some_and(|e| e == "blob" || e == "json") {
                    storage::check_private_file(&path)?;
                    remove(&path)?;
                }
            }
            store.files.lock().expect("resume files lock").sizes.clear();
            Ok(())
        })
        .await
    }

    pub async fn blob(self: &Arc<Self>, descriptor: &Descriptor) -> Result<Arc<Blob>> {
        let store = self.clone();
        let descriptor = descriptor.clone();
        disk(move || {
            let _io = store.io_lock.lock().expect("resume storage I/O lock");
            store.blob_blocking(&descriptor)
        })
        .await
    }

    fn blob_blocking(self: &Arc<Self>, descriptor: &Descriptor) -> Result<Arc<Blob>> {
        let path = self.root.join(format!(
            "{}-{}.blob",
            descriptor.digest.algorithm(),
            descriptor.digest.encoded()
        ));
        let state_path = path.with_extension("json");
        if self
            .files
            .lock()
            .expect("resume files lock")
            .active
            .contains(&path)
        {
            return Err(Error::conflict("blob is already active in this transfer"));
        }
        if descriptor.size > self.limit {
            return Err(Error::input("blob exceeds resume storage limit"));
        }
        loop {
            let victim = {
                let files = self.files.lock().expect("resume files lock");
                let total = files
                    .sizes
                    .iter()
                    .filter(|(p, _)| *p != &path)
                    .fold(descriptor.size, |total, (_, size)| {
                        total.saturating_add(*size)
                    });
                if total <= self.limit {
                    break;
                }
                files
                    .sizes
                    .keys()
                    .find(|p| *p != &path && !files.active.contains(*p))
                    .cloned()
                    .ok_or_else(|| Error::input("resume storage is occupied by active transfers"))?
            };
            remove(&victim)?;
            remove(&victim.with_extension("json"))?;
            self.files
                .lock()
                .expect("resume files lock")
                .sizes
                .remove(&victim);
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
                        && s.parts.iter().all(|p| {
                            (p.start < p.end || (s.size == 0 && s.parts.len() == 1))
                                && p.start <= p.offset
                                && p.offset <= p.end
                                && p.end <= s.size
                        })
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
        {
            let mut files = self.files.lock().expect("resume files lock");
            files.sizes.insert(path.clone(), descriptor.size);
            files.active.insert(path.clone());
        }
        let blob = Arc::new(Blob {
            path,
            state_path,
            state: Mutex::new(state),
            io_lock: Mutex::new(()),
            store: self.clone(),
        });
        blob.save()?;
        Ok(blob)
    }
}

impl Blob {
    async fn write(
        self: &Arc<Self>,
        operation: impl FnOnce(&Self) -> Result<()> + Send + 'static,
    ) -> Result<()> {
        let blob = self.clone();
        disk(move || {
            // Keep the blob and transfer lock alive until a cancelled job finishes writing.
            let _io = blob.io_lock.lock().expect("resume blob I/O lock");
            operation(&blob)
        })
        .await
    }

    fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec(&*self.state.lock().expect("resume state lock"))?;
        storage::atomic_write(&self.state_path, &bytes)
    }

    pub async fn ranges(self: &Arc<Self>, ranges: &[Range<u64>]) -> Result<()> {
        let ranges = ranges.to_vec();
        self.write(move |blob| {
            let length = fs::metadata(&blob.path)?.len();
            let reset = {
                let mut state = blob.state.lock().expect("resume state lock");
                let reset =
                    state.parts.len() != ranges.len()
                        || state.parts.iter().zip(&ranges).any(|(p, r)| {
                            p.start != r.start || p.end != r.end || p.offset > length
                        });
                if reset {
                    state.parts = ranges
                        .iter()
                        .map(|r| Part {
                            start: r.start,
                            end: r.end,
                            offset: r.start,
                        })
                        .collect();
                    state.session = None;
                }
                reset
            };
            if reset {
                File::options().write(true).open(&blob.path)?.set_len(0)?;
            }
            blob.save()
        })
        .await
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

    pub async fn downloaded(self: &Arc<Self>, size: u64) -> Result<()> {
        self.write(move |blob| {
            File::options().write(true).open(&blob.path)?.sync_data()?;
            blob.state.lock().expect("resume state lock").parts = vec![Part {
                start: 0,
                end: size,
                offset: size,
            }];
            blob.save()
        })
        .await
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

    pub async fn checkpoint(self: &Arc<Self>, start: u64, offset: u64) -> Result<()> {
        self.write(move |blob| {
            {
                let mut state = blob.state.lock().expect("resume state lock");
                let part = state
                    .parts
                    .iter_mut()
                    .find(|p| p.start == start)
                    .ok_or_else(|| Error::integrity("missing resume range"))?;
                if offset < start || offset > part.end {
                    return Err(Error::integrity("invalid resume offset"));
                }
                part.offset = offset;
            }
            // The I/O gate orders snapshots and replacements without blocking state readers.
            blob.save()
        })
        .await
    }

    pub fn session(&self) -> Option<Session> {
        self.state
            .lock()
            .expect("resume state lock")
            .session
            .clone()
    }

    pub async fn set_session(self: &Arc<Self>, session: Option<Session>) -> Result<()> {
        self.write(move |blob| {
            blob.state.lock().expect("resume state lock").session = session;
            blob.save()
        })
        .await
    }

    pub async fn reset(self: &Arc<Self>) -> Result<()> {
        self.write(|blob| {
            {
                let mut state = blob.state.lock().expect("resume state lock");
                state.parts.clear();
                state.session = None;
            }
            blob.save()?;
            File::options().write(true).open(&blob.path)?.set_len(0)?;
            Ok(())
        })
        .await
    }

    pub async fn complete(self: &Arc<Self>) -> Result<()> {
        self.write(|blob| {
            remove(&blob.path)?;
            remove(&blob.state_path)?;
            blob.store
                .files
                .lock()
                .expect("resume files lock")
                .sizes
                .remove(&blob.path);
            Ok(())
        })
        .await
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

    #[tokio::test]
    async fn successful_cleanup_removes_orphaned_session_checkpoints() {
        let directory = tempfile::tempdir().unwrap();
        let config = TransferConfig {
            resume_dir: Some(directory.path().to_owned()),
            ..Default::default()
        };
        let store = Store::open("orphaned-session", &config).await.unwrap();
        let descriptor = Descriptor::new("application/octet-stream", Digest::sha256(b"blob"), 4);
        let blob = store.blob(&descriptor).await.unwrap();
        blob.set_session(Some(Session {
            url: "https://registry.example/upload?token=private".into(),
            minimum_chunk: 0,
        }))
        .await
        .unwrap();
        fs::remove_file(&blob.path).unwrap();
        let checkpoint = blob.state_path.clone();
        drop(blob);
        drop(store);

        let store = Store::open("orphaned-session", &config).await.unwrap();
        store.clear().await.unwrap();
        assert!(!checkpoint.exists());
        assert!(store.root.join("lock").is_file());
        assert_eq!(fs::read_dir(&store.root).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn checkpoints_are_private_locked_bounded_and_survive_reopening() {
        let directory = tempfile::tempdir().unwrap();
        let config = TransferConfig {
            resume_dir: Some(directory.path().join("resume")),
            max_temp_size: "8".into(),
            ..Default::default()
        };
        let first = Descriptor::new("application/octet-stream", Digest::sha256(b"abcdefgh"), 8);
        let second = Descriptor::new("application/octet-stream", Digest::sha256(b"12345678"), 8);
        let store = Store::open("copy", &config).await.unwrap();
        assert!(Store::open("copy", &config).await.is_err());
        let blob = store.blob(&first).await.unwrap();
        blob.ranges(std::slice::from_ref(&(0..8))).await.unwrap();
        fs::write(&blob.path, b"abcd").unwrap();
        blob.checkpoint(0, 4).await.unwrap();
        assert_eq!(
            fs::metadata(&blob.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&blob.state_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(store.blob(&second).await.is_err());
        drop(blob);
        drop(store);
        let store = Store::open("copy", &config).await.unwrap();
        let blob = store.blob(&first).await.unwrap();
        assert_eq!(blob.offset(0), 4);
        let old_path = blob.path.clone();
        drop(blob);
        let replacement = store.blob(&second).await.unwrap();
        assert!(!old_path.exists());
        let path = replacement.path.clone();
        replacement.complete().await.unwrap();
        drop(replacement);
        symlink(directory.path().join("victim"), path).unwrap();
        assert!(store.blob(&second).await.is_err());
    }

    #[tokio::test]
    async fn cached_ranges_reject_empty_partitions_except_for_an_empty_blob() {
        let directory = tempfile::tempdir().unwrap();
        let config = TransferConfig {
            resume_dir: Some(directory.path().to_owned()),
            ..Default::default()
        };
        let store = Store::open("partition-validation", &config).await.unwrap();
        for (raw, ranges, valid) in [
            (b"abcd".as_slice(), vec![0..0, 0..4], false),
            (b"abcd".as_slice(), vec![0..2, 2..2, 2..4], false),
            (b"".as_slice(), vec![0..0, 0..0], false),
            (b"".as_slice(), std::iter::once(0..0).collect(), true),
            (b"abcd".as_slice(), vec![0..2, 2..4], true),
        ] {
            let descriptor = Descriptor::new(
                "application/octet-stream",
                Digest::sha256(raw),
                raw.len() as u64,
            );
            let blob = store.blob(&descriptor).await.unwrap();
            fs::write(&blob.path, raw).unwrap();
            let state = State {
                version: 1,
                digest: descriptor.digest.clone(),
                size: descriptor.size,
                parts: ranges
                    .iter()
                    .map(|range| Part {
                        start: range.start,
                        end: range.end,
                        offset: range.start,
                    })
                    .collect(),
                session: Some(Session {
                    url: "https://registry.example/upload".into(),
                    minimum_chunk: 0,
                }),
            };
            storage::atomic_write(&blob.state_path, &serde_json::to_vec(&state).unwrap()).unwrap();
            drop(blob);

            let reopened = store.blob(&descriptor).await.unwrap();
            if valid {
                assert_eq!(reopened.saved_ranges(), ranges);
                assert!(reopened.session().is_some());
                assert_eq!(fs::read(&reopened.path).unwrap(), raw);
            } else {
                assert!(
                    reopened.saved_ranges().is_empty(),
                    "invalid partition was reused: {ranges:?}"
                );
                assert!(reopened.session().is_none());
                assert_eq!(fs::metadata(&reopened.path).unwrap().len(), 0);
            }
            drop(reopened);
        }
    }
}

#[cfg(test)]
#[path = "resume/concurrency_tests.rs"]
mod concurrency_tests;
