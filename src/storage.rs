//! Private, locked, atomic configuration/credential writes.
use crate::{Error, Result};
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

/// Return a path's containing directory, treating a bare filename as relative to the current directory.
pub fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}
/// Reject a symlink at the supplied path while allowing a missing destination.
pub fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(Error::input(format!(
            "refusing symlink: {}",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
fn prepare_parent(path: &Path) -> Result<()> {
    let dir = parent(path);
    if !dir.exists() {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        restrict(dir, true)?;
    }
    reject_symlink(dir)?;
    reject_symlink(path)
}

/// Set owner-only permissions on a file or directory and reject symlink targets.
pub fn restrict(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    reject_symlink(path)?;
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
    )?;
    Ok(())
}

/// Require an existing regular credential/key file to have owner-only permissions.
pub fn check_private_file(path: &Path) -> Result<()> {
    reject_symlink(path)?;
    {
        use std::os::unix::fs::PermissionsExt;
        let m = fs::metadata(path)?;
        if !m.is_file() {
            return Err(Error::input("credential storage requires regular files"));
        }
        if m.permissions().mode() & 0o077 != 0 {
            return Err(Error::input(format!(
                "credential file is accessible to other users; run chmod 600 {}",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Run a storage update while holding the cooperating processes' sidecar file lock.
pub fn with_lock<T>(path: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    prepare_parent(path)?;
    let name = path
        .file_name()
        .ok_or_else(|| Error::input("configuration path needs a filename"))?
        .to_string_lossy();
    let lock_path: PathBuf = parent(path).join(format!(".{name}.lock"));
    reject_symlink(&lock_path)?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(&lock_path)?;
    restrict(&lock_path, false)?;
    FileExt::lock_exclusive(&lock)?;
    let result = f();
    let _ = FileExt::unlock(&lock);
    result
}

/// Persist bytes through a private temporary file and atomic replacement under its parent directory.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    prepare_parent(path)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent(path))?;
    // Set privacy before writing a single secret byte.
    restrict(temp.path(), false)?;
    temp.write_all(data)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| Error::from(e.error))?;
    {
        File::open(parent(path))?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn atomic_private_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");
        with_lock(&path, || atomic_write(&path, b"{}\n")).unwrap();
        check_private_file(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"{}\n");
    }
    #[test]
    fn symlink_rejected() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("link");
        std::os::unix::fs::symlink("/dev/null", &p).unwrap();
        assert!(atomic_write(&p, b"x").is_err());
    }
    #[test]
    fn privacy_helpers_reject_symlinks_and_non_regular_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        fs::write(&file, b"contents").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(restrict(&link, false).is_err());
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(check_private_file(&link).is_err());
        restrict(dir.path(), true).unwrap();
        assert!(check_private_file(dir.path()).is_err());
        restrict(&file, false).unwrap();
        check_private_file(&file).unwrap();
    }
}
