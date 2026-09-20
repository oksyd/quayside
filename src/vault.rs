//! Versioned authenticated credential storage. Keys are never created while reading ciphertext.
use crate::{
    Error, Result,
    auth::{AuthFile, Credential},
    storage,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const MAX_PLAINTEXT: usize = 4 * 1024 * 1024;
const MAX_ENVELOPE: usize = 6 * 1024 * 1024;
const AAD: &[u8] = b"quayside-auth:v2:AES-256-GCM";

#[derive(Deserialize)]
struct Version {
    version: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    algorithm: String,
    nonce: String,
    ciphertext: String,
}
fn invalid() -> Error {
    Error::input("invalid credential file")
}
fn empty() -> AuthFile {
    AuthFile {
        version: 1,
        registries: BTreeMap::new(),
    }
}

// Resolve existing ancestors too, so equivalent relative/symlinked parent paths cannot deadlock
// the nested auth/key locks or overwrite the other file's lock.
fn resolved(path: &Path) -> Result<PathBuf> {
    if path.try_exists()? {
        return Ok(fs::canonicalize(path)?);
    }
    let name = path
        .file_name()
        .ok_or_else(|| Error::input("credential paths require filenames"))?;
    Ok(resolved(storage::parent(path))?.join(name))
}
fn validate_paths(path: &Path, keyfile: &Path) -> Result<()> {
    storage::reject_symlink(path)?;
    storage::reject_symlink(keyfile)?;
    for parent in [storage::parent(path), storage::parent(keyfile)] {
        storage::reject_symlink(parent)?;
        if parent.try_exists()? {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(parent)?;
            if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::input(format!(
                    "credential storage directory must be private; use a directory with mode 700: {}",
                    parent.display()
                )));
            }
        }
    }
    let auth = resolved(path)?;
    let key = resolved(keyfile)?;
    let lock = |p: &Path| {
        storage::parent(p).join(format!(
            ".{}.lock",
            p.file_name().unwrap().to_string_lossy()
        ))
    };
    if auth == key || auth == lock(&key) || key == lock(&auth) {
        return Err(Error::input(
            "credential file, master key and lock paths must be distinct",
        ));
    }
    Ok(())
}
fn read_private(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    storage::check_private_file(path)?;
    if !fs::metadata(path)?.is_file() {
        return Err(Error::input("credential storage requires regular files"));
    }
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(Error::input("credential storage requires regular files"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(Error::input("credential storage file exceeds size limit"));
    }
    Ok(bytes)
}
fn version(bytes: &[u8]) -> Result<u32> {
    Ok(serde_json::from_slice::<Version>(bytes)
        .map_err(|_| invalid())?
        .version)
}
fn plaintext(bytes: &[u8]) -> Result<AuthFile> {
    if bytes.len() > MAX_PLAINTEXT {
        return Err(Error::input("credential payload exceeds size limit"));
    }
    let auth: AuthFile = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if auth.version != 1 {
        return Err(invalid());
    }
    Ok(auth)
}
fn key_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    storage::reject_symlink(path)?;
    if !path.try_exists()? {
        return Err(Error::input(
            "master key is missing; restore the original key or explicitly use a new credential file to log in again",
        ));
    }
    let bytes = read_private(path, 32)?;
    if bytes.len() != 32 {
        return Err(Error::input("invalid master key; expected 32 bytes"));
    }
    Ok(bytes)
}
fn get_or_create_key(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    storage::with_lock(path, || {
        if path.try_exists()? {
            return key_bytes(path);
        }
        let mut bytes = Zeroizing::new(vec![0; 32]);
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| Error::input("secure key generation failed"))?;
        storage::atomic_write(path, &bytes)?;
        Ok(bytes)
    })
}
fn cipher(key: &[u8]) -> Result<aead::LessSafeKey> {
    aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map(aead::LessSafeKey::new)
        .map_err(|_| Error::input("invalid encryption key"))
}
fn decrypt(bytes: &[u8], keyfile: &Path) -> Result<AuthFile> {
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if envelope.version != 2 || envelope.algorithm != "AES-256-GCM" {
        return Err(invalid());
    }
    let nonce: [u8; 12] = STANDARD
        .decode(&envelope.nonce)
        .map_err(|_| invalid())?
        .try_into()
        .map_err(|_| invalid())?;
    let mut ciphertext = Zeroizing::new(
        STANDARD
            .decode(&envelope.ciphertext)
            .map_err(|_| invalid())?,
    );
    let key = key_bytes(keyfile)?;
    let cipher = cipher(&key)?;
    let plain = cipher
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(AAD),
            &mut ciphertext,
        )
        .map_err(|_| Error::integrity("credential decryption failed: wrong key or damaged file"))?;
    plaintext(plain)
}
fn save(path: &Path, auth: &AuthFile, key: &[u8]) -> Result<()> {
    let mut bytes = Zeroizing::new(serde_json::to_vec(auth)?);
    if bytes.len() > MAX_PLAINTEXT {
        return Err(Error::input("credential payload exceeds size limit"));
    }
    // Fresh CSPRNG-generated 96-bit nonce on every write, including concurrent processes.
    let mut nonce = [0; 12];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| Error::input("secure nonce generation failed"))?;
    cipher(key)?
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(AAD),
            &mut *bytes,
        )
        .map_err(|_| Error::input("credential encryption failed"))?;
    let envelope = Envelope {
        version: 2,
        algorithm: "AES-256-GCM".into(),
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(&*bytes),
    };
    storage::atomic_write(path, &serde_json::to_vec_pretty(&envelope)?)
}
pub(crate) fn load(path: &Path, keyfile: &Path) -> Result<AuthFile> {
    validate_paths(path, keyfile)?;
    if !path.try_exists()? {
        return Ok(empty());
    }
    let bytes = read_private(path, MAX_ENVELOPE)?;
    match version(&bytes)? {
        1 => Err(Error::input(
            "plaintext credentials require explicit migration: run `quayside auth migrate` with the same --authfile and --keyfile options",
        )),
        2 => decrypt(&bytes, keyfile),
        _ => Err(Error::input("unsupported credential file version")),
    }
}
pub(crate) fn put(
    path: &Path,
    keyfile: &Path,
    registry: &str,
    credential: Credential,
) -> Result<()> {
    validate_paths(path, keyfile)?;
    storage::with_lock(path, || {
        // Load first: existing ciphertext with a missing/bad key must never cause key regeneration.
        let mut auth = load(path, keyfile)?;
        let key = get_or_create_key(keyfile)?;
        auth.registries.insert(registry.to_owned(), credential);
        save(path, &auth, &key)
    })
}
pub(crate) fn remove(path: &Path, keyfile: &Path, registry: &str) -> Result<bool> {
    validate_paths(path, keyfile)?;
    if !path.try_exists()? {
        return Ok(false);
    }
    storage::with_lock(path, || {
        let mut auth = load(path, keyfile)?;
        if auth.registries.remove(registry).is_none() {
            return Ok(false);
        }
        save(path, &auth, &key_bytes(keyfile)?)?;
        Ok(true)
    })
}
pub(crate) fn migrate(path: &Path, keyfile: &Path) -> Result<bool> {
    validate_paths(path, keyfile)?;
    storage::with_lock(path, || {
        let bytes = read_private(path, MAX_ENVELOPE)?;
        match version(&bytes)? {
            1 => {
                let auth = plaintext(&bytes)?;
                let key = get_or_create_key(keyfile)?;
                save(path, &auth, &key)?;
                Ok(true)
            }
            2 => {
                decrypt(&bytes, keyfile)?;
                Ok(false)
            }
            _ => Err(Error::input("unsupported credential file version")),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn credential() -> Credential {
        Credential {
            username: "private-user".into(),
            secret: "private-token".into(),
        }
    }
    #[test]
    fn encrypted_round_trip_fresh_nonce_and_private_permissions() {
        let root = tempfile::tempdir().unwrap();
        storage::restrict(root.path(), true).unwrap();
        let auth = root.path().join("config/auth.json");
        let key = root.path().join("data/master.key");
        put(&auth, &key, "example.com", credential()).unwrap();
        let before = fs::read_to_string(&auth).unwrap();
        for secret in ["private-user", "private-token", "example.com"] {
            assert!(!before.contains(secret));
        }
        assert_eq!(
            load(&auth, &key).unwrap().registries["example.com"].secret,
            "private-token"
        );
        let original_key = fs::read(&key).unwrap();
        put(&auth, &key, "example.com", credential()).unwrap();
        let after = fs::read_to_string(&auth).unwrap();
        let first: Envelope = serde_json::from_str(&before).unwrap();
        let second: Envelope = serde_json::from_str(&after).unwrap();
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
        assert_eq!(fs::read(&key).unwrap(), original_key);
        for path in [&auth, &key] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(storage::parent(path))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }
    #[test]
    fn missing_wrong_or_insecure_key_never_replaces_ciphertext() {
        let root = tempfile::tempdir().unwrap();
        storage::restrict(root.path(), true).unwrap();
        let auth = root.path().join("auth.json");
        let key = root.path().join("key");
        put(&auth, &key, "a", credential()).unwrap();
        let before = fs::read(&auth).unwrap();
        let original_key = fs::read(&key).unwrap();
        fs::remove_file(&key).unwrap();
        assert!(put(&auth, &key, "b", credential()).is_err());
        assert!(!key.exists());
        assert_eq!(fs::read(&auth).unwrap(), before);
        storage::atomic_write(&key, &[42; 32]).unwrap();
        assert!(load(&auth, &key).is_err());
        assert!(remove(&auth, &key, "a").is_err());
        assert_eq!(fs::read(&auth).unwrap(), before);
        storage::atomic_write(&key, &original_key).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&auth, &key).is_err());
    }
    #[test]
    fn tampering_and_unknown_formats_fail_without_disclosing_secrets() {
        let root = tempfile::tempdir().unwrap();
        storage::restrict(root.path(), true).unwrap();
        let auth = root.path().join("auth.json");
        let key = root.path().join("key");
        put(&auth, &key, "a", credential()).unwrap();
        let original: serde_json::Value =
            serde_json::from_slice(&fs::read(&auth).unwrap()).unwrap();
        for field in ["nonce", "ciphertext", "algorithm", "version"] {
            let mut value = original.clone();
            if field == "version" {
                value[field] = serde_json::json!(99);
            } else if field == "algorithm" {
                value[field] = serde_json::json!("unknown");
            } else {
                let mut data = STANDARD.decode(value[field].as_str().unwrap()).unwrap();
                data[0] ^= 1;
                value[field] = serde_json::json!(STANDARD.encode(data));
            }
            storage::atomic_write(&auth, &serde_json::to_vec(&value).unwrap()).unwrap();
            let error = load(&auth, &key).err().unwrap().to_string();
            assert!(!error.contains("private-token"));
            assert!(!error.contains("private-user"));
        }
    }
    #[test]
    fn migration_is_explicit_atomic_and_idempotent() {
        let root = tempfile::tempdir().unwrap();
        storage::restrict(root.path(), true).unwrap();
        let auth = root.path().join("auth.json");
        let key = root.path().join("data/key");
        let mut old = empty();
        old.registries.insert("a".into(), credential());
        let bytes = serde_json::to_vec(&old).unwrap();
        storage::atomic_write(&auth, &bytes).unwrap();
        assert!(load(&auth, &key).is_err());
        assert!(!key.exists());
        assert_eq!(fs::read(&auth).unwrap(), bytes);
        assert!(migrate(&auth, &key).unwrap());
        let encrypted = fs::read(&auth).unwrap();
        assert!(!migrate(&auth, &key).unwrap());
        assert_eq!(fs::read(&auth).unwrap(), encrypted);
        assert_eq!(
            load(&auth, &key).unwrap().registries["a"].secret,
            "private-token"
        );
        assert!(!root.path().join("auth.json.bak").exists());
    }
    #[test]
    fn failed_migration_preserves_plaintext_and_rejects_public_directory() {
        let root = tempfile::tempdir().unwrap();
        storage::restrict(root.path(), true).unwrap();
        let auth = root.path().join("auth.json");
        let key = root.path().join("key");
        let mut old = empty();
        old.registries.insert("a".into(), credential());
        let bytes = serde_json::to_vec(&old).unwrap();
        storage::atomic_write(&auth, &bytes).unwrap();
        storage::atomic_write(&key, b"invalid key").unwrap();
        assert!(migrate(&auth, &key).is_err());
        assert_eq!(fs::read(&auth).unwrap(), bytes);
        assert_eq!(fs::read(&key).unwrap(), b"invalid key");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(migrate(&auth, &key).is_err());
        assert_eq!(fs::read(&auth).unwrap(), bytes);
    }

    #[test]
    fn concurrent_writers_share_key_without_losing_accounts() {
        let root = tempfile::tempdir().unwrap();
        storage::restrict(root.path(), true).unwrap();
        let key = root.path().join("keys/key");
        let mut threads = vec![];
        for i in 0..12 {
            let auth = root.path().join(format!("auth{}.json", i % 2));
            let key = key.clone();
            threads.push(std::thread::spawn(move || {
                put(&auth, &key, &format!("registry-{i}"), credential()).unwrap()
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        for i in 0..2 {
            assert_eq!(
                load(&root.path().join(format!("auth{i}.json")), &key)
                    .unwrap()
                    .registries
                    .len(),
                6
            );
        }
    }
    #[test]
    fn read_only_missing_store_and_invalid_paths_do_not_generate_keys() {
        let root = tempfile::tempdir().unwrap();
        storage::restrict(root.path(), true).unwrap();
        let auth = root.path().join("auth.json");
        let key = root.path().join("keys/key");
        assert!(load(&auth, &key).unwrap().registries.is_empty());
        assert!(!remove(&auth, &key, "a").unwrap());
        assert!(!key.exists());
        assert!(put(&auth, &auth, "a", credential()).is_err());
        let auth_lock = root.path().join(".auth.json.lock");
        assert!(put(&auth, &auth_lock, "a", credential()).is_err());
        let link = root.path().join("symlink");
        std::os::unix::fs::symlink(&key, &link).unwrap();
        assert!(put(&auth, &link, "a", credential()).is_err());
    }
}
