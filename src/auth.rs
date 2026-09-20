use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// An in-memory registry credential whose strings are zeroized on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    /// Registry account name used for authentication.
    pub username: String,
    /// Password or access token; this is plaintext in memory and must not be logged.
    pub secret: String,
}

/// Decrypted credential-store contents; use the storage methods to persist encryption.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthFile {
    /// Version of the serialized file format.
    pub version: u32,
    /// Credentials indexed by normalized registry authority.
    pub registries: BTreeMap<String, Credential>,
}
impl AuthFile {
    /// Load and decrypt credentials using the separate key file; a missing store is empty.
    pub fn load(path: &Path, keyfile: &Path) -> Result<Self> {
        crate::vault::load(path, keyfile)
    }
    /// Insert or replace a credential under a lock and atomically persist the encrypted store.
    pub fn put(path: &Path, keyfile: &Path, registry: &str, credential: Credential) -> Result<()> {
        crate::vault::put(path, keyfile, registry, credential)
    }
    /// Remove a stored credential; returns whether an entry existed.
    pub fn remove(path: &Path, keyfile: &Path, registry: &str) -> Result<bool> {
        crate::vault::remove(path, keyfile, registry)
    }
}

/// Resolve explicit or XDG-based credential-store and master-key paths.
pub fn paths(
    authfile: Option<&Path>,
    keyfile: Option<&Path>,
) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    let auth = match authfile {
        Some(path) => path.to_owned(),
        None => crate::config::default_dir()?.join("auth.json"),
    };
    let key = match keyfile {
        Some(path) => path.to_owned(),
        None => dirs::data_dir()
            .ok_or_else(|| Error::input("cannot locate user data directory; use --keyfile"))?
            .join("quayside/master.key"),
    };
    Ok((auth, key))
}

/// A supported scheme parsed from a registry authentication challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Challenge {
    /// The registry requests HTTP Basic authentication.
    Basic,
    /// The registry delegates token acquisition to a realm endpoint.
    Bearer {
        /// Token endpoint advertised by the registry; trust validation occurs before use.
        realm: String,
        /// Optional token-service audience advertised by the registry.
        service: Option<String>,
        /// Optional repository permission scope advertised by the registry.
        scope: Option<String>,
    },
}

/// Split a comma-separated header while respecting quoted strings and escapes.
fn split_quoted(input: &str) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && c == '\\' {
            escaped = true;
            continue;
        }
        if c == '"' {
            quoted = !quoted;
        }
        if c == ',' && !quoted {
            parts.push(input[start..i].trim().to_string());
            start = i + 1;
        }
    }
    if quoted || escaped {
        return Err(Error::input("malformed authentication challenge"));
    }
    parts.push(input[start..].trim().to_string());
    Ok(parts)
}
fn unquote(input: &str) -> Result<String> {
    let input = input.trim();
    if !input.starts_with('"') {
        return Ok(input.to_owned());
    }
    if !input.ends_with('"') || input.len() < 2 {
        return Err(Error::input("malformed authentication parameter"));
    }
    let mut result = String::new();
    let mut escaped = false;
    for c in input[1..input.len() - 1].chars() {
        if escaped {
            result.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else {
            result.push(c);
        }
    }
    Ok(result)
}

/// Parse Basic and Bearer challenges, respecting quoted values and escapes.
pub fn challenges(header: &str) -> Result<Vec<Challenge>> {
    let parts = split_quoted(header)?;
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    for part in parts {
        let first = part.split_whitespace().next().unwrap_or("");
        if first.eq_ignore_ascii_case("Bearer") || first.eq_ignore_ascii_case("Basic") {
            let tail = part[first.len()..].trim().to_owned();
            groups.push((first.to_ascii_lowercase(), vec![tail]));
        } else if let Some((_, fields)) = groups.last_mut() {
            fields.push(part);
        }
    }
    let mut result = Vec::new();
    for (scheme, fields) in groups {
        if scheme == "basic" {
            result.push(Challenge::Basic);
            continue;
        }
        let mut values = BTreeMap::new();
        for field in fields {
            if field.is_empty() {
                continue;
            }
            let (key, val) = field
                .split_once('=')
                .ok_or_else(|| Error::input("malformed bearer challenge"))?;
            let key = key.trim().to_ascii_lowercase();
            if values.insert(key, unquote(val)?).is_some() {
                return Err(Error::input("duplicate authentication parameter"));
            }
        }
        let realm = values
            .remove("realm")
            .ok_or_else(|| Error::input("bearer challenge has no realm"))?;
        result.push(Challenge::Bearer {
            realm,
            service: values.remove("service"),
            scope: values.remove("scope"),
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bearer_commas() {
        let c = challenges(r#"Bearer realm="https://auth.example/token",service="r",scope="repository:a:pull,push""#).unwrap();
        assert!(
            matches!(&c[0], Challenge::Bearer { scope: Some(s), .. } if s == "repository:a:pull,push")
        );
    }
    #[test]
    fn multiple_schemes() {
        assert_eq!(
            challenges(r#"Basic realm="x", Bearer realm="https://auth.example/token""#)
                .unwrap()
                .len(),
            2
        );
    }
    #[test]
    fn malformed_quote_rejected() {
        assert!(challenges("Bearer realm=\"unfinished").is_err());
    }
    #[test]
    fn credential_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        crate::storage::restrict(dir.path(), true).unwrap();
        let file = dir.path().join("auth.json");
        let key = dir.path().join("keys/master.key");
        AuthFile::put(
            &file,
            &key,
            "example.com",
            Credential {
                username: "robot$ci".into(),
                secret: "secret".into(),
            },
        )
        .unwrap();
        assert_eq!(
            AuthFile::load(&file, &key).unwrap().registries["example.com"].username,
            "robot$ci"
        );
        assert!(AuthFile::remove(&file, &key, "example.com").unwrap());
        assert!(AuthFile::load(&file, &key).unwrap().registries.is_empty());
    }
}
