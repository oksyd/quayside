use crate::{Error, Result, reference::registry_name, storage};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

/// Persistent transfer configuration and per-registry overrides.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Version of the serialized file format.
    pub version: u32,
    /// Resource limits, retry policy and timeout settings for transfer operations.
    pub transfer: TransferConfig,
    /// Connection policies indexed by normalized registry authority.
    pub registries: BTreeMap<String, RegistryConfig>,
}
/// TLS, transport and token-host policy scoped to one registry.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RegistryConfig {
    /// Optional PEM bundle containing additional trusted CA certificates.
    pub ca_file: Option<PathBuf>,
    /// Use unencrypted HTTP for this explicitly configured registry.
    pub plain_http: bool,
    /// Legacy insecure-TLS option; enabling it is rejected by this implementation.
    pub insecure_skip_tls_verify: bool,
    /// Optional cross-origin token host restriction; empty permits HTTPS registry discovery.
    pub auth_hosts: Vec<String>,
}
/// Human-readable resource limits and timeouts validated before use.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransferConfig {
    /// Maximum concurrent requests per stage; blob downloads and their ranges share this limit.
    pub concurrency: usize,
    /// Initial upload chunk size; fast transfers grow within the 128MiB aggregate buffer limit.
    pub chunk_size: String,
    /// Maximum retry count for retryable requests or transfer attempts.
    pub max_retries: usize,
    /// Time allowed to establish a transport connection.
    pub connect_timeout: String,
    /// Total time budget for an individual non-streaming request.
    pub metadata_timeout: String,
    /// Request timeout configured on the HTTP client, including streaming requests.
    pub idle_timeout: String,
    /// Maximum allowed size of an individual manifest or bounded metadata payload.
    pub max_manifest_size: String,
    /// Maximum cumulative manifest metadata held for a dependency graph.
    pub max_metadata_size: String,
    /// Maximum number of objects admitted while constructing a dependency graph.
    pub max_objects: usize,
    /// Maximum dependency-graph traversal depth.
    pub max_depth: usize,
    /// Maximum accepted archive size under the local transport limits.
    pub max_archive_size: String,
    /// Shared temporary-file storage budget for active transfer workers.
    pub max_temp_size: String,
}
impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            concurrency: 4,
            chunk_size: "8MiB".into(),
            max_retries: 3,
            connect_timeout: "10s".into(),
            metadata_timeout: "60s".into(),
            idle_timeout: "60s".into(),
            max_manifest_size: "8MiB".into(),
            max_metadata_size: "64MiB".into(),
            max_objects: 10_000,
            max_depth: 32,
            max_archive_size: "1TiB".into(),
            max_temp_size: "64GiB".into(),
        }
    }
}
impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            transfer: TransferConfig::default(),
            registries: BTreeMap::new(),
        }
    }
}
/// Locate the Quayside directory within the user's configuration directory.
pub fn default_dir() -> Result<PathBuf> {
    dirs::config_dir()
        .map(|d| d.join("quayside"))
        .ok_or_else(|| {
            Error::input("cannot locate user configuration directory; use --config and --authfile")
        })
}
impl Config {
    /// Read and validate TOML configuration, or use defaults when the file is absent.
    pub fn load(path: &Path) -> Result<Self> {
        let cfg = match std::fs::read_to_string(path) {
            Ok(s) => {
                toml::from_str(&s).map_err(|e| Error::input(format!("invalid config: {e}")))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(e.into()),
        };
        Self::validate(&cfg)?;
        Ok(cfg)
    }
    /// Reject unsupported versions, unsafe policies and invalid transfer limits.
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::input("unsupported config version"));
        }
        let t = &self.transfer;
        let chunk = parse_size(&t.chunk_size)?;
        if !(1..=32).contains(&t.concurrency)
            || !(64 * 1024..=64 * 1024 * 1024).contains(&chunk)
            || chunk * t.concurrency as u64 > 128 * 1024 * 1024
        {
            return Err(Error::input(
                "concurrency/chunk_size exceed limits: 1..32 workers, 64KiB..64MiB chunks, aggregate buffers <=128MiB",
            ));
        }
        if t.max_retries > 10
            || !(1..=100_000).contains(&t.max_objects)
            || !(1..=128).contains(&t.max_depth)
        {
            return Err(Error::input("invalid retry/object/depth limits"));
        }
        for v in [&t.connect_timeout, &t.metadata_timeout, &t.idle_timeout] {
            if duration(v)?.is_zero() {
                return Err(Error::input("timeouts must be positive"));
            }
        }
        let manifest = parse_size(&t.max_manifest_size)?;
        let metadata = parse_size(&t.max_metadata_size)?;
        if !(1024..=64 * 1024 * 1024).contains(&manifest)
            || metadata < manifest
            || metadata > 512 * 1024 * 1024
        {
            return Err(Error::input("invalid metadata limits"));
        }
        parse_size(&t.max_archive_size)?;
        if parse_size(&t.max_temp_size)? == 0 {
            return Err(Error::input("max_temp_size must be positive"));
        }
        for (name, registry) in &self.registries {
            if registry_name(name)? != *name {
                return Err(Error::input(
                    "registry config keys must use normalized lowercase hostnames",
                ));
            }
            for h in &registry.auth_hosts {
                registry_name(h)?;
            }
        }
        Ok(())
    }
    /// Return the stored registry policy or the default policy when absent.
    pub fn for_registry(&self, name: &str) -> RegistryConfig {
        self.registries.get(name).cloned().unwrap_or_default()
    }
    /// Update one registry policy under a lock and atomically persist validated TOML.
    pub fn save_registry(
        path: &Path,
        name: &str,
        update: impl FnOnce(&mut RegistryConfig),
    ) -> Result<()> {
        storage::with_lock(path, || {
            let mut cfg = Self::load(path)?;
            update(cfg.registries.entry(name.to_string()).or_default());
            cfg.validate()?;
            let text = toml::to_string_pretty(&cfg).map_err(|e| Error::input(e.to_string()))?;
            storage::atomic_write(path, text.as_bytes())
        })
    }
}
/// Parse a human-readable duration such as 30s, returning a configuration error on failure.
pub fn duration(value: &str) -> Result<Duration> {
    humantime::parse_duration(value).map_err(|_| Error::input(format!("invalid duration: {value}")))
}
/// Parse nonnegative byte counts with B, KiB, MiB, GiB or TiB units and check overflow.
pub fn parse_size(value: &str) -> Result<u64> {
    let pos = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    let num: u64 = value[..pos]
        .parse()
        .map_err(|_| Error::input("size must begin with a nonnegative integer"))?;
    let multiplier = match value[pos..].trim() {
        "" | "B" => 1,
        "KiB" => 1024,
        "MiB" => 1024 * 1024,
        "GiB" => 1024 * 1024 * 1024,
        "TiB" => 1024u64.pow(4),
        _ => return Err(Error::input("size units: B, KiB, MiB, GiB, TiB")),
    };
    num.checked_mul(multiplier)
        .ok_or_else(|| Error::input("size overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn valid_defaults() {
        Config::default().validate().unwrap();
    }
    #[test]
    fn rejects_unknown_config_key() {
        assert!(toml::from_str::<Config>("verison = 1").is_err());
    }
    #[test]
    fn sizes() {
        assert_eq!(parse_size("8MiB").unwrap(), 8 * 1024 * 1024);
        assert!(parse_size("99999999999999999999GiB").is_err());
    }
    #[test]
    fn disallows_unbounded_buffers() {
        let mut c = Config::default();
        c.transfer.concurrency = 32;
        assert!(c.validate().is_err());
    }
}
