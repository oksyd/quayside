//! Read Docker daemon network defaults without contacting Docker or reading credentials.
use crate::diagnostics::{self, Level};
use serde::Deserialize;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::OnceLock,
};
use zeroize::Zeroizing;

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub(crate) struct Proxies {
    pub http_proxy: Option<String>,
    pub https_proxy: Option<String>,
    pub no_proxy: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub(crate) struct DaemonConfig {
    #[serde(skip)]
    pub source: Option<String>,
    pub proxies: Proxies,
    #[serde(rename = "registry-mirrors")]
    pub mirrors: Vec<String>,
}

impl DaemonConfig {
    pub fn mirror_endpoints(&self) -> crate::Result<Vec<(String, url::Url)>> {
        if self.mirrors.len() > 16 {
            return Err(crate::Error::input(
                "Docker registry-mirrors exceeds the limit of 16 entries",
            ));
        }
        // Validate every endpoint before starting requests. Rejected URLs may contain secrets.
        self.mirrors.iter().map(|entry| {
            let invalid = || crate::Error::input(
                "Docker registry mirrors must be HTTP(S) origins without credentials, paths, queries or fragments",
            );
            let url = url::Url::parse(entry).map_err(|_| invalid())?;
            if !matches!(url.scheme(), "https" | "http")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(invalid());
            }
            // URL normalization removes default ports; credential and policy keys retain them.
            let (_, authority) = entry.split_once("://").ok_or_else(invalid)?;
            let name = crate::reference::registry_name(authority.trim_end_matches('/'))
                .map_err(|_| invalid())?;
            Ok((name, url))
        }).collect()
    }
}

fn read(path: &Path) -> Result<Option<DaemonConfig>, &'static str> {
    match std::fs::metadata(path) {
        Ok(metadata) if !metadata.is_file() => return Err("not a regular file"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cannot read metadata"),
        _ => {}
    }
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cannot read file"),
    };
    if !file
        .metadata()
        .map_err(|_| "cannot read metadata")?
        .is_file()
    {
        return Err("not a regular file");
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read file")?;
    if bytes.len() > 1024 * 1024 {
        return Err("file exceeds 1MiB");
    }
    // Ignore unrelated fields and never expose parser diagnostics or configuration contents.
    serde_json::from_slice::<DaemonConfig>(&bytes)
        .map(Some)
        .map_err(|_| "invalid JSON or Docker field types")
}
fn load(paths: &[PathBuf]) -> DaemonConfig {
    for path in paths {
        match read(path) {
            Ok(Some(mut config)) => {
                config.source = Some(path.display().to_string());
                diagnostics::log(
                    Level::Debug,
                    format_args!("Docker network defaults loaded from {}", path.display()),
                );
                return config;
            }
            Ok(None) => {}
            Err(reason) => diagnostics::log(
                Level::Warn,
                format_args!(
                    "Ignoring Docker network configuration {}: {reason}",
                    path.display()
                ),
            ),
        }
    }
    DaemonConfig::default()
}
pub(crate) fn defaults() -> &'static DaemonConfig {
    static DOCKER: OnceLock<DaemonConfig> = OnceLock::new();
    DOCKER.get_or_init(|| {
        let mut paths = Vec::new();
        if let Some(config) = dirs::config_dir() {
            paths.push(config.join("docker/daemon.json"));
        }
        paths.push(PathBuf::from("/etc/docker/daemon.json"));
        load(&paths)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mirror_authorities_preserve_explicit_ports_and_reject_invalid_or_excessive_entries() {
        let mut config = DaemonConfig {
            mirrors: vec!["https://EXAMPLE.com:0443/".into(), "http://[::1]:80".into()],
            ..Default::default()
        };
        let endpoints = config.mirror_endpoints().unwrap();
        assert_eq!(endpoints[0].0, "example.com:443");
        assert_eq!(endpoints[1].0, "[::1]:80");
        config.mirrors = vec!["https://example.com".into(); 17];
        assert!(config.mirror_endpoints().is_err());
    }
    #[test]
    fn reads_network_fields_and_uses_first_valid_file() {
        let root = tempfile::tempdir().unwrap();
        let user = root.path().join("user.json");
        let system = root.path().join("system.json");
        std::fs::write(&user, br#"{"proxies":{"http-proxy":"http://user:1","https-proxy":"http://user:2","no-proxy":".example.com"},"insecure-registries":["anything"],"registry-mirrors":["https://mirror.example.com"],"credsStore":"never-execute"}"#).unwrap();
        std::fs::write(&system, br#"{"proxies":{"http-proxy":"http://system:1"}}"#).unwrap();
        let config = load(&[user.clone(), system.clone()]);
        assert_eq!(config.proxies.http_proxy.as_deref(), Some("http://user:1"));
        assert_eq!(config.proxies.https_proxy.as_deref(), Some("http://user:2"));
        assert_eq!(config.proxies.no_proxy.as_deref(), Some(".example.com"));
        assert_eq!(config.mirrors, ["https://mirror.example.com"]);
        std::fs::write(&user, b"{}").unwrap();
        assert!(
            load(&[user.clone(), system.clone()])
                .proxies
                .http_proxy
                .is_none()
        );
        std::fs::remove_file(&user).unwrap();
        assert_eq!(
            load(&[user, system]).proxies.http_proxy.as_deref(),
            Some("http://system:1")
        );
    }
    #[test]
    fn optional_bad_files_are_bounded_and_errors_do_not_expose_contents() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("daemon.json");
        for bytes in [
            br#"{"proxies":{"http-proxy":123},"secret":"password"}"#.as_slice(),
            b"not-json password",
        ] {
            std::fs::write(&path, bytes).unwrap();
            let error = read(&path).err().unwrap();
            assert!(!error.contains("password"));
            assert!(
                load(std::slice::from_ref(&path))
                    .proxies
                    .http_proxy
                    .is_none()
            );
        }
        let file = File::create(&path).unwrap();
        file.set_len(1024 * 1024 + 2).unwrap();
        assert_eq!(read(&path).err(), Some("file exceeds 1MiB"));
        assert!(
            load(&[root.path().join("missing")])
                .proxies
                .http_proxy
                .is_none()
        );
    }
}
