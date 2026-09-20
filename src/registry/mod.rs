//! OCI registry client facade; protocol implementation stays in private modules.
use self::authentication::CachedAuth;
use self::transport::{HttpClient, client, http_error};
#[cfg(test)]
use self::transport::{same_origin, valid_url};
use crate::auth::Credential;
use crate::config::{Config, RegistryConfig};
use crate::reference::validate_repository;
use crate::{Error, Result};
#[cfg(test)]
use blobs::range_offset;
#[cfg(test)]
use catalog::next_link;
use http::header::HeaderMap;
use http::{Method, StatusCode};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Weak};
use tokio::sync::{Mutex, Semaphore};
pub use transport::limited_body;
use url::Url;

/// A clonable registry client sharing connection policy, credentials and token cache.
#[derive(Clone)]
pub struct Registry {
    inner: Arc<Inner>,
}
struct Inner {
    name: String,
    base: Url,
    client: HttpClient,
    public_client: HttpClient,
    config: Arc<Config>,
    policy: RegistryConfig,
    credential: Option<Credential>,
    cache: Mutex<BTreeMap<String, CachedAuth>>,
    auth_refreshes: Mutex<BTreeMap<String, Weak<Mutex<()>>>>,
    blobs: Mutex<BTreeMap<(String, crate::digest::Digest), bytes::Bytes>>,
    downloads: Arc<Semaphore>,
    changed: Arc<AtomicBool>,
}
/// Result of starting a blob upload or attempting a cross-repository mount.
pub enum UploadStart {
    /// The registry reports that the existing payload was mounted without an upload session.
    Mounted,
    /// The registry allocated an upload session that requires payload transmission.
    Session {
        /// Validated upload-session endpoint on the configured registry origin.
        url: Url,
        /// Minimum chunk size requested by the registry, in bytes.
        minimum_chunk: u64,
    },
}

mod authentication;
mod blobs;
mod catalog;
mod download;
mod manifests;
mod transport;

impl Registry {
    /// Build a registry client with explicit policy, optional credentials and shared write tracking.
    pub fn new(
        name: &str,
        config: Arc<Config>,
        credential: Option<Credential>,
        changed: Arc<AtomicBool>,
    ) -> Result<Self> {
        let policy = config.for_registry(name);
        let endpoint = if name == "docker.io" {
            "registry-1.docker.io"
        } else {
            name
        };
        let base = Url::parse(&format!(
            "{}://{endpoint}/",
            if policy.plain_http { "http" } else { "https" }
        ))?;
        let mut public_base = base.clone();
        public_base
            .set_scheme("https")
            .map_err(|_| Error::input("invalid public endpoint"))?;
        Ok(Self {
            inner: Arc::new(Inner {
                client: client(&base, &config, &policy)?,
                public_client: client(&public_base, &config, &RegistryConfig::default())?,
                name: name.into(),
                base,
                downloads: Arc::new(Semaphore::new(config.transfer.concurrency)),
                config,
                policy,
                credential,
                cache: Mutex::new(BTreeMap::new()),
                auth_refreshes: Mutex::new(BTreeMap::new()),
                blobs: Mutex::new(BTreeMap::new()),
                changed,
            }),
        })
    }
    /// Return the logical registry name used for configuration and credential lookup.
    pub fn name(&self) -> &str {
        &self.inner.name
    }
    /// Borrow the shared transfer and registry configuration.
    pub fn config(&self) -> &Config {
        &self.inner.config
    }
    /// Return the resolved API origin, including the transport scheme.
    pub fn endpoint(&self) -> &Url {
        &self.inner.base
    }
    fn url(&self, path: &str) -> Result<Url> {
        self.inner.base.join(path).map_err(Into::into)
    }
    fn scope(repo: &str, actions: &str) -> String {
        format!("repository:{repo}:{actions}")
    }
    /// Check the Distribution API endpoint and report whether credentials were used successfully.
    pub async fn ping(&self) -> Result<bool> {
        let (response, authenticated) = self
            .request(
                Method::GET,
                self.url("v2/")?,
                "",
                HeaderMap::new(),
                None,
                false,
                true,
            )
            .await?;
        if response.status() != StatusCode::OK {
            return Err(http_error(&response));
        }
        Ok(authenticated)
    }
    /// Check repository tag access and report whether authentication was exercised.
    pub async fn verify_repository(&self, repo: &str) -> Result<bool> {
        validate_repository(repo)?;
        let (response, authenticated) = self
            .request(
                Method::GET,
                self.url(&format!("v2/{repo}/tags/list?n=1"))?,
                &Self::scope(repo, "pull"),
                HeaderMap::new(),
                None,
                false,
                true,
            )
            .await?;
        if response.status() != StatusCode::OK {
            return Err(http_error(&response));
        }
        limited_body(response, 1024 * 1024).await?;
        Ok(authenticated)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn link_with_comma_in_uri() {
        assert_eq!(
            next_link("</v2/a/tags/list?last=a,b>; rel=\"next\""),
            Some("/v2/a/tags/list?last=a,b".into())
        );
    }
    #[test]
    fn range_end_is_inclusive() {
        assert_eq!(range_offset("0-99").unwrap(), 100);
        assert!(range_offset("1-99").is_err());
    }
    #[test]
    fn unsafe_url_rejected() {
        assert!(valid_url(&Url::parse("https://u:p@a.example/token").unwrap()).is_err());
    }
    #[test]
    fn origin_includes_port() {
        assert!(!same_origin(
            &Url::parse("https://a.example/").unwrap(),
            &Url::parse("https://a.example:444/").unwrap()
        ));
    }
}
