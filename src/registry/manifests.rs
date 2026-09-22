use super::Registry;
use super::transport::{http_error, limited_body};
use crate::config::parse_size;
use crate::digest::Digest;
use crate::error::Code;
use crate::model::{ACCEPT_MANIFEST, Manifest};
use crate::reference::Reference;
use crate::{Error, Result};
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, StatusCode};

impl Registry {
    /// Fetch and parse a manifest while preserving its original bytes and checking a pinned digest.
    pub async fn get_manifest(&self, reference: &Reference) -> Result<Manifest> {
        self.validate_reference(reference)?;
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static(ACCEPT_MANIFEST));
        let (response, _) = self
            .request(
                Method::GET,
                self.url(&format!(
                    "v2/{}/manifests/{}",
                    reference.repository, reference.selector
                ))?,
                &Self::scope(&reference.repository, "pull"),
                headers,
                None,
                false,
                true,
            )
            .await?;
        if response.status() != StatusCode::OK {
            return Err(http_error(&response));
        }
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);
        let header_digest = response
            .headers()
            .get("docker-content-digest")
            .and_then(|h| h.to_str().ok())
            .map(str::parse::<Digest>)
            .transpose()?;
        let raw = limited_body(
            response,
            parse_size(&self.config().transfer.max_manifest_size)?,
        )
        .await?;
        if let Some(d) = &header_digest {
            d.verify(&raw)?;
        }
        let expected = reference.digest().or(header_digest);
        Manifest::parse(raw, content_type.as_deref(), expected.as_ref())
    }
    /// Fetch a manifest, mapping only a not-found response to None.
    pub async fn manifest_optional(&self, reference: &Reference) -> Result<Option<Manifest>> {
        match self.get_manifest(reference).await {
            Ok(m) => Ok(Some(m)),
            Err(e) if e.code == Code::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    /// Publish original manifest bytes at the supplied reference after checking supported content.
    pub async fn put_manifest(&self, reference: &Reference, manifest: &Manifest) -> Result<()> {
        self.validate_reference(reference)?;
        manifest.check_transfer_supported()?;
        if let Some(expected) = reference.digest() {
            expected.verify(&manifest.raw)?;
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(&manifest.descriptor.media_type)
                .map_err(|_| Error::input("invalid media type header"))?,
        );
        let (response, _) = self
            .request(
                Method::PUT,
                self.url(&format!(
                    "v2/{}/manifests/{}",
                    reference.repository, reference.selector
                ))?,
                &Self::scope(&reference.repository, "pull,push"),
                headers,
                Some(manifest.raw.clone()),
                false,
                true,
            )
            .await?;
        if response.status() != StatusCode::CREATED {
            return Err(http_error(&response));
        }
        if let Some(digest) = response
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
        {
            let d: Digest = digest.parse()?;
            d.verify(&manifest.raw)?;
        }
        Ok(())
    }
}
