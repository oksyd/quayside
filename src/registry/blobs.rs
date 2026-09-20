use super::transport::{
    content_length, http_error, limited_body, retry_delay, same_origin, valid_url,
};
use super::{Registry, UploadStart};
use crate::digest::Digest;
use crate::error::Code;
use crate::model::Descriptor;
use crate::{Error, Result};
use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, StatusCode};
use reqx::ResponseStream as Response;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

impl Registry {
    fn checked_location(&self, response: &Response) -> Result<Url> {
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Error::input("upload response has no valid Location header"))?;
        let url = Url::parse(response.uri_raw())?.join(location)?;
        valid_url(&url)?;
        if !same_origin(&url, &self.inner.base) {
            return Err(Error::unsupported(
                "cross-origin upload endpoints are not enabled; refusing to forward registry credentials",
            ));
        }
        Ok(url)
    }
    /// Check whether a blob exists and reject a reported length that conflicts with its descriptor.
    pub async fn blob_exists(&self, repo: &str, d: &Descriptor) -> Result<bool> {
        let (response, _) = self
            .request(
                Method::HEAD,
                self.url(&format!("v2/{repo}/blobs/{}", d.digest))?,
                &Self::scope(repo, "pull"),
                HeaderMap::new(),
                None,
                false,
                true,
            )
            .await?;
        match response.status() {
            StatusCode::OK => {
                if let Some(length) = response
                    .headers()
                    .get(header::CONTENT_LENGTH)
                    .and_then(|s| s.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    && length != d.size
                {
                    return Err(Error::integrity(
                        "existing blob has a different size than its descriptor",
                    ));
                }
                Ok(true)
            }
            StatusCode::NOT_FOUND => Ok(false),
            _ => Err(http_error(&response)),
        }
    }
    /// Read and verify a blob into memory, enforcing the caller's size limit.
    pub async fn get_blob_bytes(&self, repo: &str, d: &Descriptor, limit: u64) -> Result<Bytes> {
        if d.size > limit {
            return Err(Error::input(
                "config blob exceeds configured metadata size limit",
            ));
        }
        if let Some(data) = d.embedded()? {
            return Ok(data);
        }
        let (response, _) = self
            .request(
                Method::GET,
                self.url(&format!("v2/{repo}/blobs/{}", d.digest))?,
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
        let raw = limited_body(response, limit).await?;
        d.verify(&raw)?;
        Ok(raw)
    }
    /// Stream a blob to a file and verify its length and digest, retrying bounded network failures.
    pub async fn download_blob(&self, repo: &str, d: &Descriptor, output: &Path) -> Result<()> {
        self.download_blob_progress(repo, d, output, &crate::observer::NoProgress)
            .await
    }
    pub(crate) async fn download_blob_progress(
        &self,
        repo: &str,
        d: &Descriptor,
        output: &Path,
        progress: &dyn crate::observer::BlobProgress,
    ) -> Result<()> {
        if let Some(raw) = d.embedded()? {
            tokio::fs::write(output, &raw).await?;
            return Ok(());
        }
        let mut attempt = 0;
        loop {
            progress.phase(crate::observer::BlobPhase::Downloading);
            match self.download_once(repo, d, output, progress).await {
                Ok(()) => return Ok(()),
                Err(e) if e.retryable() && attempt < self.config().transfer.max_retries => {
                    tokio::time::sleep(retry_delay(None, attempt)).await;
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }
    async fn download_once(
        &self,
        repo: &str,
        d: &Descriptor,
        output: &Path,
        progress: &dyn crate::observer::BlobProgress,
    ) -> Result<()> {
        let (mut response, _) = self
            .request(
                Method::GET,
                self.url(&format!("v2/{repo}/blobs/{}", d.digest))?,
                &Self::scope(repo, "pull"),
                HeaderMap::new(),
                None,
                true,
                true,
            )
            .await?;
        if response.status() != StatusCode::OK {
            return Err(http_error(&response));
        }
        if content_length(&response).is_some_and(|n| n != d.size) {
            return Err(Error::integrity(
                "blob HTTP Content-Length does not match descriptor",
            ));
        }
        let mut file = tokio::fs::File::create(output).await?;
        let mut hasher = d.digest.hasher();
        let mut count = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let size = response
                .read(&mut buffer)
                .await
                .map_err(|_| Error::network("HTTP response body read failed"))?;
            if size == 0 {
                break;
            }
            let chunk = &buffer[..size];
            count = count
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| Error::integrity("blob size overflow"))?;
            if count > d.size {
                return Err(Error::integrity("received blob exceeds descriptor size"));
            }
            hasher.update(chunk);
            file.write_all(chunk).await?;
            progress.position(count);
        }
        if count != d.size {
            return Err(Error::integrity("received blob is shorter than descriptor"));
        }
        hasher.verify(&d.digest)?;
        file.flush().await?;
        file.sync_all().await?;
        Ok(())
    }
    /// Start an upload or request a same-registry mount from an optional source repository.
    pub async fn start_upload(
        &self,
        repo: &str,
        digest: &Digest,
        from: Option<&str>,
    ) -> Result<UploadStart> {
        let mut url = self.url(&format!("v2/{repo}/blobs/uploads/"))?;
        if let Some(from) = from {
            url.query_pairs_mut()
                .append_pair("mount", digest.as_str())
                .append_pair("from", from);
        }
        let scope = if let Some(from) = from {
            format!(
                "{} {}",
                Self::scope(repo, "pull,push"),
                Self::scope(from, "pull")
            )
        } else {
            Self::scope(repo, "pull,push")
        };
        let attempted = self
            .request(
                Method::POST,
                url,
                &scope,
                HeaderMap::new(),
                None,
                false,
                false,
            )
            .await;
        let mut response = match attempted {
            Ok((response, _)) => response,
            Err(e)
                if from.is_some()
                    && matches!(
                        e.code,
                        Code::Unauthorized | Code::Forbidden | Code::Unsupported
                    ) =>
            {
                self.request(
                    Method::POST,
                    self.url(&format!("v2/{repo}/blobs/uploads/"))?,
                    &Self::scope(repo, "pull,push"),
                    HeaderMap::new(),
                    None,
                    false,
                    false,
                )
                .await?
                .0
            }
            Err(e) => return Err(e),
        };
        if from.is_some() && matches!(response.status().as_u16(), 400 | 401 | 403 | 404 | 405) {
            response = self
                .request(
                    Method::POST,
                    self.url(&format!("v2/{repo}/blobs/uploads/"))?,
                    &Self::scope(repo, "pull,push"),
                    HeaderMap::new(),
                    None,
                    false,
                    false,
                )
                .await?
                .0;
        }
        match response.status() {
            StatusCode::CREATED if from.is_some() => Ok(UploadStart::Mounted),
            StatusCode::ACCEPTED => {
                let minimum_chunk = response
                    .headers()
                    .get("oci-chunk-min-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                Ok(UploadStart::Session {
                    url: self.checked_location(&response)?,
                    minimum_chunk,
                })
            }
            _ => Err(http_error(&response)),
        }
    }
    /// Send one chunk at the expected offset and return the validated continuation URL.
    pub async fn patch_upload(
        &self,
        repo: &str,
        url: Url,
        offset: u64,
        chunk: Bytes,
    ) -> Result<Url> {
        if chunk.is_empty() {
            return Err(Error::input("empty PATCH chunk"));
        }
        let end = offset
            .checked_add(chunk.len() as u64 - 1)
            .ok_or_else(|| Error::input("upload offset overflow"))?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("{offset}-{end}"))
                .map_err(|_| Error::input("invalid upload range"))?,
        );
        let (response, _) = self
            .request(
                Method::PATCH,
                url,
                &Self::scope(repo, "pull,push"),
                headers,
                Some(chunk),
                true,
                false,
            )
            .await?;
        if response.status() != StatusCode::ACCEPTED {
            if response.status() == StatusCode::RANGE_NOT_SATISFIABLE {
                return Err(Error::network("upload offset needs reconciliation"));
            }
            return Err(http_error(&response));
        }
        if let Some(range) = response
            .headers()
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok())
            && range_offset(range)? != end + 1
        {
            return Err(Error::network(
                "server acknowledged unexpected upload offset",
            ));
        }
        self.checked_location(&response)
    }
    /// Query an upload session and return its continuation URL and acknowledged byte offset.
    pub async fn upload_status(&self, repo: &str, url: Url) -> Result<(Url, u64)> {
        let (response, _) = self
            .request(
                Method::GET,
                url,
                &Self::scope(repo, "pull,push"),
                HeaderMap::new(),
                None,
                false,
                true,
            )
            .await?;
        if response.status() != StatusCode::NO_CONTENT {
            return Err(http_error(&response));
        }
        let range = response
            .headers()
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Error::input("upload status has no Range"))?;
        Ok((self.checked_location(&response)?, range_offset(range)?))
    }
    /// Commit an upload session using its expected payload digest.
    pub async fn finish_upload(&self, repo: &str, mut url: Url, digest: &Digest) -> Result<()> {
        if url.query_pairs().any(|(k, _)| k == "digest") {
            return Err(Error::input(
                "upload URL unexpectedly already contains a digest parameter",
            ));
        }
        url.query_pairs_mut().append_pair("digest", digest.as_str());
        let (response, _) = self
            .request(
                Method::PUT,
                url,
                &Self::scope(repo, "pull,push"),
                HeaderMap::new(),
                None,
                false,
                false,
            )
            .await?;
        if response.status() != StatusCode::CREATED {
            return Err(http_error(&response));
        }
        Ok(())
    }
}
pub(super) fn range_offset(value: &str) -> Result<u64> {
    let range = value.strip_prefix("bytes=").unwrap_or(value);
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| Error::input("invalid upload Range"))?;
    if start != "0" {
        return Err(Error::input("upload Range does not start at zero"));
    }
    end.parse::<u64>()
        .ok()
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| Error::input("invalid upload Range end"))
}
