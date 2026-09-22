use super::Registry;
use super::transport::{content_length, http_error, retry_delay};
use crate::digest::Hasher;
use crate::model::Descriptor;
use crate::observer::{BlobPhase, BlobProgress};
use crate::reference::validate_repository;
use crate::{Error, Result};
use futures_util::{StreamExt, stream};
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, StatusCode};
use reqx::ResponseStream as Response;
use std::ops::Range;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

type DownloadResponse = (Response, OwnedSemaphorePermit);

impl Registry {
    /// Stream and verify a blob, then flush the completed persistent file to disk.
    pub async fn download_blob(&self, repo: &str, d: &Descriptor, output: &Path) -> Result<()> {
        self.download_blob_progress(repo, d, output, &crate::observer::NoProgress)
            .await?;
        tokio::fs::OpenOptions::new()
            .write(true)
            .open(output)
            .await?
            .sync_all()
            .await?;
        Ok(())
    }
    pub(crate) async fn download_blob_progress(
        &self,
        repo: &str,
        d: &Descriptor,
        output: &Path,
        progress: &dyn crate::observer::BlobProgress,
    ) -> Result<()> {
        self.download_blob_with_slots(repo, d, output, progress, self.inner.downloads.clone())
            .await
    }

    pub(crate) async fn download_blob_with_slots(
        &self,
        repo: &str,
        d: &Descriptor,
        output: &Path,
        progress: &dyn BlobProgress,
        slots: Arc<Semaphore>,
    ) -> Result<()> {
        validate_repository(repo)?;
        progress.phase(BlobPhase::Downloading);
        if let Some(raw) = d.embedded()?.or(self.cached_blob(repo, d).await?) {
            tokio::fs::write(output, &raw).await?;
            progress.position(d.size);
            return Ok(());
        }
        let download = Download {
            registry: self,
            repo,
            descriptor: d,
            progress,
            slots,
        };
        let ranges = ranges(d.size, self.config().transfer.concurrency);
        let mut first = None;
        if ranges.len() > 1 {
            let response = download.request(Some(ranges[0].clone())).await?;
            match response.0.status() {
                StatusCode::PARTIAL_CONTENT => {
                    if download.parallel(output, ranges, response).await? {
                        return Ok(());
                    }
                    progress.phase(BlobPhase::Downloading);
                    progress.position(0);
                }
                // Consume the full response directly when the server ignores Range.
                StatusCode::OK => first = Some(response),
                status if range_unsupported(status) => {}
                _ => return Err(http_error(&response.0)),
            }
        }
        download.sequential(output, first).await
    }
}

struct Download<'a> {
    registry: &'a Registry,
    repo: &'a str,
    descriptor: &'a Descriptor,
    progress: &'a dyn BlobProgress,
    slots: Arc<Semaphore>,
}

impl Download<'_> {
    async fn request(&self, range: Option<Range<u64>>) -> Result<DownloadResponse> {
        let permit = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::network("download queue closed"))?;
        let mut headers = HeaderMap::new();
        if let Some(range) = range {
            headers.insert(
                header::RANGE,
                HeaderValue::from_str(&format!("bytes={}-{}", range.start, range.end - 1))
                    .map_err(|_| Error::input("invalid download range"))?,
            );
        }
        let (response, _) = self
            .registry
            .request(
                Method::GET,
                self.registry.url(&format!(
                    "v2/{}/blobs/{}",
                    self.repo, self.descriptor.digest
                ))?,
                &Registry::scope(self.repo, "pull"),
                headers,
                None,
                true,
                true,
            )
            .await?;
        Ok((response, permit))
    }

    async fn sequential(&self, output: &Path, mut first: Option<DownloadResponse>) -> Result<()> {
        let d = self.descriptor;
        // The copy pipeline needs a readable file, not crash-durable temporary storage.
        let mut file =
            BufWriter::with_capacity(1024 * 1024, tokio::fs::File::create(output).await?);
        let mut hasher = d.digest.hasher();
        let mut count = 0u64;
        let mut attempt = 0;
        loop {
            let result = self
                .download_once(&mut file, &mut hasher, &mut count, first.take())
                .await;
            match result {
                Ok(()) => break,
                Err(e)
                    if e.retryable() && attempt < self.registry.config().transfer.max_retries =>
                {
                    file.flush().await?;
                    tokio::time::sleep(retry_delay(None, attempt)).await;
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        }
        hasher.verify(&d.digest)?;
        file.flush().await?;
        Ok(())
    }
    async fn download_once(
        &self,
        file: &mut BufWriter<tokio::fs::File>,
        hasher: &mut Hasher,
        count: &mut u64,
        first: Option<DownloadResponse>,
    ) -> Result<()> {
        let d = self.descriptor;
        let progress = self.progress;
        if *count == d.size && *count > 0 {
            // Verify all received bytes even if a trailing transport error interrupted the response.
            return Ok(());
        }
        let (mut response, _permit) = match first {
            Some(response) => response,
            None => self.request((*count > 0).then_some(*count..d.size)).await?,
        };
        match response.status() {
            StatusCode::OK => {
                if *count > 0 {
                    // Servers may ignore Range. Restart cleanly instead of appending duplicate bytes.
                    file.flush().await?;
                    file.get_mut().set_len(0).await?;
                    file.seek(std::io::SeekFrom::Start(0)).await?;
                    *hasher = d.digest.hasher();
                    *count = 0;
                    progress.position(0);
                }
            }
            StatusCode::PARTIAL_CONTENT if *count > 0 => {
                let expected = format!("bytes {}-{}/{}", *count, d.size - 1, d.size);
                if response
                    .headers()
                    .get(header::CONTENT_RANGE)
                    .and_then(|v| v.to_str().ok())
                    != Some(expected.as_str())
                {
                    return Err(Error::integrity(
                        "download Content-Range does not match requested bytes",
                    ));
                }
            }
            _ => return Err(http_error(&response)),
        }
        if content_length(&response).is_some_and(|n| n != d.size - *count) {
            return Err(Error::integrity(
                "blob HTTP Content-Length does not match descriptor",
            ));
        }
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let size = response
                .read(&mut buffer)
                .await
                .map_err(|_| Error::network("HTTP response body read failed"))?;
            if size == 0 {
                break;
            }
            let next = count
                .checked_add(size as u64)
                .ok_or_else(|| Error::integrity("blob size overflow"))?;
            if next > d.size {
                return Err(Error::integrity("received blob exceeds descriptor size"));
            }
            file.write_all(&buffer[..size]).await?;
            hasher.update(&buffer[..size]);
            *count = next;
            progress.position(*count);
        }
        if *count != d.size {
            return Err(Error::network(
                "blob download ended before the declared size",
            ));
        }
        Ok(())
    }
}

impl Download<'_> {
    async fn parallel(
        &self,
        output: &Path,
        ranges: Vec<Range<u64>>,
        first: DownloadResponse,
    ) -> Result<bool> {
        tokio::fs::File::create(output)
            .await?
            .set_len(self.descriptor.size)
            .await?;
        let completed = Mutex::new(0u64);
        let mut first = Some(first);
        let mut parts = stream::iter(ranges)
            .map(|range| self.part(output, range, first.take(), &completed))
            .buffer_unordered(self.registry.config().transfer.concurrency);
        let mut supported = true;
        while let Some(result) = parts.next().await {
            supported &= result?;
        }
        // Finish and flush every writer before reusing the same inode for a fallback.
        // Dropping Tokio file futures alone does not wait for their background writes.
        if !supported {
            return Ok(false);
        }
        self.progress.phase(BlobPhase::Verifying);
        let mut file = BufReader::with_capacity(1024 * 1024, tokio::fs::File::open(output).await?);
        let mut hasher = self.descriptor.digest.hasher();
        let mut count = 0u64;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let size = file.read(&mut buffer).await?;
            if size == 0 {
                break;
            }
            count += size as u64;
            if count > self.descriptor.size {
                return Err(Error::integrity("received blob exceeds descriptor size"));
            }
            hasher.update(&buffer[..size]);
        }
        if count != self.descriptor.size {
            return Err(Error::integrity(
                "downloaded blob size does not match descriptor",
            ));
        }
        hasher.verify(&self.descriptor.digest)?;
        Ok(true)
    }

    async fn part(
        &self,
        output: &Path,
        range: Range<u64>,
        mut first: Option<DownloadResponse>,
        completed: &Mutex<u64>,
    ) -> Result<bool> {
        let mut offset = range.start;
        let mut attempt = 0;
        while offset < range.end {
            let result = self
                .part_once(output, &mut offset, range.end, first.take(), completed)
                .await;
            match result {
                Ok(false) => return Ok(false),
                Ok(true) => break,
                Err(error)
                    if error.retryable()
                        && attempt < self.registry.config().transfer.max_retries =>
                {
                    tokio::time::sleep(retry_delay(None, attempt)).await;
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(true)
    }

    async fn part_once(
        &self,
        output: &Path,
        offset: &mut u64,
        end: u64,
        first: Option<DownloadResponse>,
        completed: &Mutex<u64>,
    ) -> Result<bool> {
        let (mut response, _permit) = match first {
            Some(response) => response,
            None => self.request(Some(*offset..end)).await?,
        };
        if range_unsupported(response.status()) || response.status() == StatusCode::OK {
            return Ok(false);
        }
        if response.status() != StatusCode::PARTIAL_CONTENT {
            return Err(http_error(&response));
        }
        let expected = format!("bytes {}-{}/{}", *offset, end - 1, self.descriptor.size);
        if response
            .headers()
            .get(header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            != Some(expected.as_str())
        {
            return Err(Error::integrity(
                "download Content-Range does not match requested bytes",
            ));
        }
        if content_length(&response).is_some_and(|n| n != end - *offset) {
            return Err(Error::integrity(
                "blob HTTP Content-Length does not match requested range",
            ));
        }
        // Allocate disk buffers only while holding a request slot, keeping memory linear in concurrency.
        let mut file = BufWriter::with_capacity(
            1024 * 1024,
            tokio::fs::OpenOptions::new()
                .write(true)
                .open(output)
                .await?,
        );
        file.seek(std::io::SeekFrom::Start(*offset)).await?;
        let result = self
            .read_part(&mut response, &mut file, offset, end, completed)
            .await;
        file.flush().await?;
        result
    }

    async fn read_part(
        &self,
        response: &mut Response,
        file: &mut BufWriter<tokio::fs::File>,
        offset: &mut u64,
        end: u64,
        completed: &Mutex<u64>,
    ) -> Result<bool> {
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let size = response
                .read(&mut buffer)
                .await
                .map_err(|_| Error::network("HTTP response body read failed"))?;
            if size == 0 {
                break;
            }
            let next = offset
                .checked_add(size as u64)
                .ok_or_else(|| Error::integrity("blob size overflow"))?;
            if next > end {
                return Err(Error::integrity("received blob exceeds requested range"));
            }
            file.write_all(&buffer[..size]).await?;
            *offset = next;
            // Serialize callbacks so concurrent parts never report progress out of order.
            let mut count = completed.lock().expect("download progress lock poisoned");
            *count += size as u64;
            self.progress.position(*count);
        }
        if *offset != end {
            return Err(Error::network(
                "blob download ended before the declared range",
            ));
        }
        Ok(true)
    }
}

fn range_unsupported(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_REQUEST | StatusCode::RANGE_NOT_SATISFIABLE | StatusCode::NOT_IMPLEMENTED
    )
}

fn ranges(size: u64, concurrency: usize) -> Vec<Range<u64>> {
    // Small layers already exploit blob-level parallelism; extra requests would add latency.
    if size < 32 * 1024 * 1024 || concurrency < 2 {
        return std::iter::once(0..size).collect();
    }
    let count = (size / (8 * 1024 * 1024)).min(concurrency as u64);
    let step = size / count;
    (0..count)
        .map(|i| i * step..if i + 1 == count { size } else { (i + 1) * step })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::ranges;

    #[test]
    fn ranges_cover_every_byte_once_with_bounded_parallelism() {
        for size in [
            0,
            1,
            32 * 1024 * 1024 - 1,
            32 * 1024 * 1024,
            100_000_001,
            u64::MAX,
        ] {
            for concurrency in [1, 2, 3, 4, 64] {
                let parts = ranges(size, concurrency);
                assert!(parts.len() <= concurrency);
                assert_eq!(parts[0].start, 0);
                assert_eq!(parts.last().unwrap().end, size);
                assert!(parts.windows(2).all(|pair| pair[0].end == pair[1].start));
                assert!(parts.iter().all(|part| part.start < part.end || size == 0));
                if size < 32 * 1024 * 1024 {
                    assert_eq!(parts.len(), 1);
                }
            }
        }
    }
}
