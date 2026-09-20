use crate::{
    Error, Result,
    config::parse_size,
    digest::Digest,
    graph::Graph,
    model::{Descriptor, Manifest},
    options::WriteOptions,
    reference::Reference,
    registry::{Registry, UploadStart},
};
mod publish;
mod resolve;

pub(crate) use publish::publish_children;
pub use publish::{publish_dependencies, publish_root};
pub use resolve::{Resolved, image_platform, resolve};

use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt, stream};
use serde::Serialize;
use std::{collections::BTreeMap, path::Path, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::Semaphore;

/// Whether independently attached signatures and SBOMs were copied with the selected graph.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Referrers {
    /// Independent referrers were not included in this operation.
    NotCopied,
}

/// Typed result of copying a selected remote OCI dependency graph.
#[derive(Debug, Serialize)]
pub struct CopyResult {
    /// Fully qualified source registry reference.
    pub source: String,
    /// Fully qualified destination reference with an explicit tag or digest.
    pub destination: String,
    /// Digest of the original source manifest before platform selection.
    pub source_digest: Digest,
    /// Digest of the selected or published destination manifest.
    pub target_digest: Digest,
    /// Platform names discovered in the selected image graph.
    pub platforms: Vec<String>,
    /// Whether the destination root already matched during the initial destination check.
    pub already_present: bool,
    /// Plan the operation without publishing or replacing content.
    pub dry_run: bool,
    /// Counts of copied, mounted, skipped and planned blobs.
    pub stats: TransferStats,
    /// Whether independent referrers were included in the operation.
    pub referrers: Referrers,
}

/// Fetch and verify a bounded manifest dependency graph from a registry.
pub async fn remote_graph(
    registry: &Registry,
    reference: &Reference,
    root: Manifest,
) -> Result<Graph> {
    Graph::build(root, &registry.config().transfer, |d| {
        let registry = registry.clone();
        let reference = reference.pinned(&d.digest);
        async move { registry.get_manifest(&reference).await }
    })
    .await
}

/// Returns true only if the exact root bytes are already at the destination.
/// This is a best-effort conflict check, not a registry-side compare-and-swap lock.
pub async fn check_destination(
    target: &Registry,
    destination: &Reference,
    root: &Manifest,
    overwrite: bool,
) -> Result<bool> {
    destination.require_destination()?;
    if let Some(d) = destination.digest() {
        d.verify(&root.raw)?;
    }
    if let Some(existing) = target.manifest_optional(destination).await? {
        if existing.raw == root.raw {
            return Ok(true);
        }
        if !overwrite || destination.digest().is_some() {
            return Err(Error::conflict(format!(
                "destination {} exists with different content; use --overwrite for an intentional tag update",
                destination
            )));
        }
    }
    Ok(false)
}

/// Completed logical transfer counts, excluding lower-level request attempts.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TransferStats {
    /// Number of blobs downloaded and uploaded successfully.
    pub copied_blobs: u64,
    /// Number of verified server-side cross-repository blob mounts.
    pub mounted_blobs: u64,
    /// Number of blobs already present at the destination.
    pub skipped_blobs: u64,
    /// Number of missing blobs that would be copied during a dry run.
    pub planned_blobs: u64,
    /// Completed logical payload bytes downloaded + uploaded (not TCP / retry overhead).
    pub bytes_transferred: u64,
}
impl TransferStats {
    /// Add the outcomes of another transfer batch to these statistics.
    pub fn merge(&mut self, other: &Self) {
        self.copied_blobs += other.copied_blobs;
        self.mounted_blobs += other.mounted_blobs;
        self.skipped_blobs += other.skipped_blobs;
        self.planned_blobs += other.planned_blobs;
        self.bytes_transferred += other.bytes_transferred;
    }
}

/// Buffer-bounded upload. Chunks are immutable Bytes so authentication retries are replayable.
/// Failed chunks are reconciled against the server before their bodies are sent again.
pub async fn upload_file(
    target: &Registry,
    repo: &str,
    d: &Descriptor,
    path: &Path,
    initial: Option<UploadStart>,
) -> Result<bool> {
    upload_file_progress(target, repo, d, path, initial, &crate::observer::NoProgress).await
}
async fn upload_file_progress(
    target: &Registry,
    repo: &str,
    d: &Descriptor,
    path: &Path,
    initial: Option<UploadStart>,
    progress: &dyn crate::observer::BlobProgress,
) -> Result<bool> {
    let mut initial = initial;
    for attempt in 0..=target.config().transfer.max_retries {
        let start = match initial.take() {
            Some(s) => Ok(s),
            None => target.start_upload(repo, &d.digest, None).await,
        };
        let result = match start {
            Ok(UploadStart::Mounted) => {
                if !target.blob_exists(repo, d).await? {
                    return Err(Error::integrity(
                        "registry claimed a successful mount but blob is unavailable",
                    ));
                }
                return Ok(true);
            }
            Ok(UploadStart::Session { url, minimum_chunk }) => {
                upload_session(target, repo, d, path, (url, minimum_chunk), progress).await
            }
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => {
                if !target.blob_exists(repo, d).await? {
                    return Err(Error::integrity(
                        "uploaded blob is not available after commit",
                    ));
                }
                return Ok(false);
            }
            Err(e) if e.retryable() && attempt < target.config().transfer.max_retries => {
                // Commit response may have been lost; check before starting another session.
                if matches!(target.blob_exists(repo, d).await, Ok(true)) {
                    return Ok(false);
                }
                tokio::time::sleep(std::time::Duration::from_millis(250u64 << attempt.min(6)))
                    .await;
            }
            Err(e) => return Err(e),
        }
    }
    Err(Error::network("upload retries exhausted"))
}
async fn upload_session(
    target: &Registry,
    repo: &str,
    d: &Descriptor,
    path: &Path,
    session: (url::Url, u64),
    progress: &dyn crate::observer::BlobProgress,
) -> Result<()> {
    let (mut url, minimum_chunk) = session;
    progress.phase(crate::observer::BlobPhase::Uploading);
    let cfg = &target.config().transfer;
    let initial_chunk = parse_size(&cfg.chunk_size)?.max(minimum_chunk);
    let maximum_chunk = (64 * 1024 * 1024).min(128 * 1024 * 1024 / cfg.concurrency as u64);
    let request_timeout = crate::config::duration(&cfg.idle_timeout)?;
    if initial_chunk > maximum_chunk {
        return Err(Error::unsupported(
            "registry minimum chunk size exceeds the configured memory safety budget",
        ));
    }
    let mut file = tokio::fs::File::open(path).await?;
    if file.metadata().await?.len() != d.size {
        return Err(Error::integrity("local blob size changed before upload"));
    }
    let mut offset = 0u64;
    let mut reconciliations = 0usize;
    let mut chunk_size = initial_chunk;
    while offset < d.size {
        let size = (d.size - offset).min(chunk_size) as usize;
        let mut buffer = vec![0u8; size];
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        file.read_exact(&mut buffer).await?;
        let end = offset + size as u64;
        let started = std::time::Instant::now();
        // OCI permits the final payload in the commit PUT, saving one round trip per blob.
        let result = if end == d.size {
            match target
                .commit_upload(repo, url.clone(), &d.digest, offset, Bytes::from(buffer))
                .await
            {
                Ok(()) => {
                    progress.position(end);
                    progress.phase(crate::observer::BlobPhase::Committing);
                    return Ok(());
                }
                Err(error) => Err(error),
            }
        } else {
            target
                .patch_upload(repo, url.clone(), offset, Bytes::from(buffer))
                .await
        };
        match result {
            Ok(next) => {
                url = next;
                offset = end;
                chunk_size = next_chunk_size(
                    chunk_size,
                    initial_chunk,
                    maximum_chunk,
                    started.elapsed(),
                    request_timeout,
                );
            }
            Err(e) if e.retryable() && reconciliations < cfg.max_retries => {
                reconciliations += 1;
                chunk_size = initial_chunk;
                match target.upload_status(repo, url.clone()).await {
                    Ok((next, server_offset))
                        if server_offset >= offset && server_offset <= end
                        // Empty sessions often report 0-0, indistinguishable from one byte.
                        && !(offset == 0 && server_offset == 1) =>
                    {
                        url = next;
                        offset = server_offset;
                    }
                    _ => return Err(e), // Outer loop starts a new bounded attempt; never guesses.
                }
            }
            Err(e) => return Err(e),
        }
        progress.position(offset);
    }
    progress.phase(crate::observer::BlobPhase::Committing);
    target.finish_upload(repo, url, &d.digest).await
}

fn next_chunk_size(
    current: u64,
    initial: u64,
    maximum: u64,
    elapsed: std::time::Duration,
    timeout: std::time::Duration,
) -> u64 {
    // Amortize request latency while leaving room for variation within the request timeout.
    if elapsed < (timeout / 4).min(std::time::Duration::from_secs(1)) {
        (current * 2).min(maximum)
    } else if elapsed > (timeout / 2).min(std::time::Duration::from_secs(4)) {
        (current / 2).max(initial)
    } else {
        current
    }
}

// Drop the file before releasing its quota, including queued and cancelled uploads.
struct StagedBlob {
    temporary: tempfile::NamedTempFile,
    _reservation: crate::temporary::Reservation,
    descriptor: Descriptor,
    initial: Option<UploadStart>,
    progress: Box<dyn crate::observer::BlobProgress>,
}

pub(crate) fn largest_blobs_first(graph: &Graph) -> Vec<Descriptor> {
    let mut blobs: Vec<_> = graph.blobs.values().cloned().collect();
    blobs.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.digest.cmp(&b.digest)));
    blobs
}

/// Copy or plan unique payloads, prioritizing large blobs with independent download/upload limits.
/// Verified files pass through a bounded queue and retain their disk quota until upload completes.
pub async fn transfer_remote_blobs(
    source: &Registry,
    source_ref: &Reference,
    target: &Registry,
    destination: &Reference,
    graph: &Graph,
    dry_run: bool,
    observer: &dyn crate::observer::Observer,
) -> Result<TransferStats> {
    transfer_remote_inputs(
        [(source, source_ref, graph)],
        target,
        destination,
        dry_run,
        observer,
    )
    .await
}

struct RemoteBlob {
    source: Registry,
    repository: String,
    descriptor: Descriptor,
}

pub(crate) async fn transfer_remote_inputs<'a>(
    inputs: impl IntoIterator<Item = (&'a Registry, &'a Reference, &'a Graph)>,
    target: &Registry,
    destination: &Reference,
    dry_run: bool,
    observer: &dyn crate::observer::Observer,
) -> Result<TransferStats> {
    let mut unique = BTreeMap::<Digest, RemoteBlob>::new();
    for (source, reference, graph) in inputs {
        for d in graph.blobs.values() {
            if let Some(previous) = unique.get(&d.digest) {
                if previous.descriptor.size != d.size {
                    return Err(Error::integrity(
                        "inconsistent size for a shared index input blob",
                    ));
                }
                // Prefer a same-registry source so a shared blob can be mounted without download.
                if previous.source.endpoint().origin() == target.endpoint().origin()
                    || source.endpoint().origin() != target.endpoint().origin()
                {
                    continue;
                }
            }
            unique.insert(
                d.digest.clone(),
                RemoteBlob {
                    source: source.clone(),
                    repository: reference.repository.clone(),
                    descriptor: d.clone(),
                },
            );
        }
    }
    let mut blobs: Vec<_> = unique.into_values().collect();
    blobs.sort_by(|a, b| {
        b.descriptor
            .size
            .cmp(&a.descriptor.size)
            .then_with(|| a.descriptor.digest.cmp(&b.descriptor.digest))
    });
    let display = observer.begin(
        if dry_run {
            crate::observer::Phase::Planning
        } else {
            crate::observer::Phase::Copying
        },
        blobs.len(),
    );
    let temp_limit = parse_size(&target.config().transfer.max_temp_size)?;
    // Cross-registry transfers cannot mount: reject an impossible staging plan before any write.
    for blob in &blobs {
        if blob.source.endpoint().origin() != target.endpoint().origin()
            && blob.descriptor.size > temp_limit
            && !target
                .blob_exists(&destination.repository, &blob.descriptor)
                .await?
        {
            return Err(Error::input(
                "blob exceeds max_temp_size; increase the temporary storage limit",
            ));
        }
    }
    let budget = crate::temporary::Budget::new(temp_limit);
    let concurrency = target.config().transfer.concurrency;
    // Every source and every range shares one operation-wide download limit.
    let slots = Arc::new(Semaphore::new(concurrency));
    let (sender, receiver) = tokio::sync::mpsc::channel::<StagedBlob>(concurrency);
    let display_ref = display.as_ref();
    let downloads = async move {
        let stats = stream::iter(blobs)
            .map(|blob| {
                let d = blob.descriptor;
                let sender = sender.clone();
                let progress = display_ref.blob(d.digest.to_string(), d.size);
                let budget = budget.clone();
                let source = blob.source;
                let slots = slots.clone();
                let target = target.clone();
                let from_repo = blob.repository;
                let to_repo = destination.repository.clone();
                async move {
                    if target.blob_exists(&to_repo, &d).await? {
                        progress.finish();
                        return Ok::<_, Error>(TransferStats {
                            skipped_blobs: 1,
                            ..Default::default()
                        });
                    }
                    if dry_run {
                        progress.finish();
                        return Ok(TransferStats {
                            planned_blobs: 1,
                            ..Default::default()
                        });
                    }
                    let initial = if source.endpoint().origin() == target.endpoint().origin()
                        && from_repo != to_repo
                    {
                        Some(
                            target
                                .start_upload(&to_repo, &d.digest, Some(&from_repo))
                                .await?,
                        )
                    } else {
                        None
                    };
                    if matches!(&initial, Some(UploadStart::Mounted)) {
                        if !target.blob_exists(&to_repo, &d).await? {
                            return Err(Error::integrity("mounted blob cannot be read back"));
                        }
                        progress.finish();
                        return Ok(TransferStats {
                            mounted_blobs: 1,
                            ..Default::default()
                        });
                    }
                    // Reserve all bytes before writing; concurrent workers share this operation's quota.
                    // The temporary file drops before its reservation on success, error or cancellation.
                    progress.phase(crate::observer::BlobPhase::Waiting);
                    let _reservation = budget.reserve(d.size).await?;
                    // One verified temporary file per active worker, never a whole layer in RAM.
                    let temporary = tempfile::NamedTempFile::new()?;
                    source
                        .download_blob_with_slots(
                            &from_repo,
                            &d,
                            temporary.path(),
                            progress.as_ref(),
                            slots,
                        )
                        .await?;
                    progress.phase(crate::observer::BlobPhase::Waiting);
                    sender
                        .send(StagedBlob {
                            temporary,
                            _reservation,
                            descriptor: d,
                            initial,
                            progress,
                        })
                        .await
                        .map_err(|_| Error::network("upload queue closed"))?;
                    Ok(TransferStats::default())
                }
            })
            .buffer_unordered(concurrency)
            .try_fold(TransferStats::default(), |mut total, stats| async move {
                total.merge(&stats);
                Ok(total)
            })
            .await;
        drop(sender);
        stats
    };
    let uploads = stream::unfold(receiver, |mut receiver| async {
        receiver.recv().await.map(|blob| (blob, receiver))
    })
    .map(|blob| async move {
        let mut blob = blob;
        upload_file_progress(
            target,
            &destination.repository,
            &blob.descriptor,
            blob.temporary.path(),
            blob.initial.take(),
            blob.progress.as_ref(),
        )
        .await?;
        blob.progress.finish();
        Ok::<_, Error>(TransferStats {
            copied_blobs: 1,
            bytes_transferred: blob.descriptor.size.saturating_mul(2),
            ..Default::default()
        })
    })
    .buffer_unordered(concurrency)
    .try_fold(TransferStats::default(), |mut total, stats| async move {
        total.merge(&stats);
        Ok(total)
    });
    // Poll both stages independently. Dropping either on failure cancels the entire pipeline.
    let (mut result, uploaded) = tokio::try_join!(downloads, uploads)?;
    result.merge(&uploaded);
    Ok(result)
}

/// Resolve, transfer and publish a selected OCI dependency graph, returning a typed operation result.
pub async fn copy(
    source: &Registry,
    source_ref: &Reference,
    target: &Registry,
    destination: &Reference,
    platform: Option<&str>,
    write: &WriteOptions,
    observer: &dyn crate::observer::Observer,
) -> Result<CopyResult> {
    let resolving = observer.begin(crate::observer::Phase::Resolving, 0);
    let resolved = resolve(source, source_ref, platform).await?;
    resolved.manifest.check_transfer_supported()?;
    drop(resolving);
    let checking = observer.begin(crate::observer::Phase::CheckingDestination, 0);
    let already_present =
        check_destination(target, destination, &resolved.manifest, write.overwrite).await?;
    drop(checking);
    let resolving = observer.begin(crate::observer::Phase::Resolving, 0);
    let graph = remote_graph(source, source_ref, resolved.manifest).await?;
    drop(resolving);
    let stats = transfer_remote_blobs(
        source,
        source_ref,
        target,
        destination,
        &graph,
        write.dry_run,
        observer,
    )
    .await?;
    let _publishing = observer.begin(crate::observer::Phase::Publishing, 0);
    if !write.dry_run {
        publish_children(target, destination, &graph).await?;
        publish_root(target, destination, &graph.root, write.overwrite).await?;
    }
    let platforms = if resolved.platforms.is_empty() {
        graph.platforms()?
    } else {
        resolved.platforms
    };
    Ok(CopyResult {
        source: source_ref.to_string(),
        destination: destination.to_string(),
        source_digest: resolved.source_digest,
        target_digest: graph.root.digest().clone(),
        platforms,
        already_present,
        dry_run: write.dry_run,
        stats,
        referrers: Referrers::NotCopied,
    })
}

#[cfg(test)]
mod tests {
    use super::next_chunk_size;
    use std::time::Duration;

    #[test]
    fn adaptive_chunks_respect_memory_minimum_and_timeout() {
        let mib = 1024 * 1024;
        let timeout = Duration::from_secs(60);
        let fast = Duration::from_millis(100);
        let slow = Duration::from_secs(5);
        let initial = 8 * mib;
        let maximum = 32 * mib; // Four upload workers share 128MiB.
        let next = |current, elapsed| next_chunk_size(current, initial, maximum, elapsed, timeout);
        assert_eq!(next(initial, fast), 16 * mib);
        assert_eq!(next(16 * mib, fast), maximum);
        assert_eq!(next(maximum, fast), maximum);
        assert_eq!(next(maximum, slow), 16 * mib);
        assert_eq!(next(initial, slow), initial);
        assert_eq!(next(16 * mib, Duration::from_secs(2)), 16 * mib);
        // A shorter request timeout reduces the growth/shrink thresholds.
        assert_eq!(
            next_chunk_size(
                16 * mib,
                initial,
                maximum,
                Duration::from_millis(600),
                Duration::from_secs(2)
            ),
            16 * mib
        );
        assert_eq!(
            next_chunk_size(
                16 * mib,
                initial,
                maximum,
                Duration::from_millis(1100),
                Duration::from_secs(2)
            ),
            initial
        );
    }
}
