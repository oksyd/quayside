use crate::{
    Error, Result,
    config::parse_size,
    digest::Digest,
    graph::Graph,
    model::{Descriptor, Manifest, ManifestKind, Platform},
    options::WriteOptions,
    reference::Reference,
    registry::{Registry, UploadStart},
};
use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt, stream};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

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

/// A selected source manifest together with its original digest and platform information.
pub struct Resolved {
    /// Digest of the original source manifest before platform selection.
    pub source_digest: Digest,
    /// The selected manifest, preserving the source's original bytes.
    pub manifest: Manifest,
    /// Platform names discovered in the selected image graph.
    pub platforms: Vec<String>,
}

/// Selects content by a pinned digest. No selection ever defaults to the host CPU.
pub async fn resolve(
    source: &Registry,
    reference: &Reference,
    platform: Option<&str>,
) -> Result<Resolved> {
    let root = source.get_manifest(reference).await?;
    let original = root.digest().clone();
    if root.kind == ManifestKind::Image && platform.is_none() && !root.is_artifact()? {
        let p = image_platform(source, &reference.repository, &root).await?;
        let mut root = root;
        root.descriptor.platform = Some(p.clone());
        return Ok(Resolved {
            source_digest: original,
            manifest: root,
            platforms: vec![p.to_string()],
        });
    }
    let Some(wanted) = platform.map(str::parse::<Platform>).transpose()? else {
        let platforms = root
            .children()?
            .iter()
            .filter_map(|d| d.platform.as_ref().map(ToString::to_string))
            .collect();
        return Ok(Resolved {
            source_digest: original,
            manifest: root,
            platforms,
        });
    };
    if root.kind == ManifestKind::Image {
        let p = image_platform(source, &reference.repository, &root).await?;
        if !p.matches(&wanted) {
            return Err(Error::input(format!("requested {wanted}, image is {p}")));
        }
        let mut root = root;
        root.descriptor.platform = Some(p.clone());
        return Ok(Resolved {
            source_digest: original,
            manifest: root,
            platforms: vec![p.to_string()],
        });
    }
    let mut queue = vec![(root, 0usize)];
    let mut seen = BTreeSet::new();
    let mut available = BTreeSet::new();
    let mut candidates = BTreeMap::new();
    let mut metadata = 0u64;
    while let Some((index, depth)) = queue.pop() {
        if !seen.insert(index.digest().clone()) {
            continue;
        }
        metadata += index.raw.len() as u64;
        if depth > source.config().transfer.max_depth
            || seen.len() > source.config().transfer.max_objects
            || metadata > parse_size(&source.config().transfer.max_metadata_size)?
        {
            return Err(Error::input(
                "platform selection exceeded configured graph limits",
            ));
        }
        for d in index.children()? {
            if let Some(p) = &d.platform {
                available.insert(p.to_string());
            }
            let is_index = matches!(
                d.media_type.as_str(),
                crate::model::OCI_INDEX | crate::model::DOCKER_INDEX
            );
            if !is_index && d.platform.as_ref().is_some_and(|p| !p.matches(&wanted)) {
                continue;
            }
            if d.size > parse_size(&source.config().transfer.max_manifest_size)? {
                return Err(Error::input("child manifest exceeds size limit"));
            }
            let mut child = if let Some(raw) = d.embedded()? {
                Manifest::parse(raw, Some(&d.media_type), Some(&d.digest))?
            } else {
                source.get_manifest(&reference.pinned(&d.digest)).await?
            };
            child.verify_descriptor(&d)?;
            metadata = metadata
                .checked_add(child.raw.len() as u64)
                .ok_or_else(|| Error::input("selection metadata overflow"))?;
            if metadata > parse_size(&source.config().transfer.max_metadata_size)? {
                return Err(Error::input("platform selection metadata limit exceeded"));
            }
            if child.kind == ManifestKind::Index {
                queue.push((child, depth + 1));
            } else {
                if child.is_artifact()? {
                    continue;
                }
                let p = match d.platform {
                    Some(p) => p,
                    None => image_platform(source, &reference.repository, &child).await?,
                };
                available.insert(p.to_string());
                if p.matches(&wanted) {
                    child.descriptor.platform = Some(p.clone());
                    candidates.insert(child.digest().clone(), (child, p));
                }
            }
        }
        if queue.len() + candidates.len() > source.config().transfer.max_objects {
            return Err(Error::input("platform selection object limit exceeded"));
        }
    }
    if candidates.len() != 1 {
        return Err(Error::input(format!(
            "platform {wanted} matched {} objects; available: {}",
            candidates.len(),
            available.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    let (manifest, p) = candidates
        .into_values()
        .next()
        .ok_or_else(|| Error::input("no selected platform"))?;
    Ok(Resolved {
        source_digest: original,
        manifest,
        platforms: vec![p.to_string()],
    })
}

/// Read an image configuration to determine its platform; artifacts do not imply a platform.
pub async fn image_platform(
    registry: &Registry,
    repo: &str,
    manifest: &Manifest,
) -> Result<Platform> {
    if manifest.is_artifact()? {
        return Err(Error::input(
            "OCI artifacts have no image platform; --platform and index create require container images",
        ));
    }
    let d = manifest.config()?;
    let raw = registry
        .get_blob_bytes(
            repo,
            &d,
            parse_size(&registry.config().transfer.max_manifest_size)?,
        )
        .await?;
    Platform::from_config(&serde_json::from_slice(&raw)?)
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
/// A failed PATCH is reconciled against the server before its body is sent again.
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
    let chunk_size = parse_size(&cfg.chunk_size)?.max(minimum_chunk);
    if chunk_size > 64 * 1024 * 1024
        || chunk_size.saturating_mul(cfg.concurrency as u64) > 128 * 1024 * 1024
    {
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
    while offset < d.size {
        let size = (d.size - offset).min(chunk_size) as usize;
        let mut buffer = vec![0u8; size];
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        file.read_exact(&mut buffer).await?;
        let end = offset + size as u64;
        match target
            .patch_upload(repo, url.clone(), offset, Bytes::from(buffer))
            .await
        {
            Ok(next) => {
                url = next;
                offset = end;
            }
            Err(e) if e.retryable() && reconciliations < cfg.max_retries => {
                reconciliations += 1;
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

/// Copy or plan unique graph payloads with bounded concurrency, temporary space and observation.
pub async fn transfer_remote_blobs(
    source: &Registry,
    source_ref: &Reference,
    target: &Registry,
    destination: &Reference,
    graph: &Graph,
    dry_run: bool,
    observer: &dyn crate::observer::Observer,
) -> Result<TransferStats> {
    let display = observer.begin(
        if dry_run {
            crate::observer::Phase::Planning
        } else {
            crate::observer::Phase::Copying
        },
        graph.blobs.len(),
    );
    let temp_limit = parse_size(&target.config().transfer.max_temp_size)?;
    // Cross-registry transfers cannot mount: reject an impossible staging plan before any write.
    if source.endpoint().origin() != target.endpoint().origin() {
        for d in graph.blobs.values().filter(|d| d.size > temp_limit) {
            if !target.blob_exists(&destination.repository, d).await? {
                return Err(Error::input(
                    "blob exceeds max_temp_size; increase the temporary storage limit",
                ));
            }
        }
    }
    let budget = crate::temporary::Budget::new(temp_limit);
    let outcomes = stream::iter(graph.blobs.values().cloned())
        .map(|d| {
            let progress = display.blob(d.digest.to_string(), d.size);
            let budget = budget.clone();
            let source = source.clone();
            let target = target.clone();
            let from_repo = source_ref.repository.clone();
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
                    .download_blob_progress(&from_repo, &d, temporary.path(), progress.as_ref())
                    .await?;
                upload_file_progress(
                    &target,
                    &to_repo,
                    &d,
                    temporary.path(),
                    initial,
                    progress.as_ref(),
                )
                .await?;
                progress.finish();
                Ok(TransferStats {
                    copied_blobs: 1,
                    bytes_transferred: d.size.saturating_mul(2),
                    ..Default::default()
                })
            }
        })
        .buffer_unordered(target.config().transfer.concurrency)
        .try_collect::<Vec<_>>()
        .await?;
    let mut result = TransferStats::default();
    for o in outcomes {
        result.merge(&o);
    }
    Ok(result)
}

/// Publish dependency manifests by digest only; no temporary tags and no DELETEs.
pub async fn publish_dependencies(
    target: &Registry,
    destination: &Reference,
    graph: &Graph,
) -> Result<()> {
    for digest in &graph.order {
        let manifest = graph
            .manifests
            .get(digest)
            .ok_or_else(|| Error::integrity("internal graph order is inconsistent"))?;
        let pinned = destination.pinned(digest);
        match target.manifest_optional(&pinned).await? {
            Some(existing) if existing.raw == manifest.raw => continue,
            Some(_) => {
                return Err(Error::integrity(
                    "registry returned different manifest bytes for a digest",
                ));
            }
            None => target.put_manifest(&pinned, manifest).await?,
        }
    }
    Ok(())
}

/// Publish the root under overwrite policy and verify that its remote bytes are unchanged.
pub async fn publish_root(
    target: &Registry,
    destination: &Reference,
    root: &Manifest,
    overwrite: bool,
) -> Result<()> {
    // Recheck immediately before publishing the tag. This still cannot replace server-side CAS.
    if !check_destination(target, destination, root, overwrite).await? {
        target.put_manifest(destination, root).await?;
    }
    let verified = target.get_manifest(destination).await?;
    if verified.raw != root.raw {
        return Err(Error::integrity(
            "destination root changed or was rewritten during publication",
        ));
    }
    Ok(())
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
    let graph = remote_graph(source, source_ref, resolved.manifest).await?;
    drop(resolving);
    let checking = observer.begin(crate::observer::Phase::CheckingDestination, 0);
    let already_present =
        check_destination(target, destination, &graph.root, write.overwrite).await?;
    drop(checking);
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
        publish_dependencies(target, destination, &graph).await?;
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
