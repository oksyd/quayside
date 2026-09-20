//! OCI Image Layout and uncompressed tar transport. Never extracts image root filesystems.
use crate::{
    Error, Result,
    config::{TransferConfig, parse_size},
    graph::Graph,
    model::{Descriptor, Manifest, ManifestKind, OCI_INDEX},
    options::{ArchiveFormat, WriteOptions},
    reference::Reference,
    registry::Registry,
    storage,
    transfer::{self, TransferStats},
};
use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt, stream};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::io::AsyncReadExt;

/// Typed outcome of exporting a remote graph to a local OCI layout or archive.
#[derive(Debug, serde::Serialize)]
pub struct PullResult {
    /// Source registry reference exported to local storage.
    pub source: String,
    /// Digest of the original source manifest before platform selection.
    pub source_digest: crate::digest::Digest,
    /// Digest of the selected or published destination manifest.
    pub target_digest: crate::digest::Digest,
    /// Destination path for the exported layout directory or archive.
    pub output: PathBuf,
    /// OCI layout directory or uncompressed tar archive format.
    pub format: ArchiveFormat,
    /// Total declared payload bytes in the selected graph.
    pub blob_bytes: u64,
    /// Number of unique non-manifest payloads in the selected graph.
    pub blobs: usize,
    /// Number of unique manifests in the selected graph.
    pub manifests: usize,
    /// Plan the operation without publishing or replacing content.
    pub dry_run: bool,
    /// Whether independent referrers were included in the operation.
    pub referrers: transfer::Referrers,
}
/// Typed outcome of importing a local OCI graph into a registry.
#[derive(Debug, serde::Serialize)]
pub struct PushResult {
    /// Local OCI layout directory or archive that was imported.
    pub source: PathBuf,
    /// Fully qualified destination reference with an explicit tag or digest.
    pub destination: String,
    /// Digest of the selected or published destination manifest.
    pub target_digest: crate::digest::Digest,
    /// Counts of copied, mounted, skipped and planned blobs.
    pub stats: TransferStats,
    /// Plan the operation without publishing or replacing content.
    pub dry_run: bool,
    /// Whether independent referrers were included in the operation.
    pub referrers: transfer::Referrers,
}

/// An opened OCI layout, owning temporary extraction storage when needed.
pub struct LocalLayout {
    /// Filesystem directory containing oci-layout, index.json and blob objects.
    pub root: PathBuf,
    _temporary: Option<tempfile::TempDir>,
    temporary_bytes: u64,
}
struct CancelGuard(Arc<AtomicBool>);
impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}
struct Cancellable<R> {
    reader: R,
    cancelled: Arc<AtomicBool>,
}
impl<R: Read> Read for Cancellable<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(io::Error::other("archive operation cancelled"));
        }
        self.reader.read(buf)
    }
}
async fn blocking<T: Send + 'static>(
    f: impl FnOnce(Arc<AtomicBool>) -> Result<T> + Send + 'static,
) -> Result<T> {
    let flag = Arc::new(AtomicBool::new(false));
    let guard = CancelGuard(flag.clone());
    let result = tokio::task::spawn_blocking(move || f(flag))
        .await
        .map_err(|_| Error::new(crate::error::Code::Execution, "archive worker failed"))?;
    drop(guard);
    result
}

/// Construct the OCI blob storage path for a digest under a layout root.
pub fn blob_path(root: &Path, d: &crate::digest::Digest) -> PathBuf {
    root.join("blobs").join(d.algorithm()).join(d.encoded())
}
fn checked_file(root: &Path, relative: &Path) -> Result<PathBuf> {
    storage::reject_symlink(root)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        match component {
            Component::Normal(c) => {
                current.push(c);
                storage::reject_symlink(&current)?;
            }
            _ => return Err(Error::input("unsafe OCI layout path")),
        }
    }
    if !fs::metadata(&current)?.is_file() {
        return Err(Error::input("layout object is not a regular file"));
    }
    Ok(current)
}
fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    if file.metadata()?.len() > limit {
        return Err(Error::input("layout metadata exceeds size limit"));
    }
    let mut result = vec![];
    file.take(limit + 1).read_to_end(&mut result)?;
    if result.len() as u64 > limit {
        return Err(Error::input("layout metadata grew beyond size limit"));
    }
    Ok(result)
}

impl LocalLayout {
    /// Open a layout directory or safely extract a bounded archive into owned temporary storage.
    pub async fn open(path: &Path, limits: &TransferConfig) -> Result<Self> {
        storage::reject_symlink(path)?;
        if path.is_dir() {
            return Ok(Self {
                root: path.to_path_buf(),
                _temporary: None,
                temporary_bytes: 0,
            });
        }
        let path = path.to_path_buf();
        let limits = limits.clone();
        let (temporary, temporary_bytes) =
            blocking(move |flag| extract_archive(&path, &limits, flag)).await?;
        Ok(Self {
            root: temporary.path().to_path_buf(),
            _temporary: Some(temporary),
            temporary_bytes,
        })
    }
    /// Resolve exactly one root from the layout index, optionally by digest or reference annotation.
    pub fn selected_root(
        &self,
        reference: Option<&str>,
        limits: &TransferConfig,
    ) -> Result<Manifest> {
        let layout_path = checked_file(&self.root, Path::new("oci-layout"))?;
        let layout: Value = serde_json::from_slice(&read_limited(&layout_path, 4096)?)?;
        if layout.get("imageLayoutVersion").and_then(Value::as_str) != Some("1.0.0") {
            return Err(Error::unsupported("unsupported OCI Image Layout version"));
        }
        let index = checked_file(&self.root, Path::new("index.json"))?;
        let index = Manifest::parse(
            Bytes::from(read_limited(
                &index,
                parse_size(&limits.max_manifest_size)?,
            )?),
            Some(OCI_INDEX),
            None,
        )?;
        if index.kind != ManifestKind::Index {
            return Err(Error::input("layout index.json is not an OCI image index"));
        }
        let candidates: Vec<_> = index
            .children()?
            .into_iter()
            .filter(|d| {
                reference.is_none_or(|r| {
                    d.digest.as_str() == r
                        || d.annotations
                            .get("org.opencontainers.image.ref.name")
                            .is_some_and(|n| n == r)
                })
            })
            .collect();
        if candidates.len() != 1 {
            return Err(Error::input(format!(
                "layout root matched {} descriptors; use --ref with an exact ref name or digest",
                candidates.len()
            )));
        }
        let descriptor = &candidates[0];
        let mut m = read_manifest(&self.root, descriptor, limits)?;
        m.descriptor.platform = descriptor.platform.clone();
        Ok(m)
    }
    /// Build and verify the selected manifest dependency graph from local files.
    pub async fn graph(&self, root: Manifest, limits: &TransferConfig) -> Result<Graph> {
        Graph::build(root, limits, |d| {
            let root = self.root.clone();
            let limits = limits.clone();
            async move { read_manifest(&root, &d, &limits) }
        })
        .await
    }
    /// Verify graph payloads against their descriptors under the configured concurrency limit.
    pub async fn verify_blobs(&self, graph: &Graph, limits: &TransferConfig) -> Result<()> {
        let total = graph.blobs.values().try_fold(0u64, |a, d| {
            a.checked_add(d.size)
                .ok_or_else(|| Error::input("layout size overflow"))
        })?;
        if total > parse_size(&limits.max_archive_size)? {
            return Err(Error::input("layout exceeds configured storage size limit"));
        }
        stream::iter(graph.blobs.values().cloned())
            .map(|d| {
                let root = self.root.clone();
                async move {
                    if d.embedded()?.is_some() {
                        return Ok::<_, Error>(());
                    }
                    let path = checked_file(
                        &root,
                        Path::new("blobs")
                            .join(d.digest.algorithm())
                            .join(d.digest.encoded())
                            .as_path(),
                    )?;
                    verify_local_blob(&path, &d).await
                }
            })
            .buffer_unordered(limits.concurrency)
            .try_collect::<Vec<_>>()
            .await?;
        Ok(())
    }
}
fn read_manifest(root: &Path, d: &Descriptor, limits: &TransferConfig) -> Result<Manifest> {
    if d.size > parse_size(&limits.max_manifest_size)? {
        return Err(Error::input("layout manifest exceeds limit"));
    }
    let raw = if let Some(raw) = d.embedded()? {
        raw
    } else {
        let relative = Path::new("blobs")
            .join(d.digest.algorithm())
            .join(d.digest.encoded());
        let path = checked_file(root, &relative)?;
        Bytes::from(read_limited(&path, parse_size(&limits.max_manifest_size)?)?)
    };
    d.verify(&raw)?;
    let m = Manifest::parse(raw, Some(&d.media_type), Some(&d.digest))?;
    m.verify_descriptor(d)?;
    Ok(m)
}
/// Verify a local payload's size and digest against its descriptor.
pub async fn verify_local_blob(path: &Path, d: &Descriptor) -> Result<()> {
    let mut file = tokio::fs::File::open(path).await?;
    if file.metadata().await?.len() != d.size {
        return Err(Error::integrity(format!(
            "local size mismatch for {}",
            d.digest
        )));
    }
    let mut buf = vec![0u8; 64 * 1024];
    let mut h = d.digest.hasher();
    let mut count = 0u64;
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > d.size {
            return Err(Error::integrity("local blob grew during verification"));
        }
        h.update(&buf[..n]);
    }
    if count != d.size {
        return Err(Error::integrity("local blob changed during verification"));
    }
    h.verify(&d.digest)
}

fn safe_archive_path(path: &Path) -> Result<PathBuf> {
    let text = path
        .to_str()
        .ok_or_else(|| Error::input("non-UTF8 archive path"))?;
    // Reject Windows separators/drive paths even when extraction runs on Linux.
    if text.len() > 4096 || text.contains(['\\', ':']) {
        return Err(Error::input("unsafe archive path"));
    }
    let mut clean = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(s) => clean.push(s),
            Component::CurDir => {}
            _ => {
                return Err(Error::input(
                    "archive path traversal or absolute path rejected",
                ));
            }
        }
    }
    Ok(clean)
}
fn extract_archive(
    path: &Path,
    limits: &TransferConfig,
    flag: Arc<AtomicBool>,
) -> Result<(tempfile::TempDir, u64)> {
    let temporary = tempfile::tempdir()?;
    storage::restrict(temporary.path(), true)?;
    let reader = Cancellable {
        reader: File::open(path)?,
        cancelled: flag,
    };
    let mut archive = tar::Archive::new(reader);
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    let mut entries = 0usize;
    let mut stored = 0u64;
    let temp_limit = parse_size(&limits.max_temp_size)?;
    for entry in archive.entries()? {
        let mut entry = entry?;
        entries += 1;
        if entries > limits.max_objects + 1024 {
            return Err(Error::input("archive entry count exceeds limit"));
        }
        let relative = safe_archive_path(&entry.path()?)?;
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            continue;
        }
        if !kind.is_file() {
            return Err(Error::input(
                "links, sparse files and special entries are forbidden in OCI archives",
            ));
        }
        let size = entry.size();
        total = total
            .checked_add(size)
            .ok_or_else(|| Error::input("archive size overflow"))?;
        if total > parse_size(&limits.max_archive_size)? {
            return Err(Error::input("archive expanded size exceeds limit"));
        }
        let text = relative.to_string_lossy();
        let relevant = text == "oci-layout" || text == "index.json" || text.starts_with("blobs/");
        if !relevant {
            continue;
        }
        stored = stored
            .checked_add(size)
            .ok_or_else(|| Error::input("temporary storage size overflow"))?;
        if stored > temp_limit {
            return Err(Error::input("archive extraction exceeds max_temp_size"));
        }
        if !names.insert(relative.clone()) {
            return Err(Error::input("duplicate critical archive entry"));
        }
        if text == "oci-layout" && size > 4096 {
            return Err(Error::input("oci-layout metadata too large"));
        }
        if text == "index.json" && size > parse_size(&limits.max_manifest_size)? {
            return Err(Error::input("index.json too large"));
        }
        if text.starts_with("blobs/") {
            let parts: Vec<_> = text.split('/').collect();
            if parts.len() != 3 {
                return Err(Error::input("invalid OCI archive blob path"));
            }
            let _: crate::digest::Digest = format!("{}:{}", parts[1], parts[2]).parse()?;
        }
        let dest = temporary.path().join(&relative);
        fs::create_dir_all(storage::parent(&dest))?;
        let mut file = OpenOptions::new().write(true).create_new(true).open(dest)?;
        let written = io::copy(&mut entry, &mut file)?;
        if written != size {
            return Err(Error::integrity("truncated archive entry"));
        }
    }
    Ok((temporary, stored))
}

fn check_output(path: &Path, overwrite: bool) -> Result<()> {
    if path.file_name().is_none() {
        return Err(Error::input("output must name a file or layout directory"));
    }
    storage::reject_symlink(path)?;
    if path.exists() && !overwrite {
        return Err(Error::conflict(format!(
            "output {} already exists",
            path.display()
        )));
    }
    Ok(())
}
fn commit_directory(temporary: &tempfile::TempDir, output: &Path, overwrite: bool) -> Result<()> {
    check_output(output, overwrite)?;
    if !output.exists() {
        fs::rename(temporary.path(), output)?;
        return Ok(());
    }
    if !output.is_dir() || !output.join("oci-layout").is_file() {
        return Err(Error::conflict(
            "directory overwrite is restricted to existing OCI layouts",
        ));
    }
    let backup = tempfile::tempdir_in(storage::parent(output))?;
    let old = backup.path().join("old");
    fs::rename(output, &old)?;
    if let Err(e) = fs::rename(temporary.path(), output) {
        let _ = fs::rename(&old, output);
        return Err(e.into());
    }
    Ok(())
}
/// GNU tar file header, padded data, and optional GNU long-name entry.
fn archive_entry_bytes(path: &Path, size: u64) -> Result<u64> {
    let name_len = path.as_os_str().len() as u64;
    let data = size.checked_add(511).map(|n| n / 512 * 512);
    let extra = if name_len > 100 {
        512 + (name_len + 1).div_ceil(512) * 512
    } else {
        0
    };
    data.and_then(|n| n.checked_add(512 + extra))
        .ok_or_else(|| Error::input("archive size overflow"))
}
fn export_temporary_bytes(files: &[(PathBuf, u64)], archive: bool) -> Result<u64> {
    let mut total = if archive { 1024u64 } else { 0 };
    for (path, size) in files {
        total = total
            .checked_add(*size)
            .ok_or_else(|| Error::input("temporary storage size overflow"))?;
        if archive {
            total = total
                .checked_add(archive_entry_bytes(path, *size)?)
                .ok_or_else(|| Error::input("temporary storage size overflow"))?;
        }
    }
    Ok(total)
}
fn make_archive(
    root: &Path,
    parent: &Path,
    flag: Arc<AtomicBool>,
) -> Result<tempfile::NamedTempFile> {
    let mut output = tempfile::NamedTempFile::new_in(parent)?;
    {
        let mut builder = tar::Builder::new(output.as_file_mut());
        let mut paths = vec![PathBuf::from("oci-layout"), PathBuf::from("index.json")];
        for algorithm in ["sha256", "sha512"] {
            let dir = root.join("blobs").join(algorithm);
            if dir.exists() {
                for file in fs::read_dir(dir)? {
                    let file = file?;
                    if !file.file_type()?.is_file() {
                        return Err(Error::input("unexpected non-file in export layout"));
                    }
                    paths.push(Path::new("blobs").join(algorithm).join(file.file_name()));
                }
            }
        }
        paths.sort();
        for path in paths {
            let file = File::open(root.join(&path))?;
            let mut header = tar::Header::new_gnu();
            header.set_size(file.metadata()?.len());
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            builder.append_data(
                &mut header,
                &path,
                Cancellable {
                    reader: file,
                    cancelled: flag.clone(),
                },
            )?;
        }
        builder.finish()?;
    }
    output.flush()?;
    output.as_file().sync_all()?;
    Ok(output)
}

/// Export a verified remote dependency graph without extracting any image root filesystem.
#[allow(clippy::too_many_arguments)]
pub async fn pull(
    source: &Registry,
    reference: &Reference,
    output: &Path,
    format: ArchiveFormat,
    platform: Option<&str>,
    write: &WriteOptions,
) -> Result<PullResult> {
    check_output(output, write.overwrite)?;
    let resolved = transfer::resolve(source, reference, platform).await?;
    let graph = transfer::remote_graph(source, reference, resolved.manifest).await?;
    let blob_bytes = graph.blobs.values().try_fold(0u64, |n, d| {
        n.checked_add(d.size)
            .ok_or_else(|| Error::input("image size overflow"))
    })?;
    let metadata_bytes = graph
        .manifests
        .values()
        .map(|m| m.raw.len() as u64)
        .sum::<u64>();
    if blob_bytes.saturating_add(metadata_bytes)
        > parse_size(&source.config().transfer.max_archive_size)?
    {
        return Err(Error::input("export exceeds configured archive size limit"));
    }
    let mut root_descriptor = graph.root.descriptor.clone();
    root_descriptor.annotations.insert(
        "org.opencontainers.image.ref.name".into(),
        reference.selector.clone(),
    );
    let index_bytes = serde_json::to_vec_pretty(
        &json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":[root_descriptor]}),
    )?;
    let layout_bytes = b"{\"imageLayoutVersion\":\"1.0.0\"}\n";
    let mut staged = vec![
        (PathBuf::from("index.json"), index_bytes.len() as u64),
        (PathBuf::from("oci-layout"), layout_bytes.len() as u64),
    ];
    staged.extend(
        graph
            .manifests
            .values()
            .map(|m| (blob_path(Path::new(""), m.digest()), m.raw.len() as u64)),
    );
    staged.extend(
        graph
            .blobs
            .values()
            .map(|d| (blob_path(Path::new(""), &d.digest), d.size)),
    );
    let required = export_temporary_bytes(&staged, matches!(format, ArchiveFormat::OciArchive))?;
    if required > parse_size(&source.config().transfer.max_temp_size)? {
        return Err(Error::input(
            "export staging and archive exceed max_temp_size",
        ));
    }
    if !write.dry_run {
        fs::create_dir_all(storage::parent(output))?;
        let temp = tempfile::tempdir_in(storage::parent(output))?;
        storage::restrict(temp.path(), true)?;
        for algorithm in ["sha256", "sha512"] {
            fs::create_dir_all(temp.path().join("blobs").join(algorithm))?;
        }
        for m in graph.manifests.values() {
            tokio::fs::write(blob_path(temp.path(), m.digest()), &m.raw).await?;
        }
        stream::iter(graph.blobs.values().cloned())
            .map(|d| {
                let path = blob_path(temp.path(), &d.digest);
                let source = source.clone();
                let repo = reference.repository.clone();
                async move { source.download_blob(&repo, &d, &path).await }
            })
            .buffer_unordered(source.config().transfer.concurrency)
            .try_collect::<Vec<_>>()
            .await?;
        tokio::fs::write(temp.path().join("oci-layout"), layout_bytes).await?;
        tokio::fs::write(temp.path().join("index.json"), &index_bytes).await?;
        match format {
            ArchiveFormat::OciLayout => commit_directory(&temp, output, write.overwrite)?,
            ArchiveFormat::OciArchive => {
                let root = temp.path().to_path_buf();
                let parent = storage::parent(output).to_path_buf();
                let archive = blocking(move |flag| make_archive(&root, &parent, flag)).await?;
                check_output(output, write.overwrite)?;
                if write.overwrite {
                    archive.persist(output).map_err(|e| Error::from(e.error))?;
                } else {
                    archive
                        .persist_noclobber(output)
                        .map_err(|e| Error::from(e.error))?;
                }
            }
        }
    }
    Ok(PullResult {
        source: reference.to_string(),
        source_digest: resolved.source_digest,
        target_digest: graph.root.digest().clone(),
        output: output.to_owned(),
        format,
        blob_bytes,
        blobs: graph.blobs.len(),
        manifests: graph.manifests.len(),
        dry_run: write.dry_run,
        referrers: transfer::Referrers::NotCopied,
    })
}

/// Publish a selected local dependency graph, enforcing write policy and verifying remote content.
pub async fn push(
    path: &Path,
    root_ref: Option<&str>,
    target: &Registry,
    destination: &Reference,
    write: &WriteOptions,
) -> Result<PushResult> {
    let layout = LocalLayout::open(path, &target.config().transfer).await?;
    let root = layout.selected_root(root_ref, &target.config().transfer)?;
    let graph = layout.graph(root, &target.config().transfer).await?;
    // Validate the entire selected closure before the first remote write.
    layout
        .verify_blobs(&graph, &target.config().transfer)
        .await?;
    check_output_reference(target, destination, &graph, write).await?;
    let available = parse_size(&target.config().transfer.max_temp_size)?
        .checked_sub(layout.temporary_bytes)
        .ok_or_else(|| Error::input("archive extraction exceeds max_temp_size"))?;
    for d in graph
        .blobs
        .values()
        .filter(|d| d.data.is_some() && d.size > available)
    {
        if !target.blob_exists(&destination.repository, d).await? {
            return Err(Error::input(
                "embedded blob and extracted archive exceed max_temp_size",
            ));
        }
    }
    let budget = crate::temporary::Budget::new(available);
    let outcomes = stream::iter(graph.blobs.values().cloned())
        .map(|d| {
            let budget = budget.clone();
            let root = layout.root.clone();
            let target = target.clone();
            let repo = destination.repository.clone();
            async move {
                if target.blob_exists(&repo, &d).await? {
                    return Ok::<_, Error>(TransferStats {
                        skipped_blobs: 1,
                        ..Default::default()
                    });
                }
                if write.dry_run {
                    return Ok(TransferStats {
                        planned_blobs: 1,
                        ..Default::default()
                    });
                }
                if let Some(raw) = d.embedded()? {
                    let _reservation = budget.reserve(d.size).await?;
                    let temp = tempfile::NamedTempFile::new()?;
                    tokio::fs::write(temp.path(), &raw).await?;
                    transfer::upload_file(&target, &repo, &d, temp.path(), None).await?;
                } else {
                    let path = checked_file(
                        &root,
                        Path::new("blobs")
                            .join(d.digest.algorithm())
                            .join(d.digest.encoded())
                            .as_path(),
                    )?;
                    transfer::upload_file(&target, &repo, &d, &path, None).await?;
                }
                Ok(TransferStats {
                    copied_blobs: 1,
                    bytes_transferred: d.size,
                    ..Default::default()
                })
            }
        })
        .buffer_unordered(target.config().transfer.concurrency)
        .try_collect::<Vec<_>>()
        .await?;
    let mut stats = TransferStats::default();
    for outcome in outcomes {
        stats.merge(&outcome);
    }
    if !write.dry_run {
        transfer::publish_dependencies(target, destination, &graph).await?;
        transfer::publish_root(target, destination, &graph.root, write.overwrite).await?;
    }
    Ok(PushResult {
        source: path.to_owned(),
        destination: destination.to_string(),
        target_digest: graph.root.digest().clone(),
        stats,
        dry_run: write.dry_run,
        referrers: transfer::Referrers::NotCopied,
    })
}
async fn check_output_reference(
    target: &Registry,
    destination: &Reference,
    graph: &Graph,
    write: &WriteOptions,
) -> Result<()> {
    transfer::check_destination(target, destination, &graph.root, write.overwrite).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tar_quota_includes_padding_and_sha512_long_names() {
        let root = tempfile::tempdir().unwrap();
        let name = PathBuf::from(format!("blobs/sha512/{}", "a".repeat(128)));
        fs::create_dir_all(root.path().join("blobs/sha512")).unwrap();
        let files = vec![
            (PathBuf::from("oci-layout"), 30),
            (PathBuf::from("index.json"), 100),
            (name, 513),
        ];
        for (path, size) in &files {
            fs::write(root.path().join(path), vec![0; *size as usize]).unwrap();
        }
        let output =
            make_archive(root.path(), root.path(), Arc::new(AtomicBool::new(false))).unwrap();
        let staged: u64 = files.iter().map(|(_, size)| *size).sum();
        assert_eq!(
            export_temporary_bytes(&files, true).unwrap(),
            staged + output.as_file().metadata().unwrap().len()
        );
        assert!(archive_entry_bytes(Path::new("blob"), u64::MAX).is_err());
    }
    #[test]
    fn archive_path_validation() {
        for path in [
            "../secret",
            "/etc/passwd",
            "a/../../x",
            "C:\\secret",
            "a\\..\\b",
        ] {
            assert!(safe_archive_path(Path::new(path)).is_err(), "{path}");
        }
        assert_eq!(
            safe_archive_path(Path::new("./blobs/sha256/abc")).unwrap(),
            Path::new("blobs/sha256/abc")
        );
    }
    #[test]
    fn rejects_archive_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("evil.tar");
        let mut tar = tar::Builder::new(File::create(&path).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("/etc/passwd").unwrap();
        header.set_cksum();
        tar.append_data(&mut header, "oci-layout", io::empty())
            .unwrap();
        tar.finish().unwrap();
        drop(tar);
        assert!(
            extract_archive(
                &path,
                &TransferConfig::default(),
                Arc::new(AtomicBool::new(false))
            )
            .is_err()
        );
    }
    #[tokio::test]
    async fn bad_local_blob_fails() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(temp.path(), b"wrong").unwrap();
        let d = Descriptor::new(
            "application/octet-stream",
            crate::digest::Digest::sha256(b"right"),
            5,
        );
        assert!(verify_local_blob(temp.path(), &d).await.is_err());
    }
}
