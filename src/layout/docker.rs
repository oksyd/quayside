use super::{Cancellable, blob_path, checked_file, read_limited, safe_archive_path};
use crate::{
    Error, Result,
    config::{TransferConfig, parse_size},
    digest::Digest,
    model::{Descriptor, OCI_INDEX, OCI_MANIFEST},
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::Path,
    process::Stdio,
    sync::{Arc, atomic::AtomicBool},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Image {
    config: String,
    #[serde(default)]
    repo_tags: Option<Vec<String>>,
    layers: Vec<String>,
}

pub(super) async fn export(
    image: &Path,
    limits: &TransferConfig,
) -> Result<tempfile::NamedTempFile> {
    if image.as_os_str().is_empty() {
        return Err(Error::input("Docker image name must not be empty"));
    }
    let temporary = tempfile::NamedTempFile::new()?;
    let mut file = tokio::fs::File::from_std(temporary.reopen()?);
    let mut child = tokio::process::Command::new("docker")
        .args(["image", "save", "--"]).arg(image)
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())
        .kill_on_drop(true).spawn()
        .map_err(|_| Error::new(crate::error::Code::Execution, "unable to run Docker; install the Docker CLI or push a docker save archive instead"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::input("Docker export has no output stream"))?;
    let limit = parse_size(&limits.max_archive_size)?.min(parse_size(&limits.max_temp_size)?);
    let timeout = crate::config::duration(&limits.idle_timeout)?;
    let mut count = 0u64;
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let size = tokio::time::timeout(timeout, stdout.read(&mut buffer))
            .await
            .map_err(|_| Error::network("Docker image export timed out"))??;
        if size == 0 {
            break;
        }
        count = count
            .checked_add(size as u64)
            .ok_or_else(|| Error::input("Docker export size overflow"))?;
        if count > limit {
            return Err(Error::input(
                "Docker export exceeds max_archive_size or max_temp_size",
            ));
        }
        file.write_all(&buffer[..size]).await?;
    }
    file.flush().await?;
    let status = tokio::time::timeout(timeout, child.wait())
        .await
        .map_err(|_| Error::network("Docker image export timed out"))??;
    if !status.success() {
        return Err(Error::new(
            crate::error::Code::Execution,
            "Docker image export failed; check that the image exists in the current Docker context and the daemon is accessible",
        ));
    }
    Ok(temporary)
}

pub(super) fn convert(
    root: &Path,
    limits: &TransferConfig,
    reference: Option<&str>,
    stored: &mut u64,
    flag: Arc<AtomicBool>,
) -> Result<()> {
    let raw = read_limited(
        &checked_file(root, Path::new("manifest.json"))?,
        parse_size(&limits.max_manifest_size)?,
    )?;
    let images: Vec<Image> = serde_json::from_slice(&raw)?;
    if images.len() > limits.max_objects {
        return Err(Error::input("Docker archive image count exceeds limit"));
    }
    let mut selected = images.iter().filter(|image| {
        reference.is_none_or(|r| {
            image
                .repo_tags
                .as_ref()
                .is_some_and(|tags| tags.iter().any(|tag| tag == r))
        })
    });
    let image = selected.next().ok_or_else(|| {
        Error::input("Docker archive has no matching image; use --ref with an exact RepoTag")
    })?;
    if selected.next().is_some() {
        return Err(Error::input(
            "Docker archive contains multiple matching images; use --ref with an exact RepoTag",
        ));
    }
    if image.layers.len().saturating_add(2) > limits.max_objects {
        return Err(Error::input("Docker archive object count exceeds limit"));
    }
    let config_path = checked_file(root, &safe_archive_path(Path::new(&image.config))?)?;
    let config = read_limited(&config_path, parse_size(&limits.max_manifest_size)?)?;
    let config_digest = Digest::sha256(&config);
    if let Some(name) = config_path.file_stem().and_then(|s| s.to_str())
        && name.len() == 64
        && name.bytes().all(|b| b.is_ascii_hexdigit())
    {
        format!("sha256:{name}")
            .parse::<Digest>()?
            .verify(&config)?;
    }
    let value: serde_json::Value = serde_json::from_slice(&config)?;
    let diff_ids: Vec<Digest> = serde_json::from_value(value["rootfs"]["diff_ids"].clone())?;
    if value["rootfs"]["type"] != "layers" || diff_ids.len() != image.layers.len() {
        return Err(Error::integrity(
            "Docker config rootfs does not match archive layers",
        ));
    }
    link_blob(root, &config_path, &config_digest)?;
    let mut cached = BTreeMap::<std::path::PathBuf, (Digest, u64)>::new();
    let mut layers = Vec::new();
    for (name, expected) in image.layers.iter().zip(&diff_ids) {
        let path = checked_file(root, &safe_archive_path(Path::new(name))?)?;
        let (digest, size) = if let Some(entry) = cached.get(&path) {
            entry.clone()
        } else {
            let mut file = Cancellable {
                reader: fs::File::open(&path)?,
                cancelled: flag.clone(),
            };
            let mut hasher = Digest::sha256(b"").hasher();
            let mut buffer = vec![0; 1024 * 1024];
            let mut size = 0u64;
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                size += n as u64;
                if size > parse_size(&limits.max_archive_size)? {
                    return Err(Error::input("Docker layer exceeds archive size limit"));
                }
                hasher.update(&buffer[..n]);
            }
            let entry = (hasher.finish(), size);
            cached.insert(path.clone(), entry.clone());
            entry
        };
        if &digest != expected {
            return Err(Error::integrity(
                "Docker layer does not match config rootfs diff_id",
            ));
        }
        link_blob(root, &path, &digest)?;
        layers.push(Descriptor::new(
            "application/vnd.oci.image.layer.v1.tar",
            digest,
            size,
        ));
    }
    let config = Descriptor::new(
        "application/vnd.oci.image.config.v1+json",
        config_digest,
        config.len() as u64,
    );
    let manifest = serde_json::to_vec(
        &json!({"schemaVersion":2,"mediaType":OCI_MANIFEST,"config":config,"layers":layers}),
    )?;
    if manifest.len() as u64 > parse_size(&limits.max_manifest_size)? {
        return Err(Error::input("converted manifest exceeds size limit"));
    }
    let mut descriptor = Descriptor::new(
        OCI_MANIFEST,
        Digest::sha256(&manifest),
        manifest.len() as u64,
    );
    if let Some(tag) = reference.or_else(|| {
        image
            .repo_tags
            .as_ref()
            .and_then(|tags| tags.first().map(String::as_str))
    }) {
        descriptor
            .annotations
            .insert("org.opencontainers.image.ref.name".into(), tag.into());
    }
    let index = serde_json::to_vec(
        &json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":[descriptor.clone()]}),
    )?;
    for (path, raw) in [
        (blob_path(root, &descriptor.digest), manifest),
        (root.join("index.json"), index),
        (
            root.join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#.to_vec(),
        ),
    ] {
        *stored = stored
            .checked_add(raw.len() as u64)
            .ok_or_else(|| Error::input("temporary size overflow"))?;
        if *stored > parse_size(&limits.max_temp_size)? {
            return Err(Error::input("Docker conversion exceeds max_temp_size"));
        }
        fs::write(path, raw)?;
    }
    Ok(())
}

fn link_blob(root: &Path, source: &Path, digest: &Digest) -> Result<()> {
    let destination = blob_path(root, digest);
    if source == destination {
        return Ok(());
    }
    if destination.exists() {
        digest.verify_file(&destination, fs::metadata(source)?.len())?;
    } else {
        fs::create_dir_all(destination.parent().expect("blob parent"))?;
        fs::hard_link(source, destination)?;
    }
    Ok(())
}

// Inspect only tar headers and bounded metadata; seek over payloads instead of reading every layer twice.
pub(super) fn archive_files(
    path: &Path,
    limits: &TransferConfig,
    flag: Arc<AtomicBool>,
) -> Result<std::collections::BTreeSet<std::path::PathBuf>> {
    let reader = Cancellable {
        reader: std::io::BufReader::new(fs::File::open(path)?),
        cancelled: flag,
    };
    let mut archive = tar::Archive::new(reader);
    let mut manifest = None;
    let mut oversized = false;
    let mut oci = false;
    for (count, entry) in archive.entries_with_seek()?.enumerate() {
        if count >= limits.max_objects.saturating_add(1024) {
            return Err(Error::input("archive entry count exceeds limit"));
        }
        let mut entry = entry?;
        let path = safe_archive_path(&entry.path()?)?;
        if path == Path::new("oci-layout") {
            oci = true;
        }
        if path == Path::new("manifest.json") && entry.header().entry_type().is_file() {
            let limit = parse_size(&limits.max_manifest_size)?;
            if entry.size() > limit {
                oversized = true;
                continue;
            }
            let mut raw = Vec::new();
            entry.by_ref().take(limit + 1).read_to_end(&mut raw)?;
            manifest = Some(raw);
        }
    }
    if oversized && !oci {
        return Err(Error::input("Docker archive manifest exceeds size limit"));
    }
    let Some(raw) = manifest else {
        return Ok(Default::default());
    };
    let images: Vec<Image> = match serde_json::from_slice(&raw) {
        Ok(images) => images,
        Err(_) if oci => return Ok(Default::default()),
        Err(error) => return Err(error.into()),
    };
    let mut files = std::collections::BTreeSet::from([std::path::PathBuf::from("manifest.json")]);
    for image in images {
        for name in std::iter::once(image.config).chain(image.layers) {
            files.insert(safe_archive_path(Path::new(&name))?);
            if files.len() > limits.max_objects {
                return Err(Error::input("Docker archive object count exceeds limit"));
            }
        }
    }
    Ok(files)
}

// Docker's containerd store may export a complete registry index but only local platform payloads.
// Select the saved images by config digest, preserving every selected image manifest verbatim.
pub(super) fn selected_oci_root(
    root: &Path,
    limits: &TransferConfig,
    reference: Option<&str>,
) -> Result<crate::model::Manifest> {
    use crate::model::{Manifest, ManifestKind};
    use std::collections::BTreeSet;
    let limit = parse_size(&limits.max_manifest_size)?;
    let metadata_limit = parse_size(&limits.max_metadata_size)?;
    let mut metadata = 0;
    let images: Vec<Image> = serde_json::from_slice(&read_metadata(
        &checked_file(root, Path::new("manifest.json"))?,
        limit,
        metadata_limit,
        &mut metadata,
    )?)?;
    if images.len() > limits.max_objects {
        return Err(Error::input("Docker archive image count exceeds limit"));
    }
    let selected: Vec<_> = images
        .iter()
        .filter(|image| {
            reference.is_none_or(|tag| {
                image
                    .repo_tags
                    .as_ref()
                    .is_some_and(|tags| tags.iter().any(|t| t == tag))
            })
        })
        .collect();
    if selected.is_empty() {
        return Err(Error::input(
            "Docker archive has no matching image; use --ref with an exact RepoTag",
        ));
    }
    if reference.is_none() && selected.len() > 1 {
        let mut tags: BTreeSet<_> = selected[0].repo_tags.iter().flatten().cloned().collect();
        for image in &selected[1..] {
            tags.retain(|tag| image.repo_tags.as_ref().is_some_and(|t| t.contains(tag)));
        }
        if tags.is_empty() {
            return Err(Error::input(
                "Docker archive contains multiple images; use --ref with an exact RepoTag",
            ));
        }
    }
    let mut wanted = BTreeMap::new();
    let mut configs = BTreeMap::<std::path::PathBuf, Digest>::new();
    for image in selected {
        let path = checked_file(root, &safe_archive_path(Path::new(&image.config))?)?;
        let digest = if let Some(digest) = configs.get(&path) {
            digest.clone()
        } else {
            let raw = read_metadata(&path, limit, metadata_limit, &mut metadata)?;
            let digest = Digest::sha256(&raw);
            configs.insert(path, digest.clone());
            digest
        };
        if let Some(previous) = wanted.insert(digest, image)
            && previous.layers != image.layers
        {
            return Err(Error::integrity(
                "Docker archive has conflicting layer lists for one config",
            ));
        }
    }
    let index = Manifest::parse(
        read_metadata(
            &checked_file(root, Path::new("index.json"))?,
            limit,
            metadata_limit,
            &mut metadata,
        )?
        .into(),
        Some(OCI_INDEX),
        None,
    )?;
    enum Task {
        Visit(Box<Descriptor>, usize),
        Finish(Digest, Vec<Digest>),
    }
    let mut pending: Vec<_> = index
        .children()?
        .into_iter()
        .map(|d| Task::Visit(Box::new(d), 1))
        .collect();
    let mut seen = BTreeMap::new();
    let mut subtree_depths = BTreeMap::<Digest, usize>::new();
    let mut found = BTreeMap::new();
    while let Some(task) = pending.pop() {
        let (descriptor, depth) = match task {
            Task::Visit(descriptor, depth) => (*descriptor, depth),
            Task::Finish(digest, children) => {
                let depth = children
                    .iter()
                    .map(|child| subtree_depths[child] + 1)
                    .max()
                    .unwrap_or(0);
                subtree_depths.insert(digest, depth);
                continue;
            }
        };
        if depth > limits.max_depth || pending.len() >= limits.max_objects.saturating_mul(2) {
            return Err(Error::input("Docker archive manifest graph exceeds limits"));
        }
        if let Some(previous) = seen.get(&descriptor.digest) {
            if previous != &(descriptor.size, descriptor.media_type.clone()) {
                return Err(Error::integrity(
                    "conflicting Docker archive manifest descriptors",
                ));
            }
            let height = subtree_depths
                .get(&descriptor.digest)
                .ok_or_else(|| Error::integrity("cyclic Docker archive manifest graph"))?;
            if depth.saturating_add(*height) > limits.max_depth {
                return Err(Error::input("Docker archive manifest graph exceeds limits"));
            }
            continue;
        }
        if seen.len() >= limits.max_objects {
            return Err(Error::input("Docker archive manifest graph exceeds limits"));
        }
        seen.insert(
            descriptor.digest.clone(),
            (descriptor.size, descriptor.media_type.clone()),
        );
        // Only absent index branches may be skipped; present objects must verify normally.
        if descriptor.data.is_none() && !blob_path(root, &descriptor.digest).try_exists()? {
            subtree_depths.insert(descriptor.digest, 0);
            continue;
        }
        metadata = metadata
            .checked_add(descriptor.size)
            .ok_or_else(|| Error::input("metadata size overflow"))?;
        if metadata > metadata_limit {
            return Err(Error::input("Docker archive metadata exceeds limit"));
        }
        let mut manifest = super::read_manifest(root, &descriptor, limits)?;
        manifest.descriptor.platform = descriptor.platform;
        if manifest.kind == ManifestKind::Index {
            let children = manifest.children()?;
            pending.push(Task::Finish(
                descriptor.digest,
                children.iter().map(|child| child.digest.clone()).collect(),
            ));
            pending.extend(
                children
                    .into_iter()
                    .map(|d| Task::Visit(Box::new(d), depth + 1)),
            );
            continue;
        }
        subtree_depths.insert(descriptor.digest, 0);
        if let Some(image) = wanted.get(&manifest.config()?.digest) {
            let blobs = manifest.blobs()?;
            if blobs.len() != image.layers.len() + 1 {
                return Err(Error::integrity(
                    "Docker archive layer list differs from OCI manifest",
                ));
            }
            for (name, d) in image.layers.iter().zip(&blobs[1..]) {
                let path = safe_archive_path(Path::new(name))?;
                if root.join(path) != blob_path(root, &d.digest) {
                    return Err(Error::integrity(
                        "Docker archive layer path differs from OCI manifest",
                    ));
                }
            }
            let key = manifest.config()?.digest;
            if let Some(previous) = found.insert(key, manifest.clone())
                && previous.raw != manifest.raw
            {
                return Err(Error::input(
                    "Docker archive has ambiguous manifests for one config",
                ));
            }
        }
    }
    if found.len() != wanted.len() {
        return Err(Error::integrity(
            "Docker archive is missing a selected image manifest",
        ));
    }
    if found.len() == 1 {
        return Ok(found.into_values().next().expect("one selected image"));
    }
    let descriptors: Vec<_> = found.into_values().map(|m| m.descriptor).collect();
    let raw = serde_json::to_vec(
        &json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":descriptors}),
    )?;
    if raw.len() as u64 > limit {
        return Err(Error::input("selected Docker index exceeds size limit"));
    }
    Manifest::parse(raw.into(), Some(OCI_INDEX), None)
}

fn read_metadata(path: &Path, limit: u64, total_limit: u64, used: &mut u64) -> Result<Vec<u8>> {
    let available = total_limit
        .checked_sub(*used)
        .ok_or_else(|| Error::input("Docker archive metadata exceeds limit"))?;
    let raw = read_limited(path, limit.min(available))?;
    *used += raw.len() as u64;
    Ok(raw)
}
