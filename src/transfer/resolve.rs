use crate::{
    Error, Result,
    config::parse_size,
    digest::Digest,
    model::{Descriptor, Manifest, ManifestKind, Platform},
    reference::Reference,
    registry::Registry,
};
use futures_util::{StreamExt, stream};
use std::collections::{BTreeMap, BTreeSet};

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
    let wanted = platform.map(str::parse::<Platform>).transpose()?;
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
    let Some(wanted) = wanted else {
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
    let limits = &source.config().transfer;
    let max_manifest = parse_size(&limits.max_manifest_size)?;
    let max_metadata = parse_size(&limits.max_metadata_size)?;
    let mut metadata = root.raw.len() as u64;
    let mut admitted = BTreeMap::from([(root.digest().clone(), root.descriptor.clone())]);
    let mut queue = vec![(root, 0usize)];
    let mut available = BTreeSet::new();
    let mut candidates = BTreeMap::new();
    while let Some((index, depth)) = queue.pop() {
        if metadata > max_metadata || admitted.len() > limits.max_objects {
            return Err(Error::input(
                "platform selection exceeded configured graph limits",
            ));
        }
        let mut batch = Vec::new();
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
            if depth + 1 > limits.max_depth {
                return Err(Error::input("platform selection depth limit exceeded"));
            }
            if d.size > max_manifest {
                return Err(Error::input("child manifest exceeds size limit"));
            }
            if let Some(previous) = admitted.get(&d.digest) {
                if previous.size != d.size || previous.media_type != d.media_type {
                    return Err(Error::integrity(
                        "conflicting descriptors during platform selection",
                    ));
                }
                continue;
            }
            // Reserve declared metadata before starting sibling requests; each digest counts once.
            metadata = metadata
                .checked_add(d.size)
                .ok_or_else(|| Error::input("selection metadata overflow"))?;
            if metadata > max_metadata {
                return Err(Error::input("platform selection metadata limit exceeded"));
            }
            if admitted.len() >= limits.max_objects {
                return Err(Error::input("platform selection object limit exceeded"));
            }
            admitted.insert(d.digest.clone(), d.clone());
            batch.push(d);
        }
        let mut fetched = stream::iter(batch)
            .map(|descriptor| selected_child(source, reference, descriptor))
            .buffered(limits.concurrency);
        while let Some(child) = fetched.next().await {
            let (mut child, platform) = child?;
            if child.kind == ManifestKind::Index {
                queue.push((child, depth + 1));
            } else if let Some(p) = platform {
                available.insert(p.to_string());
                if p.matches(&wanted) {
                    child.descriptor.platform = Some(p.clone());
                    candidates.insert(child.digest().clone(), (child, p));
                }
            }
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

async fn selected_child(
    source: &Registry,
    reference: &Reference,
    descriptor: Descriptor,
) -> Result<(Manifest, Option<Platform>)> {
    let child = if let Some(raw) = descriptor.embedded()? {
        Manifest::parse(raw, Some(&descriptor.media_type), Some(&descriptor.digest))?
    } else {
        source
            .get_manifest(&reference.pinned(&descriptor.digest))
            .await?
    };
    child.verify_descriptor(&descriptor)?;
    let platform = if child.kind == ManifestKind::Index || child.is_artifact()? {
        None
    } else {
        Some(match descriptor.platform {
            Some(platform) => platform,
            None => image_platform(source, &reference.repository, &child).await?,
        })
    };
    Ok((child, platform))
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
