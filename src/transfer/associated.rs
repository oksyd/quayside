use super::{
    Graph, Manifest, Reference, Registry, Resolved, remote_graph, resolve::resolve_selection,
};
use crate::{
    Error, Result,
    digest::Digest,
    model::{Descriptor, OCI_INDEX},
    options::{PlatformSelection, TransferOptions},
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub(crate) async fn selected(
    source: &Registry,
    reference: &Reference,
    selection: &PlatformSelection,
    options: &TransferOptions,
) -> Result<Resolved> {
    if options.include_attestations && matches!(selection, PlatformSelection::All) {
        return Err(Error::input(
            "--all already includes indexed attestations; omit --include-attestations",
        ));
    }
    let mut resolved = resolve_selection(source, reference, selection).await?;
    if !options.include_attestations || &resolved.source_digest == resolved.manifest.digest() {
        return Ok(resolved);
    }
    let original = source
        .get_manifest(&reference.pinned(&resolved.source_digest))
        .await?;
    let full = remote_graph(source, reference, original).await?;
    let mut related = BTreeMap::<Digest, Vec<Descriptor>>::new();
    for manifest in full.manifests.values() {
        for descriptor in manifest.children()? {
            let subject = full.manifests[&descriptor.digest]
                .subject()?
                .map(|d| d.digest)
                .or_else(|| {
                    (descriptor
                        .annotations
                        .get("vnd.docker.reference.type")
                        .map(String::as_str)
                        == Some("attestation-manifest"))
                    .then(|| {
                        descriptor
                            .annotations
                            .get("vnd.docker.reference.digest")
                            .and_then(|d| d.parse::<Digest>().ok())
                    })
                    .flatten()
                });
            if let Some(subject) = subject {
                // Association annotations belong to each edge, not just its content digest.
                related.entry(subject).or_default().push(descriptor);
            }
        }
    }
    let mut keep = BTreeMap::from([(
        resolved.manifest.digest().clone(),
        resolved.manifest.descriptor.clone(),
    )]);
    let mut queue = VecDeque::from([(resolved.manifest.digest().clone(), 0usize)]);
    while let Some((subject, depth)) = queue.pop_front() {
        for descriptor in related.remove(&subject).unwrap_or_default() {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                keep.entry(descriptor.digest.clone())
            {
                if depth >= source.config().transfer.max_depth {
                    return Err(Error::input("attestations exceed depth limit"));
                }
                queue.push_back((descriptor.digest.clone(), depth + 1));
                entry.insert(descriptor);
            }
        }
    }
    if keep.len() > 1 {
        let mut descriptors = vec![resolved.manifest.descriptor.clone()];
        keep.remove(resolved.manifest.digest());
        descriptors.extend(keep.into_values());
        let raw = serde_json::to_vec(
            &serde_json::json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": descriptors}),
        )?;
        if raw.len() as u64
            > crate::config::parse_size(&source.config().transfer.max_manifest_size)?
        {
            return Err(Error::input("selected index exceeds manifest size limit"));
        }
        resolved.manifest = Manifest::parse(raw.into(), Some(OCI_INDEX), None)?;
    }
    Ok(resolved)
}

pub(crate) async fn expand(
    source: &Registry,
    reference: &Reference,
    graph: &mut Graph,
) -> Result<()> {
    let limits = &source.config().transfer;
    let mut queue: VecDeque<_> = graph
        .manifests
        .keys()
        .cloned()
        .map(|d| (d, 0usize))
        .collect();
    let mut scheduled: BTreeSet<_> = graph.manifests.keys().cloned().collect();
    let mut visited = BTreeSet::new();
    while let Some((subject, depth)) = queue.pop_front() {
        if !visited.insert(subject.clone()) {
            continue;
        }
        if visited.len() > limits.max_objects {
            return Err(Error::input("referrer traversal exceeds object limit"));
        }
        for descriptor in source.list_referrers(&reference.pinned(&subject)).await? {
            if descriptor.size > crate::config::parse_size(&limits.max_manifest_size)? {
                return Err(Error::input("referrer manifest exceeds size limit"));
            }
            let manifest = match graph.manifests.get(&descriptor.digest) {
                Some(existing) => existing.clone(),
                None => match descriptor.embedded()? {
                    Some(raw) => Manifest::parse(
                        raw,
                        Some(&descriptor.media_type),
                        Some(&descriptor.digest),
                    )?,
                    None => {
                        source
                            .get_manifest(&reference.pinned(&descriptor.digest))
                            .await?
                    }
                },
            };
            manifest.verify_descriptor(&descriptor)?;
            if manifest.subject()?.is_none_or(|d| d.digest != subject) {
                return Err(Error::integrity(
                    "referrer listing returned an unrelated manifest",
                ));
            }
            if visited.contains(&descriptor.digest) {
                continue;
            }
            if depth >= limits.max_depth {
                return Err(Error::input("referrer traversal exceeds depth limit"));
            }
            let associated = remote_graph(source, reference, manifest).await?;
            for digest in associated.manifests.keys() {
                if scheduled.insert(digest.clone()) {
                    if scheduled.len() > limits.max_objects {
                        return Err(Error::input("referrer traversal exceeds object limit"));
                    }
                    queue.push_back((digest.clone(), depth + 1));
                }
            }
            graph.merge_referrer(associated, limits)?;
        }
    }
    Ok(())
}
