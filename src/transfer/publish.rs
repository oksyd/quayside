use super::{Graph, Manifest, Reference, Registry, check_destination};
use crate::{Error, Result};
use futures_util::{TryStreamExt, stream::FuturesUnordered};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Publish all graph manifests by digest, with independent manifests sent concurrently.
/// Each dependency is confirmed before its parent; no temporary tags or DELETEs are used.
pub async fn publish_dependencies(
    target: &Registry,
    destination: &Reference,
    graph: &Graph,
) -> Result<()> {
    publish_graph(target, destination, graph, true).await
}

pub(crate) async fn publish_children(
    target: &Registry,
    destination: &Reference,
    graph: &Graph,
) -> Result<()> {
    // Publishing the root at the final reference also makes it addressable by digest.
    publish_graph(target, destination, graph, false).await
}

async fn publish_graph(
    target: &Registry,
    destination: &Reference,
    graph: &Graph,
    include_root: bool,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut remaining = BTreeMap::new();
    let mut parents = BTreeMap::<_, Vec<_>>::new();
    let mut ready = VecDeque::new();
    // Validate every dependency before writing and count only distinct child edges.
    for digest in &graph.order {
        let manifest = graph
            .manifests
            .get(digest)
            .ok_or_else(|| Error::integrity("internal graph order is inconsistent"))?;
        let children: BTreeSet<_> = manifest.children()?.into_iter().map(|d| d.digest).collect();
        if children.iter().any(|child| !seen.contains(child)) {
            return Err(Error::integrity(
                "manifest dependency is missing or out of order",
            ));
        }
        if !seen.insert(digest.clone()) {
            return Err(Error::integrity("duplicate manifest in publication order"));
        }
        if include_root || digest != graph.root.digest() {
            remaining.insert(digest.clone(), children.len());
            if children.is_empty() {
                ready.push_back(digest.clone());
            }
            for child in children {
                parents.entry(child).or_default().push(digest.clone());
            }
        }
    }
    if seen.len() != graph.manifests.len() || !seen.contains(graph.root.digest()) {
        return Err(Error::integrity("publication order omits graph manifests"));
    }
    let mut active = FuturesUnordered::new();
    let mut completed = 0usize;
    loop {
        while active.len() < target.config().transfer.concurrency {
            let Some(digest) = ready.pop_front() else {
                break;
            };
            active.push(publish_one(target, destination, &graph.manifests[&digest]));
        }
        let Some(digest) = active.try_next().await? else {
            break;
        };
        completed += 1;
        // Release each parent immediately; unrelated slow branches do not form a batch barrier.
        for parent in parents.remove(&digest).unwrap_or_default() {
            let count = remaining
                .get_mut(&parent)
                .ok_or_else(|| Error::integrity("missing publication dependency counter"))?;
            *count -= 1;
            if *count == 0 {
                ready.push_front(parent);
            }
        }
    }
    if completed != remaining.len() {
        return Err(Error::integrity("manifest publication did not complete"));
    }
    Ok(())
}

async fn publish_one(
    target: &Registry,
    destination: &Reference,
    manifest: &Manifest,
) -> Result<crate::digest::Digest> {
    let pinned = destination.pinned(manifest.digest());
    match target.manifest_optional(&pinned).await? {
        Some(existing) if existing.raw == manifest.raw => {}
        Some(_) => {
            return Err(Error::integrity(
                "registry returned different manifest bytes for a digest",
            ));
        }
        None => target.put_manifest(&pinned, manifest).await?,
    }
    Ok(manifest.digest().clone())
}

/// Publish the root under overwrite policy and verify that its remote bytes are unchanged.
pub async fn publish_root(
    target: &Registry,
    destination: &Reference,
    root: &Manifest,
    overwrite: bool,
) -> Result<()> {
    // Recheck immediately before publishing the tag. This still cannot replace server-side CAS.
    if check_destination(target, destination, root, overwrite).await? {
        return Ok(());
    }
    target.put_manifest(destination, root).await?;
    let verified = target.get_manifest(destination).await?;
    if verified.raw != root.raw {
        return Err(Error::integrity(
            "destination root changed or was rewritten during publication",
        ));
    }
    Ok(())
}
