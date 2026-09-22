use crate::{
    Error, Result,
    config::{TransferConfig, parse_size},
    digest::Digest,
    model::{Descriptor, Manifest, ManifestKind},
};
use futures_util::{StreamExt, TryStreamExt, stream};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
};

/// Complete forward dependency graph. `order` is children-first, suitable for PUTs.
#[derive(Clone, Debug)]
pub struct Graph {
    /// The selected root manifest whose dependency closure is represented.
    pub root: Manifest,
    /// Unique manifests indexed by their verified content digest.
    pub manifests: BTreeMap<Digest, Manifest>,
    /// Unique non-manifest payload descriptors indexed by digest.
    pub blobs: BTreeMap<Digest, Descriptor>,
    /// Manifest publication order with dependencies before their parents.
    pub order: Vec<Digest>,
}
enum Task {
    Visit(Manifest, usize),
    Fetch(Descriptor, usize),
    Finish(Digest),
}
impl Graph {
    /// Fetch siblings concurrently within transfer limits and verify a dependency closure.
    /// Reject cycles and conflicting descriptors while preserving children-first publication order.
    pub async fn build<F, Fut>(
        root: Manifest,
        limits: &TransferConfig,
        mut fetch: F,
    ) -> Result<Self>
    where
        F: FnMut(Descriptor) -> Fut,
        Fut: Future<Output = Result<Manifest>>,
    {
        let mut graph = Self {
            root: root.clone(),
            manifests: BTreeMap::new(),
            blobs: BTreeMap::new(),
            order: vec![],
        };
        let mut stack = vec![Task::Visit(root, 0)];
        let mut visiting = BTreeSet::new();
        let mut done = BTreeSet::new();
        let mut subtree_depths = BTreeMap::<Digest, usize>::new();
        let mut metadata_size = graph.root.raw.len() as u64;
        let mut prefetched = BTreeMap::<Digest, Manifest>::new();
        let concurrency = limits.concurrency.clamp(1, 32);
        let max_metadata = parse_size(&limits.max_metadata_size)?;
        let max_manifest = parse_size(&limits.max_manifest_size)?;
        while let Some(task) = stack.pop() {
            match task {
                Task::Fetch(d, depth) => {
                    if let Some(m) = graph.manifests.get(&d.digest) {
                        m.verify_descriptor(&d)?;
                        if visiting.contains(&d.digest) {
                            return Err(Error::integrity("cyclic manifest graph"));
                        }
                        if done.contains(&d.digest) {
                            // A shared subtree can be reached through a deeper path later.
                            if depth.saturating_add(subtree_depths[&d.digest]) > limits.max_depth {
                                return Err(Error::input("manifest graph depth limit exceeded"));
                            }
                            continue;
                        }
                    }
                    if depth > limits.max_depth {
                        return Err(Error::input("manifest graph depth limit exceeded"));
                    }
                    if !prefetched.contains_key(&d.digest) {
                        // Prefetch a bounded group of siblings while retaining deterministic DFS order.
                        let mut batch = vec![d.clone()];
                        let mut scheduled = BTreeSet::from([d.digest.clone()]);
                        for task in stack.iter().rev() {
                            let Task::Fetch(sibling, _) = task else { break };
                            if batch.len() == concurrency {
                                break;
                            }
                            if !graph.manifests.contains_key(&sibling.digest)
                                && !prefetched.contains_key(&sibling.digest)
                                && scheduled.insert(sibling.digest.clone())
                            {
                                batch.push(sibling.clone());
                            }
                        }
                        if graph.manifests.len()
                            + graph.blobs.len()
                            + prefetched.len()
                            + batch.len()
                            > limits.max_objects
                        {
                            return Err(Error::input("manifest graph object limit exceeded"));
                        }
                        // Reserve declared sizes before starting requests, including buffered siblings.
                        for descriptor in &batch {
                            if descriptor.size > max_manifest {
                                return Err(Error::input("manifest exceeds configured size limit"));
                            }
                            metadata_size = metadata_size
                                .checked_add(descriptor.size)
                                .ok_or_else(|| Error::input("metadata size overflow"))?;
                            if metadata_size > max_metadata {
                                return Err(Error::input("manifest graph metadata limit exceeded"));
                            }
                        }
                        let manifests: Vec<Manifest> = stream::iter(batch)
                            .map(|descriptor| {
                                let pending =
                                    descriptor.data.is_none().then(|| fetch(descriptor.clone()));
                                async move {
                                    let manifest = match pending {
                                        Some(pending) => pending.await?,
                                        None => Manifest::parse(
                                            descriptor.embedded()?.ok_or_else(|| {
                                                Error::integrity("missing embedded manifest")
                                            })?,
                                            Some(&descriptor.media_type),
                                            Some(&descriptor.digest),
                                        )?,
                                    };
                                    manifest.verify_descriptor(&descriptor)?;
                                    Ok::<_, Error>(manifest)
                                }
                            })
                            .buffered(concurrency)
                            .try_collect()
                            .await?;
                        for manifest in manifests {
                            prefetched.insert(manifest.digest().clone(), manifest);
                        }
                    }
                    let m = prefetched
                        .remove(&d.digest)
                        .ok_or_else(|| Error::integrity("missing prefetched manifest"))?;
                    m.verify_descriptor(&d)?;
                    stack.push(Task::Visit(m, depth));
                }
                Task::Visit(m, depth) => {
                    let digest = m.digest().clone();
                    if done.contains(&digest) {
                        continue;
                    }
                    if depth > limits.max_depth {
                        return Err(Error::input("manifest graph depth limit exceeded"));
                    }
                    if !visiting.insert(digest.clone()) {
                        return Err(Error::integrity("cyclic manifest graph"));
                    }
                    if m.raw.len() as u64 > max_manifest || metadata_size > max_metadata {
                        return Err(Error::input("manifest graph metadata limit exceeded"));
                    }
                    m.check_transfer_supported()?;
                    for b in m.blobs()? {
                        // Inline data is part of the graph: reject corrupt bytes before any transfer.
                        b.embedded()?;
                        if let Some(previous) = graph.blobs.get_mut(&b.digest) {
                            if previous.size != b.size {
                                return Err(Error::integrity(
                                    "inconsistent size for a shared blob digest",
                                ));
                            }
                            if previous.data.is_none() {
                                previous.data = b.data;
                            }
                        } else {
                            graph.blobs.insert(b.digest.clone(), b);
                        }
                    }
                    let children = m.children()?;
                    if graph.manifests.len() + graph.blobs.len() + prefetched.len() + 1
                        > limits.max_objects
                        || children.len() > limits.max_objects
                    {
                        return Err(Error::input("manifest graph object limit exceeded"));
                    }
                    graph.manifests.insert(digest.clone(), m);
                    stack.push(Task::Finish(digest));
                    for child in children.into_iter().rev() {
                        stack.push(Task::Fetch(child, depth + 1));
                    }
                    if stack.len() > limits.max_objects.saturating_mul(2) {
                        return Err(Error::input("manifest graph queue limit exceeded"));
                    }
                }
                Task::Finish(digest) => {
                    let depth = graph.manifests[&digest]
                        .children()?
                        .iter()
                        .map(|child| subtree_depths[&child.digest] + 1)
                        .max()
                        .unwrap_or(0);
                    subtree_depths.insert(digest.clone(), depth);
                    visiting.remove(&digest);
                    done.insert(digest.clone());
                    graph.order.push(digest);
                }
            }
        }
        Ok(graph)
    }
    /// Return sorted, deduplicated platform names advertised by manifests in the graph.
    pub fn platforms(&self) -> Result<Vec<String>> {
        let mut result = BTreeSet::new();
        for m in self
            .manifests
            .values()
            .filter(|m| m.kind == ManifestKind::Index)
        {
            for d in m.children()? {
                if let Some(p) = d.platform {
                    result.insert(p.to_string());
                }
            }
        }
        Ok(result.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::OCI_INDEX;
    use bytes::Bytes;
    use serde_json::json;
    fn index(children: &[Descriptor], id: usize) -> Manifest {
        Manifest::parse(
            Bytes::from(
                serde_json::to_vec(&json!({
                    "schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": children,
                    "annotations": {"test.id": id.to_string()}
                }))
                .unwrap(),
            ),
            None,
            None,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn siblings_fetch_concurrently_with_bounded_dedup_and_stable_order() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let leaves: Vec<_> = (0..4).map(|id| index(&[], id)).collect();
        let mut children: Vec<_> = leaves.iter().map(|m| m.descriptor.clone()).collect();
        children.insert(1, children[0].clone());
        let root = index(&children, 5);
        let limits = TransferConfig {
            concurrency: 2,
            ..Default::default()
        };
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let graph = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            Graph::build(root.clone(), &limits, |d| {
                let leaf = leaves
                    .iter()
                    .find(|m| m.digest() == &d.digest)
                    .unwrap()
                    .clone();
                let (active, maximum, calls, barrier) = (
                    active.clone(),
                    maximum.clone(),
                    calls.clone(),
                    barrier.clone(),
                );
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum.fetch_max(current, Ordering::SeqCst);
                    barrier.wait().await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(leaf)
                }
            }),
        )
        .await
        .expect("manifest requests must overlap")
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(maximum.load(Ordering::SeqCst), 2);
        let mut expected: Vec<_> = leaves.iter().map(|m| m.digest().clone()).collect();
        expected.push(root.digest().clone());
        assert_eq!(graph.order, expected);
    }

    #[tokio::test]
    async fn prefetch_reserves_metadata_before_starting_requests() {
        let leaf = index(&[], 0);
        let root = index(std::slice::from_ref(&leaf.descriptor), 1);
        let limits = TransferConfig {
            max_metadata_size: root.raw.len().to_string(),
            ..Default::default()
        };
        let error = Graph::build(root, &limits, |_| async {
            panic!("over-budget manifest must not be fetched")
        })
        .await
        .unwrap_err();
        assert!(error.message.contains("metadata limit"));
    }

    #[tokio::test]
    async fn prefetched_manifest_still_checks_every_descriptor() {
        let leaf = index(&[], 0);
        let mut conflicting = leaf.descriptor.clone();
        conflicting.size += 1;
        let mut corrupt_inline = leaf.descriptor.clone();
        corrupt_inline.data = Some("YmFk".into());
        for duplicate in [conflicting, corrupt_inline] {
            let root = index(&[leaf.descriptor.clone(), duplicate], 1);
            let error = Graph::build(root, &TransferConfig::default(), |_| {
                let leaf = leaf.clone();
                async move { Ok(leaf) }
            })
            .await
            .unwrap_err();
            assert_eq!(error.code, crate::error::Code::Integrity);
        }
    }

    #[tokio::test]
    async fn nested_order_and_dedup() {
        let leaf = Manifest::parse(
            Bytes::from(
                serde_json::to_vec(
                    &json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":[]}),
                )
                .unwrap(),
            ),
            None,
            None,
        )
        .unwrap();
        let parent = Manifest::parse(Bytes::from(serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":[leaf.descriptor.clone(),leaf.descriptor.clone()]})).unwrap()), None, None).unwrap();
        let graph = Graph::build(parent.clone(), &TransferConfig::default(), |_| {
            let leaf = leaf.clone();
            async move { Ok(leaf) }
        })
        .await
        .unwrap();
        assert_eq!(
            graph.order,
            vec![leaf.digest().clone(), parent.digest().clone()]
        );
    }
    #[tokio::test]
    async fn shared_subtrees_obey_depth_limit_on_every_path() {
        let leaf = index(&[], 0);
        let shared = index(std::slice::from_ref(&leaf.descriptor), 1);
        let branch = index(std::slice::from_ref(&shared.descriptor), 2);
        let root = index(&[shared.descriptor.clone(), branch.descriptor.clone()], 3);
        let manifests: BTreeMap<_, _> = [leaf, shared, branch]
            .into_iter()
            .map(|manifest| (manifest.digest().clone(), manifest))
            .collect();
        for max_depth in [2, 3] {
            let limits = TransferConfig {
                max_depth,
                ..Default::default()
            };
            let mut requests = 0;
            let result = Graph::build(root.clone(), &limits, |d| {
                requests += 1;
                let manifest = manifests[&d.digest].clone();
                async move { Ok(manifest) }
            })
            .await;
            if max_depth == 2 {
                assert!(result.unwrap_err().message.contains("depth limit"));
            } else {
                assert_eq!(result.unwrap().manifests.len(), 4);
            }
            assert_eq!(requests, 3, "shared manifests should still be fetched once");
        }
    }
    #[tokio::test]
    async fn subject_is_not_silently_dropped() {
        let m = Manifest::parse(Bytes::from(serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":[],"subject":{"digest":Digest::sha256(b"x")}})).unwrap()), None, None).unwrap();
        assert!(
            Graph::build(m, &TransferConfig::default(), |_| async {
                Err(Error::input("not called"))
            })
            .await
            .is_err()
        );
    }
}
