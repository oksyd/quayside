use crate::{
    Error, Result,
    config::{TransferConfig, parse_size},
    digest::Digest,
    model::{Descriptor, Manifest, ManifestKind},
};
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
    /// Fetch and verify a bounded dependency closure, rejecting cycles and conflicting descriptors.
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
        let mut metadata_size = 0u64;
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
                            continue;
                        }
                    }
                    if d.size > max_manifest {
                        return Err(Error::input("manifest exceeds configured size limit"));
                    }
                    let m = if let Some(raw) = d.embedded()? {
                        Manifest::parse(raw, Some(&d.media_type), Some(&d.digest))?
                    } else {
                        fetch(d.clone()).await?
                    };
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
                    metadata_size = metadata_size
                        .checked_add(m.raw.len() as u64)
                        .ok_or_else(|| Error::input("metadata size overflow"))?;
                    if m.raw.len() as u64 > max_manifest || metadata_size > max_metadata {
                        return Err(Error::input("manifest graph metadata limit exceeded"));
                    }
                    m.check_transfer_supported()?;
                    for b in m.blobs()? {
                        if let Some(previous) = graph.blobs.get(&b.digest) {
                            if previous.size != b.size {
                                return Err(Error::integrity(
                                    "inconsistent size for a shared blob digest",
                                ));
                            }
                        } else {
                            graph.blobs.insert(b.digest.clone(), b);
                        }
                    }
                    let children = m.children()?;
                    if graph.manifests.len() + graph.blobs.len() + 1 > limits.max_objects
                        || children.len() > limits.max_objects
                    {
                        return Err(Error::input("manifest graph object limit exceeded"));
                    }
                    graph.manifests.insert(digest.clone(), m);
                    stack.push(Task::Finish(digest));
                    for child in children.into_iter().rev() {
                        stack.push(Task::Fetch(child, depth + 1));
                    }
                    if stack.len() > limits.max_objects * 2 {
                        return Err(Error::input("manifest graph queue limit exceeded"));
                    }
                }
                Task::Finish(digest) => {
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
