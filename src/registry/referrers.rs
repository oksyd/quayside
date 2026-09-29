use super::Registry;
use crate::{
    Error, Result,
    digest::Digest,
    error::Code,
    model::{Descriptor, Manifest, OCI_INDEX},
    reference::Reference,
};
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, StatusCode};
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};
use tokio::sync::Mutex;

pub(super) type UpdateLocks = Mutex<BTreeMap<(String, String), Weak<Mutex<()>>>>;

impl Registry {
    /// List independent referrers with pagination and the OCI fallback tag convention.
    pub async fn list_referrers(&self, reference: &Reference) -> Result<Vec<Descriptor>> {
        self.validate_reference(reference)?;
        let digest = reference
            .digest()
            .ok_or_else(|| Error::input("referrer discovery requires a pinned digest"))?;
        let base = self.url(&format!("v2/{}/referrers/{digest}", reference.repository))?;
        let mut next = base.clone();
        let mut seen = std::collections::BTreeSet::new();
        let mut entries: BTreeMap<Digest, Descriptor> = BTreeMap::new();
        let mut bytes = 0u64;
        for page in 0..1000 {
            if !seen.insert(next.to_string()) {
                return Err(Error::input("referrers pagination loop"));
            }
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, HeaderValue::from_static(OCI_INDEX));
            let (response, _) = self
                .request(
                    Method::GET,
                    next.clone(),
                    &Self::scope(&reference.repository, "pull"),
                    headers,
                    None,
                    false,
                    true,
                )
                .await?;
            if page == 0
                && matches!(
                    response.status(),
                    StatusCode::NOT_FOUND
                        | StatusCode::METHOD_NOT_ALLOWED
                        | StatusCode::NOT_IMPLEMENTED
                )
            {
                let fallback = Reference {
                    selector: format!("{}-{}", digest.algorithm(), &digest.encoded()[..64]),
                    ..reference.clone()
                };
                return match self.manifest_optional(&fallback).await? {
                    None => Ok(vec![]),
                    Some(index) => Ok(referrer_entries(
                        &index,
                        self.config().transfer.max_objects,
                    )?
                    .into_values()
                    .collect()),
                };
            }
            if response.status() != StatusCode::OK {
                return Err(super::transport::http_error(&response));
            }
            let link = response
                .headers()
                .get_all(header::LINK)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .find_map(super::catalog::next_link);
            let raw = super::limited_body(
                response,
                crate::config::parse_size(&self.config().transfer.max_manifest_size)?,
            )
            .await?;
            bytes += raw.len() as u64;
            if bytes > crate::config::parse_size(&self.config().transfer.max_metadata_size)? {
                return Err(Error::input("referrer listings exceed metadata limit"));
            }
            let index = Manifest::parse(raw, Some(OCI_INDEX), None)?;
            for (digest, descriptor) in
                referrer_entries(&index, self.config().transfer.max_objects)?
            {
                if let Some(old) = entries.get(&digest)
                    && (old.size != descriptor.size || old.media_type != descriptor.media_type)
                {
                    return Err(Error::integrity(
                        "conflicting referrer descriptor across pages",
                    ));
                }
                entries.entry(digest).or_insert(descriptor);
            }
            if entries.len() > self.config().transfer.max_objects {
                return Err(Error::input("referrers exceed object limit"));
            }
            let Some(link) = link else {
                return Ok(entries.into_values().collect());
            };
            next = next.join(&link)?;
            super::transport::valid_url(&next)?;
            if !super::transport::same_origin(&next, &base) || next.path() != base.path() {
                return Err(Error::input("unsafe referrers pagination URL"));
            }
        }
        Err(Error::input("referrers pagination limit exceeded"))
    }

    // OCI fallback tags are shared by every artifact referring to the same subject.
    // Serialize local updates and use conditional writes when the registry supplies an ETag.
    pub(super) async fn register_referrer(
        &self,
        reference: &Reference,
        manifest: &Manifest,
        subject: &Digest,
    ) -> Result<()> {
        let reference = Reference {
            selector: format!("{}-{}", subject.algorithm(), &subject.encoded()[..64]),
            explicit: true,
            ..reference.clone()
        };
        let lock = {
            let mut updates = self.inner.referrer_updates.lock().await;
            updates.retain(|_, lock| lock.strong_count() > 0);
            let entry = updates
                .entry((reference.repository.clone(), reference.selector.clone()))
                .or_default();
            match entry.upgrade() {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(Mutex::new(()));
                    *entry = Arc::downgrade(&lock);
                    lock
                }
            }
        };
        let _guard = lock.lock().await;
        let descriptor = manifest.referrer_descriptor()?;
        let mut required = BTreeMap::from([(descriptor.digest.clone(), descriptor)]);
        for _ in 0..4 {
            let existing = match self.manifest_with_etag(&reference).await {
                Ok(value) => Some(value),
                Err(error) if error.code == Code::NotFound => None,
                Err(error) => return Err(error),
            };
            let mut headers = HeaderMap::new();
            let mut value = match existing {
                Some((index, etag)) => {
                    let entries = referrer_entries(&index, self.config().transfer.max_objects)?;
                    for entry in entries.values() {
                        if let Some(expected) = required.get(&entry.digest)
                            && (entry.size != expected.size
                                || entry.media_type != expected.media_type)
                        {
                            return Err(Error::integrity("conflicting referrer descriptor"));
                        }
                    }
                    if required.keys().all(|digest| entries.contains_key(digest)) {
                        return Ok(());
                    }
                    for (digest, entry) in entries {
                        required.entry(digest).or_insert(entry);
                    }
                    if let Some(etag) = etag.filter(|value| value.as_bytes().starts_with(b"\"")) {
                        headers.insert(header::IF_MATCH, etag);
                    }
                    index.value
                }
                None => {
                    headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
                    json!({"schemaVersion": 2, "mediaType": OCI_INDEX})
                }
            };
            if required.len() > self.config().transfer.max_objects {
                return Err(Error::input(
                    "referrers index exceeds configured object limit",
                ));
            }
            value["manifests"] = serde_json::to_value(required.values().collect::<Vec<_>>())?;
            let index = Manifest::parse(serde_json::to_vec(&value)?.into(), Some(OCI_INDEX), None)?;
            match self.put_manifest_raw(&reference, &index, headers).await {
                Ok(_) => {}
                Err(error) if error.code == Code::Conflict => continue,
                Err(error) => return Err(error),
            }
            let stored = self.get_manifest(&reference).await?;
            let entries = referrer_entries(&stored, self.config().transfer.max_objects)?;
            if required.values().all(|expected| {
                entries.get(&expected.digest).is_some_and(|entry| {
                    entry.size == expected.size && entry.media_type == expected.media_type
                })
            }) {
                return Ok(());
            }
            // Preserve every observed entry when retrying a registry without conditional writes.
        }
        Err(Error::conflict(
            "referrers index changed during registration; retry the transfer",
        ))
    }
}

fn referrer_entries(index: &Manifest, max_objects: usize) -> Result<BTreeMap<Digest, Descriptor>> {
    if index.descriptor.media_type != OCI_INDEX || index.subject()?.is_some() {
        return Err(Error::conflict(
            "referrers tag does not contain a valid OCI referrers index",
        ));
    }
    let entries = index.children()?;
    if entries.len() > max_objects {
        return Err(Error::input(
            "referrers index exceeds configured object limit",
        ));
    }
    let mut unique: BTreeMap<Digest, Descriptor> = BTreeMap::new();
    for entry in entries {
        if let Some(previous) = unique.get(&entry.digest)
            && (previous.size != entry.size || previous.media_type != entry.media_type)
        {
            return Err(Error::integrity("conflicting referrer descriptor"));
        }
        unique.entry(entry.digest.clone()).or_insert(entry);
    }
    Ok(unique)
}
