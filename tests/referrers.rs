mod support;

use quayside::{
    digest::Digest,
    model::{Manifest, OCI_INDEX, OCI_MANIFEST},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    sync::{Arc, Mutex},
};
use support::{Harness, Image, Response, Server, attested_layout};

#[derive(Default)]
struct State {
    manifests: BTreeMap<String, Vec<u8>>,
    puts: Vec<String>,
    native: bool,
    no_etag: bool,
    wrong_subject: bool,
    fallback_status: Option<u16>,
    conflict_once: bool,
    reject_attestations: Option<u16>,
}

fn stored_response(body: &[u8]) -> Response {
    let value: Value = serde_json::from_slice(body).unwrap();
    Response::new(200, body.to_vec())
        .header("Content-Type", value["mediaType"].as_str().unwrap())
        .header("Docker-Content-Digest", Digest::sha256(body).as_str())
        .header("ETag", &format!("\"{}\"", Digest::sha256(body)))
}

fn registry(image: &Image, state: Arc<Mutex<State>>) -> Server {
    let blobs = image.blobs.clone();
    Server::new(move |request| {
        let selector = request.path.rsplit('/').next().unwrap().to_owned();
        if request.method == "HEAD" {
            return Response::new(200, vec![])
                .header("Content-Length", &blobs[&selector].len().to_string());
        }
        assert!(request.path.starts_with("/v2/app/manifests/"));
        let mut state = state.lock().unwrap();
        if request.method == "GET" {
            return state
                .manifests
                .get(&selector)
                .map(|body| {
                    let mut response = stored_response(body);
                    if state.no_etag {
                        response.headers.retain(|(name, _)| name != "ETag");
                    }
                    response
                })
                .unwrap_or_else(|| Response::new(404, vec![]));
        }
        assert_eq!(request.method, "PUT");
        state.puts.push(selector.clone());
        if selector.starts_with("sha256-") || selector.starts_with("sha512-") {
            assert!(
                !state.native,
                "native registration must not write fallback tags"
            );
            if let Some(status) = state.fallback_status {
                return Response::new(status, vec![]);
            }
            if state.conflict_once {
                state.conflict_once = false;
                // Another writer wins creation, forcing a fresh read and merge.
                state.manifests.insert(selector, existing_index());
                return Response::new(412, vec![]);
            }
            if let Some(body) = state.manifests.get(&selector) {
                if state.no_etag {
                    assert!(!request.headers.contains_key("if-match"));
                } else {
                    assert_eq!(
                        request.headers.get("if-match"),
                        Some(&format!("\"{}\"", Digest::sha256(body)))
                    );
                }
            } else {
                assert_eq!(
                    request.headers.get("if-none-match").map(String::as_str),
                    Some("*")
                );
            }
        }
        let value: Value = serde_json::from_slice(&request.body).unwrap();
        if value["artifactType"] == "application/vnd.docker.attestation.manifest.v1+json"
            && let Some(status) = state.reject_attestations
        {
            return Response::new(
                status,
                br#"{"errors":[{"code":"DENIED","message":"secret-server-message"}]}"#.to_vec(),
            );
        }
        let digest = Digest::sha256(&request.body);
        state
            .manifests
            .insert(digest.to_string(), request.body.clone());
        state.manifests.insert(selector, request.body);
        let mut response =
            Response::new(201, vec![]).header("Docker-Content-Digest", digest.as_str());
        if state.wrong_subject && value.get("subject").is_some() {
            response = response.header("OCI-Subject", Digest::sha256(b"wrong").as_str());
        } else if state.native
            && let Some(subject) = value.get("subject")
        {
            response = response.header("OCI-Subject", subject["digest"].as_str().unwrap());
        }
        response
    })
}

fn source(image: &Image) -> Server {
    let root = image.manifest.clone();
    let blobs = image.blobs.clone();
    Server::new(move |request| {
        assert_eq!(request.method, "GET");
        let selector = request.path.rsplit('/').next().unwrap();
        let body = if selector == "v1" || selector == Digest::sha256(&root).as_str() {
            &root
        } else {
            &blobs[selector]
        };
        if request.path.contains("/manifests/") {
            stored_response(body)
        } else {
            Response::new(200, body.clone())
        }
    })
}

fn existing_index() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schemaVersion": 2, "mediaType": OCI_INDEX,
        "annotations": {"test.keep": "original"}, "test.extension": true,
        "manifests": [{"mediaType": OCI_MANIFEST, "digest": Digest::sha256(b"existing"),
            "size": 123, "artifactType": "application/example", "annotations": {"test.keep": "original"}}]
    })).unwrap()
}

fn proofs(image: &Image) -> Vec<Manifest> {
    image
        .blobs
        .values()
        .filter_map(|bytes| {
            let manifest = Manifest::parse(bytes.clone().into(), None, None).ok()?;
            manifest.subject().unwrap().is_some().then_some(manifest)
        })
        .collect()
}

#[test]
fn copy_preserves_attestations_and_registers_native_or_legacy_referrers() {
    for (native, no_etag) in [(true, false), (false, false), (false, true)] {
        let root = tempfile::tempdir().unwrap();
        let image = attested_layout(root.path());
        let proofs = proofs(&image);
        let state = Arc::new(Mutex::new(State {
            native,
            no_etag,
            ..Default::default()
        }));
        if !native {
            for proof in &proofs {
                let subject = proof.subject().unwrap().unwrap();
                state.lock().unwrap().manifests.insert(
                    subject.digest.to_string().replace(':', "-"),
                    existing_index(),
                );
            }
        }
        let source = source(&image);
        let target = registry(&image, state.clone());
        let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
        let src = format!("{}/app:v1", source.host);
        let dst = format!("{}/app:v1", target.host);
        harness.json(&["image", "copy", "--all", &src, &dst, "--dry-run"], 0);
        assert!(state.lock().unwrap().puts.is_empty());
        for _ in 0..2 {
            let result = harness.json(&["image", "copy", "--all", &src, &dst], 0);
            assert_eq!(result["data"]["target_digest"], image.digest);
            assert_eq!(
                result["data"]["platforms"],
                json!(["linux/amd64", "linux/arm64"])
            );
            let state = state.lock().unwrap();
            assert_eq!(state.manifests["v1"], image.manifest);
            for proof in &proofs {
                assert_eq!(state.manifests[proof.digest().as_str()], proof.raw);
                if !native {
                    let subject = proof.subject().unwrap().unwrap();
                    let tag = subject.digest.to_string().replace(':', "-");
                    let index: Value = serde_json::from_slice(&state.manifests[&tag]).unwrap();
                    assert_eq!(index["annotations"]["test.keep"], "original");
                    assert_eq!(index["test.extension"], true);
                    let entries = index["manifests"].as_array().unwrap();
                    let attached = proofs
                        .iter()
                        .filter(|p| p.subject().unwrap().unwrap().digest == subject.digest)
                        .count();
                    assert_eq!(
                        entries.len(),
                        attached + 1,
                        "entries must be merged without duplicates"
                    );
                    let entry = entries
                        .iter()
                        .find(|d| d["digest"] == proof.digest().to_string())
                        .unwrap();
                    assert_eq!(entry["artifactType"], proof.value["artifactType"]);
                    assert_eq!(entry["annotations"], proof.value["annotations"]);
                }
            }
        }
    }
}

#[test]
fn sha512_subject_uses_the_standard_truncated_fallback_tag() {
    let root = tempfile::tempdir().unwrap();
    let mut image = attested_layout(root.path());
    let mut proof = proofs(&image).remove(0).value;
    proof["subject"]["digest"] = json!(format!("sha512:{}", "ab".repeat(64)));
    image.manifest = serde_json::to_vec(&proof).unwrap();
    image.digest = Digest::sha256(&image.manifest).to_string();
    let source = source(&image);
    let state = Arc::new(Mutex::new(State::default()));
    let target = registry(&image, state.clone());
    let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    harness.json(
        &[
            "image",
            "copy",
            "--all",
            &format!("{}/app:v1", source.host),
            &format!("{}/app:v1", target.host),
        ],
        0,
    );
    let state = state.lock().unwrap();
    let tag = format!("sha512-{}", "ab".repeat(32));
    let index: Value = serde_json::from_slice(&state.manifests[&tag]).unwrap();
    assert_eq!(index["manifests"][0]["digest"], image.digest);
}

#[test]
fn failed_registration_is_reported_and_repaired_on_retry() {
    for root_only in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut image = attested_layout(root.path());
        if root_only {
            let proof = proofs(&image).remove(0);
            image.manifest = proof.raw.to_vec();
            image.digest = proof.digest().to_string();
        }
        let source = source(&image);
        let state = Arc::new(Mutex::new(State {
            fallback_status: Some(403),
            ..Default::default()
        }));
        let target = registry(&image, state.clone());
        let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
        let src = format!("{}/app:v1", source.host);
        let dst = format!("{}/app:v1", target.host);
        let error = harness.json(&["image", "copy", "--all", &src, &dst], 9);
        assert_eq!(error["status"], "partial");
        assert_eq!(error["data"]["remote_writes_may_have_occurred"], true);
        assert_eq!(
            state.lock().unwrap().manifests.contains_key("v1"),
            root_only
        );
        state.lock().unwrap().fallback_status = None;
        harness.json(&["image", "copy", "--all", &src, &dst], 0);
        for proof in proofs(&image)
            .into_iter()
            .filter(|proof| !root_only || proof.digest().as_str() == image.digest)
        {
            let tag = proof
                .subject()
                .unwrap()
                .unwrap()
                .digest
                .to_string()
                .replace(':', "-");
            let state = state.lock().unwrap();
            let index: Value = serde_json::from_slice(&state.manifests[&tag]).unwrap();
            assert!(
                index["manifests"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|d| d["digest"] == proof.digest().to_string())
            );
        }
    }
}

#[test]
fn fallback_conflicts_are_merged_and_retries_are_bounded() {
    for persistent in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let image = attested_layout(root.path());
        let proof = proofs(&image).remove(0);
        let source_image = Image {
            manifest: proof.raw.to_vec(),
            digest: proof.digest().to_string(),
            ..image
        };
        let source = source(&source_image);
        let state = Arc::new(Mutex::new(State {
            conflict_once: !persistent,
            fallback_status: persistent.then_some(412),
            ..Default::default()
        }));
        let target = registry(&source_image, state.clone());
        let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
        harness.json(
            &[
                "image",
                "copy",
                "--all",
                &format!("{}/app:v1", source.host),
                &format!("{}/app:v1", target.host),
            ],
            if persistent { 9 } else { 0 },
        );
        let state = state.lock().unwrap();
        let tag = proof
            .subject()
            .unwrap()
            .unwrap()
            .digest
            .to_string()
            .replace(':', "-");
        if persistent {
            assert_eq!(
                state
                    .puts
                    .iter()
                    .filter(|p| p.starts_with("sha256-"))
                    .count(),
                4
            );
        } else {
            let index: Value = serde_json::from_slice(&state.manifests[&tag]).unwrap();
            assert_eq!(index["manifests"].as_array().unwrap().len(), 2);
            assert_eq!(index["annotations"]["test.keep"], "original");
        }
    }
}

#[test]
fn wrong_acknowledgement_and_occupied_fallback_tag_fail() {
    for wrong_ack in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let image = attested_layout(root.path());
        let state = Arc::new(Mutex::new(State {
            wrong_subject: wrong_ack,
            ..Default::default()
        }));
        if !wrong_ack {
            for proof in proofs(&image) {
                let tag = proof
                    .subject()
                    .unwrap()
                    .unwrap()
                    .digest
                    .to_string()
                    .replace(':', "-");
                state
                    .lock()
                    .unwrap()
                    .manifests
                    .insert(tag, proof.raw.to_vec());
            }
        }
        let source = source(&image);
        let target = registry(&image, state.clone());
        let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
        let result = harness.json(
            &[
                "image",
                "copy",
                "--all",
                &format!("{}/app:v1", source.host),
                &format!("{}/app:v1", target.host),
            ],
            9,
        );
        assert!(
            result["error"]["message"]
                .as_str()
                .unwrap()
                .contains(if wrong_ack {
                    "different subject"
                } else {
                    "referrers tag"
                })
        );
        assert!(
            !state
                .lock()
                .unwrap()
                .puts
                .iter()
                .any(|p| p == "v1" || p.starts_with("sha256-"))
        );
    }
}

#[test]
fn all_platform_pull_and_push_preserve_attestations() {
    let root = tempfile::tempdir().unwrap();
    let image = attested_layout(root.path());
    let source = source(&image);
    let state = Arc::new(Mutex::new(State {
        native: true,
        ..Default::default()
    }));
    let target = registry(&image, state.clone());
    let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    let src = format!("{}/app:v1", source.host);
    let dst = format!("{}/app:v1", target.host);
    let directory = root.path().join("pulled");
    harness.json(
        &[
            "image",
            "pull",
            "--all",
            &src,
            "--output",
            directory.to_str().unwrap(),
            "--format",
            "oci-layout",
        ],
        0,
    );
    for proof in proofs(&image) {
        assert_eq!(
            fs::read(
                directory
                    .join("blobs/sha256")
                    .join(proof.digest().encoded())
            )
            .unwrap(),
            proof.raw
        );
    }
    harness.json(&["image", "push", directory.to_str().unwrap(), &dst], 0);
    assert_eq!(state.lock().unwrap().manifests["v1"], image.manifest);
    let selected = format!("{}/app:amd64", target.host);
    harness.json(
        &[
            "image",
            "copy",
            &src,
            &selected,
            "--platform",
            "linux/amd64",
        ],
        0,
    );
    let state = state.lock().unwrap();
    let manifest: Value = serde_json::from_slice(&state.manifests["amd64"]).unwrap();
    assert_eq!(manifest["mediaType"], OCI_MANIFEST);
    assert!(manifest.get("subject").is_none());
}

fn independent_image(root: &std::path::Path) -> Image {
    let mut image = attested_layout(root);
    let mut value: Value = serde_json::from_slice(&image.manifest).unwrap();
    value["manifests"]
        .as_array_mut()
        .unwrap()
        .retain(|d| d["platform"]["os"] != "unknown");
    image.manifest = serde_json::to_vec(&value).unwrap();
    image.digest = Digest::sha256(&image.manifest).to_string();
    let proof = proofs(&image).remove(0);
    let mut nested = proof.value.clone();
    nested["subject"] = serde_json::to_value(proof.descriptor).unwrap();
    let raw = serde_json::to_vec(&nested).unwrap();
    image.blobs.insert(Digest::sha256(&raw).to_string(), raw);
    image
}

fn discovery_source(image: &Image, native: bool, unrelated: bool) -> Server {
    let root = image.manifest.clone();
    let root_digest = image.digest.clone();
    let blobs = image.blobs.clone();
    let mut listings: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for proof in proofs(image) {
        let subject = proof.subject().unwrap().unwrap().digest.to_string();
        let mut descriptor = serde_json::to_value(proof.descriptor.clone()).unwrap();
        if unrelated {
            descriptor = serde_json::to_value(
                Manifest::parse(root.clone().into(), None, None)
                    .unwrap()
                    .descriptor,
            )
            .unwrap();
        }
        listings.entry(subject).or_default().push(descriptor);
    }
    Server::new(move |request| {
        assert_eq!(request.method, "GET");
        let selector = request
            .path
            .split('?')
            .next()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap();
        if request.path.contains("/referrers/") || selector.starts_with("sha256-") {
            let api = request.path.contains("/referrers/");
            if api && !native {
                return Response::new(404, vec![]);
            }
            let subject = selector.replacen("sha256-", "sha256:", 1);
            let mut entries = listings.get(&subject).cloned().unwrap_or_default();
            let more = api && entries.len() > 1 && !request.path.contains('?');
            if api && entries.len() > 1 {
                if more {
                    entries.truncate(1);
                } else {
                    entries.remove(0);
                }
            }
            let bytes = serde_json::to_vec(
                &json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":entries}),
            )
            .unwrap();
            let mut response = stored_response(&bytes);
            if more {
                response =
                    response.header("Link", &format!("<{}?page=2>; rel=\"next\"", request.path));
            }
            return response;
        }
        let body = if selector == "v1" || selector == root_digest {
            Some(&root)
        } else {
            blobs.get(selector)
        };
        match body {
            Some(body) if request.path.contains("/manifests/") => stored_response(body),
            Some(body) => Response::new(200, body.clone()),
            None => Response::new(404, vec![]),
        }
    })
}

#[test]
fn discovers_paginated_and_fallback_referrers_recursively_and_round_trips_offline() {
    for native in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let image = independent_image(root.path());
        let expected = proofs(&image);
        let source = discovery_source(&image, native, false);
        let state = Arc::new(Mutex::new(State {
            native: true,
            ..Default::default()
        }));
        let target = registry(&image, state.clone());
        let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
        let src = format!("{}/app:v1", source.host);
        let dst = format!("{}/app:v1", target.host);
        let result = harness.json(
            &[
                "image",
                "copy",
                "--all",
                &src,
                &dst,
                "--referrers",
                "all",
                "--dry-run",
            ],
            0,
        );
        assert_eq!(result["data"]["referrers"], "planned");
        assert!(state.lock().unwrap().puts.is_empty());
        let result = harness.json(
            &["image", "copy", "--all", &src, &dst, "--referrers", "all"],
            0,
        );
        assert_eq!(result["data"]["referrers"], "copied");
        for proof in &expected {
            assert_eq!(
                state.lock().unwrap().manifests[proof.digest().as_str()],
                proof.raw
            );
        }
        state.lock().unwrap().manifests.clear();
        let output = harness.root.path().join("associated.oci.tar");
        harness.json(
            &[
                "image",
                "pull",
                "--all",
                &src,
                "--referrers",
                "all",
                "-o",
                output.to_str().unwrap(),
            ],
            0,
        );
        let result = harness.json(&["image", "push", output.to_str().unwrap(), &dst], 0);
        assert_eq!(result["data"]["referrers"], "copied");
        for proof in &expected {
            assert_eq!(
                state.lock().unwrap().manifests[proof.digest().as_str()],
                proof.raw
            );
        }
    }
}

#[test]
fn selected_platform_keeps_only_its_attestations_when_requested() {
    for explicit in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let image = attested_layout(root.path());
        let source = source(&image);
        let state = Arc::new(Mutex::new(State {
            native: true,
            ..Default::default()
        }));
        let target = registry(&image, state.clone());
        let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
        let src = format!("{}/app:v1", source.host);
        let dst = format!("{}/app:v1", target.host);
        let mut args = vec!["image", "copy", &src, &dst, "--include-attestations"];
        let platform = quayside::model::Platform::native().unwrap();
        let architecture = if explicit {
            args.extend(["--platform", "linux/amd64"]);
            "amd64"
        } else {
            &platform.architecture
        };
        harness.json(&args, 0);
        let state = state.lock().unwrap();
        let index: Value = serde_json::from_slice(&state.manifests["v1"]).unwrap();
        let entries = index["manifests"].as_array().unwrap();
        assert_eq!(entries.len(), if architecture == "amd64" { 3 } else { 2 });
        assert_eq!(entries[0]["platform"]["architecture"], architecture);
        for descriptor in &entries[1..] {
            let raw = &state.manifests[descriptor["digest"].as_str().unwrap()];
            assert_eq!(raw, &image.blobs[descriptor["digest"].as_str().unwrap()]);
            let proof: Value = serde_json::from_slice(raw).unwrap();
            assert_eq!(proof["subject"]["digest"], entries[0]["digest"]);
        }
    }
}

#[test]
fn native_copy_and_pull_skip_other_platforms_and_attestations() {
    let native = quayside::model::Platform::native().unwrap();
    let other = if native.architecture == "amd64" {
        "arm64"
    } else {
        "amd64"
    };
    for explicit in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let image = attested_layout(root.path());
        let platform = format!(
            "linux/{}",
            if explicit {
                other
            } else {
                &native.architecture
            }
        );
        let index: Value = serde_json::from_slice(&image.manifest).unwrap();
        let descriptor = index["manifests"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["platform"]["architecture"] == platform.split('/').nth(1).unwrap())
            .unwrap();
        let digest = descriptor["digest"].as_str().unwrap().to_owned();
        let selected = image.blobs[&digest].clone();
        let manifest = Manifest::parse(selected.clone().into(), None, None).unwrap();
        let allowed: BTreeMap<_, _> = manifest
            .blobs()
            .unwrap()
            .into_iter()
            .map(|d| (d.digest.to_string(), image.blobs[d.digest.as_str()].clone()))
            .chain([
                (digest.clone(), selected.clone()),
                ("v1".into(), image.manifest.clone()),
            ])
            .collect();
        let source = Server::new(move |request| {
            assert_eq!(request.method, "GET");
            let key = request.path.rsplit('/').next().unwrap();
            let body = allowed
                .get(key)
                .expect("must not fetch other platforms or attestations");
            if request.path.contains("/manifests/") {
                stored_response(body)
            } else {
                Response::new(200, body.clone())
            }
        });
        let state = Arc::new(Mutex::new(State::default()));
        let target = registry(&image, state.clone());
        let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
        let src = format!("{}/app:v1", source.host);
        let dst = format!("{}/app:v1", target.host);
        let mut args = vec!["image", "copy", &src, &dst];
        if explicit {
            args.extend(["--platform", &platform]);
        }
        let result = harness.json(&args, 0);
        assert_eq!(result["data"]["platforms"], json!([platform]));
        assert_eq!(result["data"]["source_digest"], image.digest);
        assert_eq!(result["data"]["target_digest"], digest);
        assert_eq!(state.lock().unwrap().manifests["v1"], selected);
        assert_eq!(state.lock().unwrap().manifests.len(), 2);

        let output = root.path().join("pulled");
        let mut args = vec![
            "image",
            "pull",
            &src,
            "-o",
            output.to_str().unwrap(),
            "--format",
            "oci-layout",
        ];
        if explicit {
            args.extend(["--platform", &platform]);
        }
        let pulled = harness.json(&args, 0);
        assert_eq!(pulled["data"]["platforms"], json!([platform]));
        assert_eq!(pulled["data"]["source_digest"], image.digest);
        assert_eq!(pulled["data"]["target_digest"], digest);
        let files = fs::read_dir(output.join("blobs/sha256")).unwrap().count();
        assert_eq!(files, manifest.blobs().unwrap().len() + 1);
        for proof in proofs(&image) {
            assert!(
                !output
                    .join("blobs/sha256")
                    .join(proof.digest().encoded())
                    .exists()
            );
        }
    }
}

#[test]
fn missing_native_platform_fails_before_payloads_or_destination_access() {
    let native = quayside::model::Platform::native().unwrap();
    let other = if native.architecture == "amd64" {
        "arm64"
    } else {
        "amd64"
    };
    for indexed in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let image = support::image_layout_for(root.path(), 1, 64, other);
        let manifest = Manifest::parse(image.manifest.clone().into(), None, None).unwrap();
        let config = manifest.config().unwrap();
        let mut descriptor = manifest.descriptor.clone();
        descriptor.platform = Some(format!("linux/{other}").parse().unwrap());
        let raw = if indexed {
            serde_json::to_vec(
                &json!({"schemaVersion":2, "mediaType":OCI_INDEX, "manifests":[descriptor]}),
            )
            .unwrap()
        } else {
            image.manifest.clone()
        };
        let source = Server::new(move |request| {
            if request.path.ends_with("/manifests/v1") {
                return stored_response(&raw);
            }
            assert!(!indexed, "an incompatible child must not be fetched");
            assert!(
                request.path.ends_with(config.digest.as_str()),
                "must not download layers"
            );
            Response::new(200, image.blobs[config.digest.as_str()].clone())
        });
        let target = Server::new(|_| panic!("must reject platform before contacting destination"));
        let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
        let src = format!("{}/app:v1", source.host);
        let dst = format!("{}/app:v1", target.host);
        let output = root.path().join("pulled");
        for args in [
            vec!["image", "copy", &src, &dst],
            vec!["image", "pull", &src, "-o", output.to_str().unwrap()],
        ] {
            let error = harness.json(&args, 2);
            let message = error["error"]["message"].as_str().unwrap();
            assert!(message.contains(&native.to_string()), "{message}");
            assert!(message.contains("--platform") && message.contains("--all"));
            assert_eq!(error["data"]["remote_writes_may_have_occurred"], false);
            assert!(!output.exists());
        }
    }
}

#[test]
fn platform_notice_respects_json_quiet_and_no_progress() {
    let root = tempfile::tempdir().unwrap();
    let image = attested_layout(root.path());
    let source = source(&image);
    let target = registry(&image, Arc::default());
    let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    let src = format!("{}/app:v1", source.host);
    let dst = format!("{}/app:v1", target.host);
    let platform = quayside::model::Platform::native().unwrap();
    for flags in [
        vec![],
        vec!["--no-progress"],
        vec!["--quiet"],
        vec!["--json"],
    ] {
        let output = harness
            .command(&["image", "copy", &src, &dst, "--dry-run"])
            .args(&flags)
            .output()
            .unwrap();
        assert!(output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(
            stderr.contains(&format!("Platform: {platform}")),
            !flags.contains(&"--json") && !flags.contains(&"--quiet"),
            "{stderr}"
        );
        if flags.contains(&"--json") {
            let value: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(value["data"]["platforms"], json!([platform.to_string()]));
        }
    }
}

#[test]
fn native_copy_preserves_platformless_artifacts() {
    for opaque in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let image = support::artifact_layout(root.path(), false, opaque);
        let source = source(&image);
        let state = Arc::new(Mutex::new(State::default()));
        let target = registry(&image, state.clone());
        let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
        let src = format!("{}/app:v1", source.host);
        let dst = format!("{}/app:v1", target.host);
        let result = harness.json(&["image", "copy", &src, &dst], 0);
        assert_eq!(result["data"]["platforms"], json!([]));
        assert_eq!(result["data"]["target_digest"], image.digest);
        assert_eq!(state.lock().unwrap().manifests["v1"], image.manifest);
        harness.json(
            &["image", "copy", &src, &dst, "--platform", "linux/amd64"],
            2,
        );
    }
}

#[test]
fn attestation_rejection_identifies_the_manifest_and_preserves_the_image_tag() {
    for status in [403, 415] {
        for option in ["--all", "--include-attestations"] {
            let root = tempfile::tempdir().unwrap();
            let image = attested_layout(root.path());
            let source = source(&image);
            let state = Arc::new(Mutex::new(State {
                native: true,
                reject_attestations: Some(status),
                ..Default::default()
            }));
            let target = registry(&image, state.clone());
            let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
            harness.config.transfer.concurrency = 1;
            harness.config.transfer.max_retries = 3;
            let src = format!("{}/app:v1", source.host);
            let dst = format!("{}/app:v1", target.host);
            // Ordinary image copies succeed against a registry that rejects attachments.
            let copied = harness.json(&["image", "copy", &src, &dst], 0);
            let selected = state.lock().unwrap().manifests["v1"].clone();
            state.lock().unwrap().puts.clear();
            let output = harness
                .command(&["--json", "image", "copy", &src, &dst, option, "--overwrite"])
                .output()
                .unwrap();
            assert!(!output.status.success());
            let error: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                error["error"]["code"],
                if status == 403 {
                    "FORBIDDEN"
                } else {
                    "UNSUPPORTED"
                }
            );
            let message = error["error"]["message"].as_str().unwrap();
            for expected in [
                "Operation: publish manifest by digest",
                "(build attestation)",
                "Config media type: application/vnd.oci.empty.v1+json",
                "Registry error: DENIED",
                "permission to publish artifacts",
                "default platform or --platform",
            ] {
                assert!(message.contains(expected), "{message}");
            }
            assert!(!message.contains("secret-server-message"));
            let state = state.lock().unwrap();
            let rejected: Vec<_> = proofs(&image)
                .into_iter()
                .filter(|p| state.puts.iter().any(|d| d == p.digest().as_str()))
                .collect();
            assert_eq!(rejected.len(), 1);
            let digest = rejected[0].digest().as_str();
            assert!(message.contains(digest), "{message}");
            assert_eq!(
                state.puts.iter().filter(|d| *d == digest).count(),
                1,
                "rejections must not retry or downgrade content"
            );
            assert_eq!(state.manifests["v1"], selected);
            assert_eq!(
                copied["data"]["target_digest"],
                Digest::sha256(&selected).to_string()
            );
            assert!(!state.puts.iter().any(|p| p == "v1"));
        }
    }
}

#[test]
fn token_denial_during_attestation_publication_is_not_a_manifest_rejection() {
    let root = tempfile::tempdir().unwrap();
    let mut image = attested_layout(root.path());
    let proof = proofs(&image).remove(0);
    image.manifest = proof.raw.to_vec();
    image.digest = proof.digest().to_string();
    let source = source(&image);
    let blobs = image.blobs.clone();
    let target = Server::new(move |request| {
        if request.path.starts_with("/token?") {
            return Response::new(403, br#"{"errors":[{"code":"DENIED"}]}"#.to_vec());
        }
        if request.method == "HEAD" {
            let digest = request.path.rsplit('/').next().unwrap();
            return Response::new(200, vec![])
                .header("Content-Length", &blobs[digest].len().to_string());
        }
        if request.method == "GET" {
            return Response::new(404, vec![]);
        }
        assert_eq!(request.method, "PUT");
        Response::new(401, vec![]).header("WWW-Authenticate", &format!(
            "Bearer realm=\"http://{}/token\",service=\"fixture\",scope=\"repository:app:pull,push\"",
            request.headers["host"]
        ))
    });
    let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    let error = harness.json(
        &[
            "image",
            "copy",
            &format!("{}/app:v1", source.host),
            &format!("{}/app:v1", target.host),
        ],
        3,
    );
    let message = error["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("Operation: request registry token"),
        "{message}"
    );
    assert!(!message.contains("Manifest:"), "{message}");
    assert!(!message.contains("attestation"), "{message}");
}

#[test]
fn rejects_unrelated_discovered_manifests_before_any_remote_write() {
    let root = tempfile::tempdir().unwrap();
    let image = independent_image(root.path());
    let source = discovery_source(&image, true, true);
    let state = Arc::new(Mutex::new(State::default()));
    let target = registry(&image, state.clone());
    let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    let result = harness.json(
        &[
            "image",
            "copy",
            &format!("{}/app:v1", source.host),
            &format!("{}/app:v1", target.host),
            "--referrers",
            "all",
        ],
        7,
    );
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unrelated")
    );
    assert!(state.lock().unwrap().puts.is_empty());
}
