mod support;

use quayside::model::{Descriptor, Manifest, OCI_INDEX, OCI_MANIFEST};
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use support::{Harness, Response, Server, image_layout};

#[test]
fn digest_reads_only_manifest_and_inspect_reads_config_once() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 1, 8192);
    let expected = image.digest.clone();
    let reads = Arc::new(AtomicUsize::new(0));
    let observed = reads.clone();
    let server = Server::new(move |request| {
        if request.path.contains("/manifests/") {
            Response::new(200, image.manifest.clone()).header("Content-Type", OCI_MANIFEST)
        } else {
            observed.fetch_add(1, Ordering::SeqCst);
            Response::new(
                200,
                image.blobs[request.path.rsplit('/').next().unwrap()].clone(),
            )
        }
    });
    let harness = Harness::new(&[(&server.host, true)]);
    let reference = format!("{}/app:v1", server.host);
    let result = harness.json(&["image", "digest", &reference], 0);
    assert_eq!(result["data"]["digest"], expected);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    let inspected = harness.json(&["image", "inspect", &reference], 0);
    assert_eq!(inspected["data"]["platforms"], json!(["linux/arm64/v8"]));
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    harness.json(
        &["image", "digest", &reference, "--platform", "linux/arm64"],
        0,
    );
    assert_eq!(reads.load(Ordering::SeqCst), 2);
}

#[test]
fn tag_checks_once_before_write_and_verifies_after_write() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 0, 0);
    let writes = Arc::new(AtomicUsize::new(0));
    let observed = writes.clone();
    let server = Server::new(move |request| match request.method.as_str() {
        "GET" if request.path.ends_with("/v2") && observed.load(Ordering::SeqCst) == 0 => {
            Response::new(404, vec![])
        }
        "GET" => Response::new(200, image.manifest.clone()).header("Content-Type", OCI_MANIFEST),
        "PUT" => {
            assert_eq!(request.body, image.manifest);
            observed.fetch_add(1, Ordering::SeqCst);
            Response::new(201, vec![])
        }
        _ => panic!("unexpected tag request"),
    });
    let harness = Harness::new(&[(&server.host, true)]);
    let src = format!("{}/app:v1", server.host);
    let dst = format!("{}/app:v2", server.host);
    harness.json(&["image", "tag", &src, &dst], 0);
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    assert_eq!(server.connections.load(Ordering::SeqCst), 4); // source GET, check, PUT, verify
    harness.json(&["image", "tag", &src, &dst], 0);
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    assert_eq!(server.connections.load(Ordering::SeqCst), 6); // existing identical tag needs one check
}

#[test]
fn index_inputs_share_verified_config_and_duplicate_references_are_not_refetched() {
    let root = tempfile::tempdir().unwrap();
    let first = image_layout(&root.path().join("a"), 1, 16);
    let second = image_layout(&root.path().join("b"), 1, 32);
    let reads = Arc::new(Mutex::new(BTreeMap::<String, usize>::new()));
    let observed = reads.clone();
    let server = Server::new(move |request| {
        assert_eq!(
            request.method, "GET",
            "conflicting platforms must be rejected before writes"
        );
        *observed
            .lock()
            .unwrap()
            .entry(request.path.clone())
            .or_default() += 1;
        if request.path.ends_with("/manifests/a") {
            Response::new(200, first.manifest.clone()).header("Content-Type", OCI_MANIFEST)
        } else if request.path.ends_with("/manifests/b") {
            Response::new(200, second.manifest.clone()).header("Content-Type", OCI_MANIFEST)
        } else {
            Response::new(
                200,
                first.blobs[request.path.rsplit('/').next().unwrap()].clone(),
            )
        }
    });
    let harness = Harness::new(&[(&server.host, true)]);
    let a = format!("{}/app:a", server.host);
    let b = format!("{}/app:b", server.host);
    let dst = format!("{}/app:all", server.host);
    harness.json(
        &[
            "index", "create", &dst, "--from", &a, "--from", &a, "--from", &b,
        ],
        8,
    );
    let reads = reads.lock().unwrap();
    assert_eq!(reads.len(), 3); // two different manifests, one shared config
    assert!(reads.values().all(|count| *count == 1));
}

fn index(children: &[&Manifest], name: &str) -> Manifest {
    Manifest::parse(
        serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":OCI_INDEX,
            "annotations":{"fixture":name},
            "manifests":children.iter().map(|m| &m.descriptor).collect::<Vec<_>>()
        }))
        .unwrap()
        .into(),
        Some(OCI_INDEX),
        None,
    )
    .unwrap()
}

#[test]
fn copy_publishes_siblings_concurrently_and_parents_after_children() {
    // Empty indexes need no payloads; the nested DAG contains a shared child.
    let a = index(&[], "a");
    let b = index(&[], "b");
    let middle = index(&[&a], "middle");
    let root = index(&[&middle, &b, &a], "root");
    let root_digest = root.digest().to_string();
    let leaves = [a.digest().to_string(), b.digest().to_string()];
    let manifests: BTreeMap<_, _> = [&a, &b, &middle, &root]
        .into_iter()
        .map(|m| (m.digest().to_string(), m.clone()))
        .collect();
    let source = Server::new(move |request| {
        let key = request.path.rsplit('/').next().unwrap();
        let manifest = if key == "v1" { &root } else { &manifests[key] };
        Response::new(200, manifest.raw.to_vec()).header("Content-Type", OCI_INDEX)
    });
    let stored = Arc::new(Mutex::new(BTreeMap::<String, Vec<u8>>::new()));
    let remote = stored.clone();
    let writes = Arc::new(Mutex::new(Vec::new()));
    let observed = writes.clone();
    let arrived = Arc::new((Mutex::new(0), Condvar::new()));
    let target = Server::new(move |request| {
        let key = request.path.rsplit('/').next().unwrap();
        if request.method == "GET" {
            if leaves.iter().any(|leaf| leaf == key) {
                let mut count = arrived.0.lock().unwrap();
                *count += 1;
                arrived.1.notify_all();
                let (_count, timeout) = arrived
                    .1
                    .wait_timeout_while(count, Duration::from_secs(3), |n| *n < 2)
                    .unwrap();
                assert!(
                    !timeout.timed_out(),
                    "independent manifest checks must overlap"
                );
            }
            return remote
                .lock()
                .unwrap()
                .get(key)
                .map(|bytes| Response::new(200, bytes.clone()).header("Content-Type", OCI_INDEX))
                .unwrap_or_else(|| Response::new(404, vec![]));
        }
        assert_eq!(request.method, "PUT");
        let manifest = Manifest::parse(request.body.clone().into(), Some(OCI_INDEX), None).unwrap();
        let mut remote = remote.lock().unwrap();
        for child in manifest.children().unwrap() {
            assert!(
                remote.contains_key(child.digest.as_str()),
                "parent published before dependency"
            );
        }
        remote.insert(manifest.digest().to_string(), request.body.clone());
        remote.insert(key.to_owned(), request.body);
        observed.lock().unwrap().push(key.to_owned());
        Response::new(201, vec![])
    });
    let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    harness.config.transfer.concurrency = 2;
    let src = format!("{}/app:v1", source.host);
    let dst = format!("{}/app:v1", target.host);
    harness.json(&["image", "copy", &src, &dst], 0);
    let writes = writes.lock().unwrap();
    assert_eq!(writes.len(), 4);
    assert_eq!(writes.last().unwrap(), "v1");
    assert!(
        !writes.contains(&root_digest),
        "root needs only the final tag publication"
    );
    assert!(stored.lock().unwrap().contains_key(&root_digest));
}

#[test]
fn failed_dependency_check_never_publishes_parent() {
    let child = index(&[], "child");
    let root = index(&[&child], "parent");
    let source = Server::new(move |request| {
        let manifest = if request.path.ends_with("/v1") {
            &root
        } else {
            &child
        };
        Response::new(200, manifest.raw.to_vec()).header("Content-Type", OCI_INDEX)
    });
    let target = Server::new(|request| {
        assert_eq!(
            request.method, "GET",
            "a failed dependency cannot permit publication"
        );
        Response::new(
            if request.path.ends_with("/v1") {
                404
            } else {
                500
            },
            vec![],
        )
    });
    let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    harness.json(
        &[
            "image",
            "copy",
            &format!("{}/app:v1", source.host),
            &format!("{}/app:v1", target.host),
        ],
        6,
    );
}

#[test]
fn cancelled_manifest_write_reports_uncertain_remote_changes() {
    let a = index(&[], "writing");
    let b = index(&[], "failing");
    let root = index(&[&a, &b], "root");
    let failing = b.digest().to_string();
    let source = Server::new(move |request| {
        let key = request.path.rsplit('/').next().unwrap();
        let manifest = if key == "v1" {
            &root
        } else if key == a.digest().as_str() {
            &a
        } else {
            &b
        };
        Response::new(200, manifest.raw.to_vec()).header("Content-Type", OCI_INDEX)
    });
    let gate = Arc::new((Mutex::new((false, false)), Condvar::new()));
    let observed = gate.clone();
    let target = Server::new(move |request| {
        if request.method == "PUT" {
            // The request body reached the registry, but hold its response until copy has exited.
            let mut state = observed.0.lock().unwrap();
            state.0 = true;
            observed.1.notify_all();
            let (_state, _) = observed
                .1
                .wait_timeout_while(state, Duration::from_secs(3), |s| !s.1)
                .unwrap();
            return Response::new(201, vec![]);
        }
        if request.path.ends_with(&failing) {
            let (_state, timeout) = observed
                .1
                .wait_timeout_while(observed.0.lock().unwrap(), Duration::from_secs(3), |s| !s.0)
                .unwrap();
            assert!(!timeout.timed_out(), "expected a concurrent manifest write");
            return Response::new(500, vec![]);
        }
        Response::new(404, vec![])
    });
    let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    harness.config.transfer.concurrency = 2;
    let result = harness.json(
        &[
            "image",
            "copy",
            &format!("{}/app:v1", source.host),
            &format!("{}/app:v1", target.host),
        ],
        9,
    );
    assert_eq!(result["data"]["remote_writes_may_have_occurred"], true);
    gate.0.lock().unwrap().1 = true;
    gate.1.notify_all();
}

#[test]
fn ready_parent_does_not_wait_for_an_unrelated_slow_branch() {
    let fast = index(&[], "fast");
    let slow = index(&[], "slow");
    // Repeated edges must not keep a parent waiting for a second completion of the same child.
    let parent = index(&[&fast, &fast], "parent");
    let root = index(&[&parent, &slow], "root");
    let slow_digest = slow.digest().to_string();
    let parent_digest = parent.digest().to_string();
    let manifests: BTreeMap<_, _> = [&fast, &slow, &parent]
        .into_iter()
        .map(|m| (m.digest().to_string(), m.raw.to_vec()))
        .collect();
    let source = Server::new(move |request| {
        let key = request.path.rsplit('/').next().unwrap();
        Response::new(
            200,
            if key == "v1" {
                root.raw.to_vec()
            } else {
                manifests[key].clone()
            },
        )
        .header("Content-Type", OCI_INDEX)
    });
    let committed = (Mutex::new(false), Condvar::new());
    let stored = Mutex::new(BTreeMap::<String, Vec<u8>>::new());
    let target = Server::new(move |request| {
        let key = request.path.rsplit('/').next().unwrap();
        if request.method == "GET" {
            if key == slow_digest {
                let (_done, timeout) = committed
                    .1
                    .wait_timeout_while(
                        committed.0.lock().unwrap(),
                        Duration::from_secs(3),
                        |done| !*done,
                    )
                    .unwrap();
                assert!(
                    !timeout.timed_out(),
                    "ready parent was blocked by an unrelated slow manifest"
                );
            }
            return stored
                .lock()
                .unwrap()
                .get(key)
                .map(|body| Response::new(200, body.clone()).header("Content-Type", OCI_INDEX))
                .unwrap_or_else(|| Response::new(404, vec![]));
        }
        assert_eq!(request.method, "PUT");
        stored.lock().unwrap().insert(key.to_owned(), request.body);
        if key == parent_digest {
            *committed.0.lock().unwrap() = true;
            committed.1.notify_all();
        }
        Response::new(201, vec![])
    });
    let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    harness.config.transfer.concurrency = 2;
    harness.json(
        &[
            "image",
            "copy",
            &format!("{}/app:v1", source.host),
            &format!("{}/app:v1", target.host),
        ],
        0,
    );
}

#[test]
fn platform_selection_fetches_candidates_concurrently_and_deduplicates_them() {
    let root = tempfile::tempdir().unwrap();
    let arm = image_layout(&root.path().join("arm"), 0, 0);
    let amd = support::image_layout_for(&root.path().join("amd"), 0, 0, "amd64");
    let arm_manifest =
        Manifest::parse(arm.manifest.clone().into(), Some(OCI_MANIFEST), None).unwrap();
    let amd_manifest =
        Manifest::parse(amd.manifest.clone().into(), Some(OCI_MANIFEST), None).unwrap();
    let index = index(&[&arm_manifest, &amd_manifest, &arm_manifest], "platforms");
    let expected = arm.digest.clone();
    let reads = Arc::new(Mutex::new(BTreeMap::<String, usize>::new()));
    let observed = reads.clone();
    let arrivals = (Mutex::new(0), Condvar::new());
    let source = Server::new(move |request| {
        let key = request.path.rsplit('/').next().unwrap();
        if key == "v1" {
            return Response::new(200, index.raw.to_vec()).header("Content-Type", OCI_INDEX);
        }
        *observed
            .lock()
            .unwrap()
            .entry(request.path.clone())
            .or_default() += 1;
        if request.path.contains("/manifests/") {
            let mut arrived = arrivals.0.lock().unwrap();
            *arrived += 1;
            arrivals.1.notify_all();
            let (_arrived, timeout) = arrivals
                .1
                .wait_timeout_while(arrived, Duration::from_secs(3), |n| *n < 2)
                .unwrap();
            assert!(
                !timeout.timed_out(),
                "platform candidates must be fetched concurrently"
            );
            Response::new(
                200,
                if key == arm.digest {
                    arm.manifest.clone()
                } else {
                    amd.manifest.clone()
                },
            )
            .header("Content-Type", OCI_MANIFEST)
        } else {
            Response::new(
                200,
                arm.blobs
                    .get(key)
                    .or_else(|| amd.blobs.get(key))
                    .unwrap()
                    .clone(),
            )
        }
    });
    let mut harness = Harness::new(&[(&source.host, true)]);
    harness.config.transfer.concurrency = 2;
    let result = harness.json(
        &[
            "image",
            "digest",
            &format!("{}/app:v1", source.host),
            "--platform",
            "linux/arm64",
        ],
        0,
    );
    assert_eq!(result["data"]["digest"], expected);
    let reads = reads.lock().unwrap();
    assert_eq!(reads.len(), 4); // Two candidate manifests and their platform configurations.
    assert!(reads.values().all(|count| *count == 1));
}

#[test]
fn platform_selection_reserves_limits_before_requests_and_rejects_conflicting_descriptors() {
    for mode in ["metadata", "objects", "conflict"] {
        let child = index(&[], "child");
        let mut descriptor = child.descriptor.clone();
        if mode == "metadata" {
            descriptor.size = 1000;
        }
        let mut descriptors = vec![descriptor.clone()];
        if mode == "conflict" {
            descriptor.size += 1;
            descriptors.push(descriptor);
        }
        let body = serde_json::to_vec(
            &json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":descriptors}),
        )
        .unwrap();
        let source = Server::new(move |request| {
            assert!(
                request.path.ends_with("/v1"),
                "invalid plans must fail before fetching children"
            );
            Response::new(200, body.clone()).header("Content-Type", OCI_INDEX)
        });
        let mut harness = Harness::new(&[(&source.host, true)]);
        harness.config.transfer.max_manifest_size = "1KiB".into();
        harness.config.transfer.max_metadata_size = "1KiB".into();
        if mode == "objects" {
            harness.config.transfer.max_objects = 1;
        }
        harness.json(
            &[
                "image",
                "digest",
                &format!("{}/app:v1", source.host),
                "--platform",
                "linux/arm64",
            ],
            if mode == "conflict" { 7 } else { 2 },
        );
        assert_eq!(source.connections.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn nested_platform_selection_counts_each_manifest_once_against_budget() {
    let temp = tempfile::tempdir().unwrap();
    let image = image_layout(temp.path(), 0, 0);
    let mut value: serde_json::Value = serde_json::from_slice(&image.manifest).unwrap();
    value["annotations"] = json!({"fixture": "x".repeat(400)});
    let leaf = Manifest::parse(
        serde_json::to_vec(&value).unwrap().into(),
        Some(OCI_MANIFEST),
        None,
    )
    .unwrap();
    let middle = index(&[&leaf], "middle");
    let root = index(&[&middle], "root");
    let total = root.raw.len() + middle.raw.len() + leaf.raw.len();
    let budget = total.max(1024);
    assert!(
        total + middle.raw.len() > budget,
        "fixture must detect double-counted indexes"
    );
    let expected = leaf.digest().to_string();
    let source = Server::new(move |request| {
        let key = request.path.rsplit('/').next().unwrap();
        if request.path.contains("/blobs/") {
            return Response::new(200, image.blobs[key].clone());
        }
        let manifest = if key == "v1" {
            &root
        } else if key == middle.digest().as_str() {
            &middle
        } else {
            &leaf
        };
        Response::new(200, manifest.raw.to_vec())
            .header("Content-Type", &manifest.descriptor.media_type)
    });
    let mut harness = Harness::new(&[(&source.host, true)]);
    harness.config.transfer.max_manifest_size = "1KiB".into();
    harness.config.transfer.max_metadata_size = format!("{budget}B");
    let result = harness.json(
        &[
            "image",
            "digest",
            &format!("{}/app:v1", source.host),
            "--platform",
            "linux/arm64",
        ],
        0,
    );
    assert_eq!(result["data"]["digest"], expected);
    assert_eq!(source.connections.load(Ordering::SeqCst), 4);
}

#[test]
#[ignore = "local platform latency benchmark; optionally set QUAYSIDE_TEST_BINARY to compare builds"]
fn platform_selection_latency_benchmark() {
    let temp = tempfile::tempdir().unwrap();
    let mut manifests = Vec::new();
    let mut configs = BTreeMap::new();
    let mut expected = String::new();
    for arch in [
        "arm64", "amd64", "386", "arm", "ppc64", "ppc64le", "riscv64", "s390x",
    ] {
        let image = support::image_layout_for(&temp.path().join(arch), 0, 0, arch);
        if arch == "arm64" {
            expected = image.digest.clone();
        }
        manifests.push(Manifest::parse(image.manifest.into(), Some(OCI_MANIFEST), None).unwrap());
        configs.extend(image.blobs);
    }
    let root = index(&manifests.iter().collect::<Vec<_>>(), "platforms");
    let manifests: BTreeMap<_, _> = manifests
        .into_iter()
        .map(|m| (m.digest().to_string(), m.raw.to_vec()))
        .collect();
    let source = Server::new(move |request| {
        std::thread::sleep(Duration::from_millis(80));
        let key = request.path.rsplit('/').next().unwrap();
        if key == "v1" {
            Response::new(200, root.raw.to_vec()).header("Content-Type", OCI_INDEX)
        } else if request.path.contains("/manifests/") {
            Response::new(200, manifests[key].clone()).header("Content-Type", OCI_MANIFEST)
        } else {
            Response::new(200, configs[key].clone())
        }
    });
    let harness = Harness::new(&[(&source.host, true)]);
    let started = std::time::Instant::now();
    let result = harness.json(
        &[
            "image",
            "digest",
            &format!("{}/app:v1", source.host),
            "--platform",
            "linux/arm64",
        ],
        0,
    );
    assert_eq!(result["data"]["digest"], expected);
    println!(
        "8 candidates without platform hints, 80ms per request, concurrency=4: elapsed={:?}, requests={}",
        started.elapsed(),
        source.connections.load(Ordering::SeqCst)
    );
}

#[test]
fn pull_and_push_schedule_largest_blobs_first() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 2, 8192);
    let mut manifest: serde_json::Value = serde_json::from_slice(&image.manifest).unwrap();
    manifest["artifactType"] = json!("application/example");
    let raw = serde_json::to_vec(&manifest).unwrap();
    let reads = Arc::new(Mutex::new(Vec::new()));
    let observed = reads.clone();
    let server = Server::new(move |request| {
        if request.path.contains("/manifests/") {
            return Response::new(200, raw.clone()).header("Content-Type", OCI_MANIFEST);
        }
        let body = image.blobs[request.path.rsplit('/').next().unwrap()].clone();
        observed.lock().unwrap().push(body.len());
        Response::new(200, body)
    });
    let mut harness = Harness::new(&[(&server.host, true)]);
    harness.config.transfer.concurrency = 1;
    let reference = format!("{}/app:v1", server.host);
    let output = root.path().join("image.tar");
    harness.json(
        &["image", "pull", &reference, "-o", output.to_str().unwrap()],
        0,
    );
    let sizes = reads.lock().unwrap().clone();
    assert_eq!(&sizes[..2], &[8192, 8192]);
    assert!(sizes[2] < 8192);
    let checked = Arc::new(Mutex::new(Vec::new()));
    let observed = checked.clone();
    let target = Server::new(move |request| {
        assert!(matches!(request.method.as_str(), "HEAD" | "GET"));
        if request.method == "HEAD" {
            observed
                .lock()
                .unwrap()
                .push(request.path.rsplit('/').next().unwrap().to_owned());
        }
        Response::new(404, vec![])
    });
    harness.config.registries.insert(
        target.host.clone(),
        quayside::config::RegistryConfig {
            plain_http: true,
            ..Default::default()
        },
    );
    harness.json(
        &[
            "image",
            "push",
            output.to_str().unwrap(),
            &format!("{}/app:v1", target.host),
            "--dry-run",
        ],
        0,
    );
    let checked = checked.lock().unwrap();
    let config: Descriptor = serde_json::from_value(manifest["config"].clone()).unwrap();
    assert_eq!(checked.len(), 3);
    assert_eq!(checked.last().unwrap(), config.digest.as_str());
}

#[test]
#[ignore = "local metadata latency benchmark; optionally set QUAYSIDE_TEST_BINARY to compare builds"]
fn manifest_publication_latency_benchmark() {
    let children: Vec<_> = (0..32).map(|n| index(&[], &n.to_string())).collect();
    let root = index(&children.iter().collect::<Vec<_>>(), "root");
    let expected = root.digest().to_string();
    let manifests: BTreeMap<_, _> = children
        .into_iter()
        .map(|m| (m.digest().to_string(), m.raw.to_vec()))
        .collect();
    let source = Server::new(move |request| {
        let key = request.path.rsplit('/').next().unwrap();
        let body = if key == "v1" {
            root.raw.to_vec()
        } else {
            manifests[key].clone()
        };
        Response::new(200, body).header("Content-Type", OCI_INDEX)
    });
    let published = Mutex::new(BTreeMap::<String, Vec<u8>>::new());
    let target = Server::new(move |request| {
        std::thread::sleep(Duration::from_millis(80));
        let key = request.path.rsplit('/').next().unwrap();
        let mut published = published.lock().unwrap();
        if request.method == "GET" {
            published
                .get(key)
                .map(|body| Response::new(200, body.clone()).header("Content-Type", OCI_INDEX))
                .unwrap_or_else(|| Response::new(404, vec![]))
        } else {
            assert_eq!(request.method, "PUT");
            published.insert(key.to_owned(), request.body);
            Response::new(201, vec![])
        }
    });
    let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    let started = std::time::Instant::now();
    let result = harness.json(
        &[
            "image",
            "copy",
            &format!("{}/app:v1", source.host),
            &format!("{}/app:v1", target.host),
        ],
        0,
    );
    assert_eq!(result["data"]["target_digest"], expected);
    println!(
        "32 child manifests, 80ms target request latency, concurrency=4: elapsed={:?}, target_requests={}",
        started.elapsed(),
        target.connections.load(Ordering::SeqCst)
    );
}
