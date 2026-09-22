mod support;

use quayside::digest::Digest;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    process::Stdio,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use support::{Harness, Request, Response, Server, image_layout};

#[derive(Default)]
struct Store {
    uploads: BTreeMap<String, Vec<u8>>,
    blobs: BTreeMap<String, Vec<u8>>,
    manifests: BTreeMap<String, Vec<u8>>,
    next: usize,
}

fn destination(accept: impl Fn(&Request) -> bool + Send + Sync + 'static) -> Server {
    destination_with_commit(accept, || true)
}

fn destination_with_commit(
    accept: impl Fn(&Request) -> bool + Send + Sync + 'static,
    committed: impl Fn() -> bool + Send + Sync + 'static,
) -> Server {
    let state = Mutex::new(Store::default());
    Server::new(move |request| {
        if request.path.contains("/blobs/uploads/") && !request.body.is_empty() && !accept(&request)
        {
            return Response::new(500, vec![]);
        }
        let mut state = state.lock().unwrap();
        if request.path.contains("/manifests/") {
            return match request.method.as_str() {
                "GET" => state
                    .manifests
                    .get(&request.path)
                    .map(|body| {
                        Response::new(200, body.clone())
                            .header("Content-Type", quayside::model::OCI_MANIFEST)
                    })
                    .unwrap_or_else(|| Response::new(404, vec![])),
                "PUT" => {
                    state.manifests.insert(request.path, request.body);
                    Response::new(201, vec![])
                }
                _ => panic!("unexpected manifest method"),
            };
        }
        if request.method == "HEAD" {
            let digest = request.path.rsplit('/').next().unwrap();
            return state
                .blobs
                .get(digest)
                .map(|body| {
                    Response::new(200, vec![]).header("Content-Length", &body.len().to_string())
                })
                .unwrap_or_else(|| Response::new(404, vec![]));
        }
        match request.method.as_str() {
            "POST" => {
                state.next += 1;
                let path = format!("/v2/app/blobs/uploads/{}", state.next);
                state.uploads.insert(path.clone(), vec![]);
                Response::new(202, vec![]).header("Location", &path)
            }
            "PATCH" => {
                let bytes = state.uploads.get_mut(&request.path).unwrap();
                assert_eq!(
                    request.headers["content-range"],
                    format!("{}-{}", bytes.len(), bytes.len() + request.body.len() - 1)
                );
                bytes.extend_from_slice(&request.body);
                Response::new(202, vec![]).header("Location", &request.path)
            }
            "PUT" => {
                let url =
                    url::Url::parse(&format!("http://example.invalid{}", request.path)).unwrap();
                let digest = url
                    .query_pairs()
                    .find(|(key, _)| key == "digest")
                    .unwrap()
                    .1
                    .into_owned();
                let mut bytes = state.uploads.remove(url.path()).unwrap();
                if !request.body.is_empty() {
                    assert_eq!(
                        request.headers["content-range"],
                        format!("{}-{}", bytes.len(), bytes.len() + request.body.len() - 1)
                    );
                    bytes.extend_from_slice(&request.body);
                }
                assert_eq!(Digest::sha256(&bytes).to_string(), digest);
                state.blobs.insert(digest, bytes);
                Response::new(if committed() { 201 } else { 500 }, vec![])
            }
            "GET" => Response::new(404, vec![]),
            _ => panic!("unexpected upload method: {}", request.method),
        }
    })
}

fn copy(harness: &Harness, source: &Server, target: &Server, exit: i32) -> Value {
    let mut child = harness
        .command(&[
            "--json",
            "image",
            "copy",
            &format!("{}/app:v1", source.host),
            &format!("{}/app:v1", target.host),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("transfer pipeline stalled");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(exit),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_dir(harness.root.path().join("tmp"))
            .unwrap()
            .count(),
        0,
        "temporary blobs must be removed"
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn download_continues_while_upload_waits_and_large_blobs_go_first() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 2, 8192);
    // An artifact uses the same transfer pipeline without a preliminary image-config fetch.
    let mut manifest: Value = serde_json::from_slice(&image.manifest).unwrap();
    manifest["artifactType"] = json!("application/example");
    let manifest = serde_json::to_vec(&manifest).unwrap();
    let fetched = Arc::new((Mutex::new(Vec::<usize>::new()), Condvar::new()));
    let observed = fetched.clone();
    let source = Server::new(move |request| {
        if request.path.contains("/manifests/") {
            return Response::new(200, manifest.clone())
                .header("Content-Type", quayside::model::OCI_MANIFEST);
        }
        let bytes = image.blobs[request.path.rsplit('/').next().unwrap()].clone();
        observed.0.lock().unwrap().push(bytes.len());
        observed.1.notify_all();
        Response::new(200, bytes)
    });
    let overlap = fetched.clone();
    let target = destination(move |_| {
        let (seen, timeout) = overlap
            .1
            .wait_timeout_while(overlap.0.lock().unwrap(), Duration::from_secs(3), |seen| {
                seen.len() < 2
            })
            .unwrap();
        !timeout.timed_out() && seen.len() >= 2
    });
    let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    harness.config.transfer.concurrency = 1;
    let result = copy(&harness, &source, &target, 0);
    assert_eq!(result["data"]["stats"]["copied_blobs"], 3);
    let sizes = fetched.0.lock().unwrap();
    assert_eq!(&sizes[..2], &[8192, 8192]);
    assert!(sizes[2] < 8192);
}

#[test]
fn quota_smaller_than_all_blobs_does_not_deadlock() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 4, 8192);
    let total: usize = image.blobs.values().map(Vec::len).sum();
    let source = Server::new(move |request| {
        if request.path.contains("/manifests/") {
            Response::new(200, image.manifest.clone())
                .header("Content-Type", quayside::model::OCI_MANIFEST)
        } else {
            Response::new(
                200,
                image.blobs[request.path.rsplit('/').next().unwrap()].clone(),
            )
        }
    });
    let target = destination(|_| true);
    let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    harness.config.transfer.concurrency = 2;
    harness.config.transfer.max_temp_size = "8KiB".into();
    let result = copy(&harness, &source, &target, 0);
    assert_eq!(result["data"]["stats"]["copied_blobs"], 5);
    assert_eq!(
        result["data"]["stats"]["bytes_transferred"],
        total as u64 * 2
    );
}

#[test]
fn failed_upload_cancels_pipeline_and_removes_staged_files() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 6, 8192);
    let source = Server::new(move |request| {
        if request.path.contains("/manifests/") {
            Response::new(200, image.manifest.clone())
                .header("Content-Type", quayside::model::OCI_MANIFEST)
        } else {
            Response::new(
                200,
                image.blobs[request.path.rsplit('/').next().unwrap()].clone(),
            )
        }
    });
    let patches = Arc::new(AtomicUsize::new(0));
    let seen = patches.clone();
    let target = destination(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        false
    });
    let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    harness.config.transfer.concurrency = 1;
    let result = copy(&harness, &source, &target, 9);
    assert!(
        result["data"]["remote_writes_may_have_occurred"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(patches.load(Ordering::SeqCst), 1);
}

#[test]
fn corrupt_download_is_never_queued_for_upload() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 1, 8192);
    let mut manifest: Value = serde_json::from_slice(&image.manifest).unwrap();
    manifest["artifactType"] = json!("application/example");
    let manifest = serde_json::to_vec(&manifest).unwrap();
    let source = Server::new(move |request| {
        if request.path.contains("/manifests/") {
            Response::new(200, manifest.clone())
                .header("Content-Type", quayside::model::OCI_MANIFEST)
        } else {
            let mut bytes = image.blobs[request.path.rsplit('/').next().unwrap()].clone();
            bytes[0] ^= 1;
            Response::new(200, bytes)
        }
    });
    let writes = Arc::new(AtomicUsize::new(0));
    let seen = writes.clone();
    let target = Server::new(move |request| {
        if !matches!(request.method.as_str(), "GET" | "HEAD") {
            seen.fetch_add(1, Ordering::SeqCst);
        }
        Response::new(404, vec![])
    });
    let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    harness.config.transfer.concurrency = 1;
    let result = copy(&harness, &source, &target, 7);
    assert_eq!(result["error"]["code"], "INTEGRITY");
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}

#[test]
fn shared_inline_blobs_are_preserved_and_validated_before_transfer() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    for corrupt in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let image = image_layout(root.path(), 1, 8192);
        let mut manifest: Value = serde_json::from_slice(&image.manifest).unwrap();
        manifest["artifactType"] = json!("application/example");
        let config = &image.blobs[manifest["config"]["digest"].as_str().unwrap()];
        manifest["config"]["data"] = json!(STANDARD.encode(config));
        let mut inline = manifest["layers"][0].clone();
        let mut bytes = image.blobs[inline["digest"].as_str().unwrap()].clone();
        if corrupt {
            bytes[0] ^= 1;
        }
        inline["data"] = json!(STANDARD.encode(bytes));
        manifest["layers"].as_array_mut().unwrap().push(inline);
        let manifest = serde_json::to_vec(&manifest).unwrap();
        let blob_reads = Arc::new(AtomicUsize::new(0));
        let reads = blob_reads.clone();
        let source = Server::new(move |request| {
            if request.path.contains("/manifests/") {
                Response::new(200, manifest.clone())
                    .header("Content-Type", quayside::model::OCI_MANIFEST)
            } else {
                reads.fetch_add(1, Ordering::SeqCst);
                Response::new(404, vec![])
            }
        });
        let target = destination(|_| true);
        let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
        let result = copy(&harness, &source, &target, if corrupt { 7 } else { 0 });
        assert_eq!(blob_reads.load(Ordering::SeqCst), 0);
        if corrupt {
            assert_eq!(result["error"]["code"], "INTEGRITY");
            assert_eq!(result["data"]["remote_writes_may_have_occurred"], false);
            assert_eq!(target.connections.load(Ordering::SeqCst), 1);
        } else {
            assert_eq!(result["data"]["stats"]["copied_blobs"], 2);
        }
    }
}

#[test]
fn uploads_commit_the_final_chunk_and_reuse_verified_config() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 1, 1024 * 1024);
    let reads = Arc::new(Mutex::new(BTreeMap::<String, usize>::new()));
    let observed = reads.clone();
    let source = Server::new(move |request| {
        if request.path.contains("/manifests/") {
            return Response::new(200, image.manifest.clone())
                .header("Content-Type", quayside::model::OCI_MANIFEST);
        }
        let digest = request.path.rsplit('/').next().unwrap();
        *observed.lock().unwrap().entry(digest.into()).or_default() += 1;
        Response::new(200, image.blobs[digest].clone())
    });
    let writes = Arc::new(Mutex::new(Vec::new()));
    let observed = writes.clone();
    let target = destination(move |request| {
        observed
            .lock()
            .unwrap()
            .push((request.method.clone(), request.body.len()));
        true
    });
    let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    harness.config.transfer.concurrency = 1;
    copy(&harness, &source, &target, 0);
    assert!(reads.lock().unwrap().values().all(|reads| *reads == 1));
    let writes = writes.lock().unwrap();
    let layer: Vec<_> = writes
        .iter()
        .filter(|(_, size)| *size >= 65536)
        .cloned()
        .collect();
    // Exact growth depends on request latency; correctness must also hold on slow CI runners.
    assert_eq!(layer.first().unwrap(), &("PATCH".into(), 65536));
    assert_eq!(layer.last().unwrap().0, "PUT");
    assert_eq!(
        layer.iter().map(|(_, size)| size).sum::<usize>(),
        1024 * 1024
    );
    assert_eq!(
        writes.iter().filter(|(method, _)| method == "PUT").count(),
        2
    );
}

#[test]
fn lost_commit_response_checks_the_blob_before_reuploading() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 1, 8192);
    let source = Server::new(move |request| {
        if request.path.contains("/manifests/") {
            Response::new(200, image.manifest.clone())
                .header("Content-Type", quayside::model::OCI_MANIFEST)
        } else {
            Response::new(
                200,
                image.blobs[request.path.rsplit('/').next().unwrap()].clone(),
            )
        }
    });
    let commits = Arc::new(AtomicUsize::new(0));
    let observed = commits.clone();
    let target = destination_with_commit(
        |_| true,
        move || {
            // Persist the blob but fail to report success on the first commit.
            observed.fetch_add(1, Ordering::SeqCst) != 0
        },
    );
    let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    harness.config.transfer.max_retries = 1;
    harness.config.transfer.concurrency = 1;
    copy(&harness, &source, &target, 0);
    assert_eq!(commits.load(Ordering::SeqCst), 2);
}

fn interrupted_download(mode: &str, exit: i32) {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 1, 8192);
    let mode = mode.to_owned();
    let ranges = Arc::new(Mutex::new(Vec::new()));
    let observed = ranges.clone();
    let requests = Arc::new(AtomicUsize::new(0));
    let seen = requests.clone();
    let source = Server::new(move |request| {
        if request.path.contains("/manifests/") {
            return Response::new(200, image.manifest.clone())
                .header("Content-Type", quayside::model::OCI_MANIFEST);
        }
        let bytes = &image.blobs[request.path.rsplit('/').next().unwrap()];
        if bytes.len() != 8192 {
            return Response::new(200, bytes.clone());
        }
        let range = request.headers.get("range").cloned();
        observed.lock().unwrap().push(range);
        if seen.fetch_add(1, Ordering::SeqCst) == 0 {
            return Response::new(200, bytes[..4096].to_vec()).header("Content-Length", "8192");
        }
        match mode.as_str() {
            "ignore" => Response::new(200, bytes.clone()),
            "invalid" => Response::new(206, bytes[4096..].to_vec())
                .header("Content-Range", "bytes 0-4095/8192"),
            "corrupt" => {
                let mut body = bytes[4096..].to_vec();
                body[0] ^= 1;
                Response::new(206, body).header("Content-Range", "bytes 4096-8191/8192")
            }
            _ => Response::new(206, bytes[4096..].to_vec())
                .header("Content-Range", "bytes 4096-8191/8192"),
        }
    });
    let target = destination(|_| true);
    let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    harness.config.transfer.max_retries = 1;
    harness.config.transfer.concurrency = 1;
    let result = copy(&harness, &source, &target, exit);
    assert_eq!(
        *ranges.lock().unwrap(),
        vec![None, Some("bytes=4096-8191".into())]
    );
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    if exit == 7 {
        assert_eq!(result["error"]["code"], "INTEGRITY");
    }
}

#[test]
fn interrupted_download_resumes_verified_bytes() {
    interrupted_download("resume", 0);
}

#[test]
fn ignored_range_restarts_and_verifies_the_full_blob() {
    interrupted_download("ignore", 0);
}

#[test]
fn invalid_range_is_rejected() {
    interrupted_download("invalid", 7);
}

#[test]
fn corrupt_resumed_bytes_are_rejected() {
    interrupted_download("corrupt", 7);
}

fn parallel_authentication(reject_first_token: bool) {
    use base64::Engine;
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 4, 8192);
    let mut manifest: Value = serde_json::from_slice(&image.manifest).unwrap();
    manifest["artifactType"] = json!("application/example");
    let config = manifest["config"]["digest"].as_str().unwrap().to_owned();
    manifest["config"]["data"] =
        json!(base64::engine::general_purpose::STANDARD.encode(&image.blobs[&config]));
    let manifest = serde_json::to_vec(&manifest).unwrap();
    let tokens = Arc::new(AtomicUsize::new(0));
    let issued = tokens.clone();
    let initial = (Mutex::new(0), Condvar::new());
    let rejected = (Mutex::new(0), Condvar::new());
    let source = Server::new(move |request| {
        if request.path.starts_with("/token") {
            let token = if issued.fetch_add(1, Ordering::SeqCst) == 0 && reject_first_token {
                "expired-token"
            } else {
                "valid-token"
            };
            return Response::new(
                200,
                serde_json::to_vec(&json!({"token":token,"expires_in":60})).unwrap(),
            );
        }
        if request.path.contains("/manifests/") {
            return Response::new(200, manifest.clone())
                .header("Content-Type", quayside::model::OCI_MANIFEST);
        }
        let auth = request.headers.get("authorization").map(String::as_str);
        if auth == Some("Bearer valid-token") {
            return Response::new(
                200,
                image.blobs[request.path.rsplit('/').next().unwrap()].clone(),
            );
        }
        // Force all four downloads to observe the same missing/rejected credential.
        let gate = if auth.is_none() { &initial } else { &rejected };
        let mut count = gate.0.lock().unwrap();
        *count += 1;
        gate.1.notify_all();
        let (_count, timeout) = gate
            .1
            .wait_timeout_while(count, Duration::from_secs(3), |n| *n < 4)
            .unwrap();
        assert!(
            !timeout.timed_out(),
            "blob requests should authenticate concurrently"
        );
        Response::new(401, vec![]).header(
            "WWW-Authenticate",
            &format!(
                "Bearer realm=\"http://{}/token\",service=\"fixture\"",
                request.headers["host"]
            ),
        )
    });
    let target = destination(|_| true);
    let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    copy(&harness, &source, &target, 0);
    assert_eq!(
        tokens.load(Ordering::SeqCst),
        if reject_first_token { 2 } else { 1 }
    );
}

#[test]
fn concurrent_blob_requests_share_one_token_exchange() {
    parallel_authentication(false);
}

#[test]
fn concurrent_rejected_tokens_are_refreshed_once() {
    parallel_authentication(true);
}

#[test]
#[ignore = "local timing benchmark; optionally set QUAYSIDE_TEST_BINARY to compare builds"]
fn copy_latency_benchmark() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 1, 32 * 1024 * 1024);
    let source = Server::new(move |request| {
        if request.path.contains("/manifests/") {
            Response::new(200, image.manifest.clone())
                .header("Content-Type", quayside::model::OCI_MANIFEST)
        } else {
            Response::new(
                200,
                image.blobs[request.path.rsplit('/').next().unwrap()].clone(),
            )
        }
    });
    let chunks = Arc::new(AtomicUsize::new(0));
    let observed = chunks.clone();
    let target = destination(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(80));
        true
    });
    let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    harness.config.transfer.concurrency = 1;
    harness.config.transfer.chunk_size = "1MiB".into();
    let start = Instant::now();
    copy(&harness, &source, &target, 0);
    println!(
        "32MiB layer, 80ms latency per payload request, 1MiB initial chunk: elapsed={:?}, payload_requests={}",
        start.elapsed(),
        chunks.load(Ordering::SeqCst)
    );
}

fn range_copy(mode: &'static str, layers: usize, chunk_delay: Duration) -> Duration {
    use quayside::model::{Descriptor, OCI_MANIFEST};
    let root = tempfile::tempdir().unwrap();
    let mut image = image_layout(root.path(), 0, 0);
    let mut manifest: Value = serde_json::from_slice(&image.manifest).unwrap();
    let size = 32 * 1024 * 1024;
    for layer in 0..layers {
        let body: Vec<_> = (0..size)
            .map(|i| ((i / 65536 + layer) % 251) as u8)
            .collect();
        let d = Descriptor::new(
            "application/vnd.oci.image.layer.v1.tar",
            Digest::sha256(&body),
            size as u64,
        );
        image.blobs.insert(d.digest.to_string(), body);
        manifest["layers"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::to_value(d).unwrap());
    }
    let config = manifest["config"]["digest"].as_str().unwrap().to_owned();
    let config_size = manifest["config"]["size"].as_u64().unwrap();
    image.manifest = serde_json::to_vec(&manifest).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    let peak = Arc::new(AtomicUsize::new(0));
    let measured = peak.clone();
    let active = AtomicUsize::new(0);
    let truncated = std::sync::atomic::AtomicBool::new(false);
    let source = Server::new(move |request| {
        if request.path.contains("/manifests/") {
            return Response::new(200, image.manifest.clone()).header("Content-Type", OCI_MANIFEST);
        }
        let bytes = &image.blobs[request.path.rsplit('/').next().unwrap()];
        if bytes.len() != size {
            return Response::new(200, bytes.clone());
        }
        let range = request.headers.get("range").map(|range| {
            let (start, end) = range
                .strip_prefix("bytes=")
                .unwrap()
                .split_once('-')
                .unwrap();
            start.parse::<usize>().unwrap()..end.parse::<usize>().unwrap() + 1
        });
        observed.lock().unwrap().push(range.clone());
        measured.fetch_max(active.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(30));
        active.fetch_sub(1, Ordering::SeqCst);
        let mut response = match range {
            None => Response::new(200, bytes.clone()),
            Some(_) if mode == "ignore" => Response::new(200, bytes.clone()),
            Some(_) if mode == "reject" => Response::new(416, vec![]),
            Some(range) if mode == "mixed" && range.start > 0 => Response::new(200, bytes.clone()),
            Some(range) => {
                let mut body = bytes[range.clone()].to_vec();
                if mode == "corrupt" {
                    body[0] ^= 1;
                }
                if mode == "resume" && !truncated.swap(true, Ordering::SeqCst) {
                    body.truncate(1024 * 1024);
                }
                Response::new(206, body)
                    .header("Content-Length", &range.len().to_string())
                    .header(
                        "Content-Range",
                        &if mode == "invalid" {
                            format!("bytes {}-{}/{}", range.start + 1, range.end - 1, size)
                        } else {
                            format!("bytes {}-{}/{}", range.start, range.end - 1, size)
                        },
                    )
            }
        };
        response.chunk_delay = chunk_delay;
        response
    });
    let failed = matches!(mode, "corrupt" | "invalid");
    let writes = Arc::new(AtomicUsize::new(0));
    let seen = writes.clone();
    let target = if failed {
        Server::new(move |request| {
            if !matches!(request.method.as_str(), "GET" | "HEAD") {
                seen.fetch_add(1, Ordering::SeqCst);
            }
            if request.method == "HEAD" && request.path.ends_with(&config) {
                Response::new(200, vec![]).header("Content-Length", &config_size.to_string())
            } else {
                Response::new(404, vec![])
            }
        })
    } else {
        destination(|_| true)
    };
    let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    harness.config.transfer.chunk_size = "8MiB".into();
    harness.config.transfer.idle_timeout = "10s".into();
    harness.config.transfer.max_retries = usize::from(mode == "resume");
    let start = Instant::now();
    let result = copy(&harness, &source, &target, if failed { 7 } else { 0 });
    let elapsed = start.elapsed();
    let requests = requests.lock().unwrap();
    if mode != "benchmark" {
        match mode {
            "ignore" => assert_eq!(requests.len(), 1), // Reuse the ignored Range's full response.
            "reject" => assert_eq!(requests.len(), 2),
            "mixed" => assert_eq!(requests.len(), 5),
            "resume" => {
                assert_eq!(requests.len(), 5);
                assert!(
                    requests
                        .iter()
                        .flatten()
                        .any(|range| range.start == 1024 * 1024)
                );
            }
            "valid" => {
                assert_eq!(requests.len(), 4 * layers);
                assert!(
                    peak.load(Ordering::SeqCst) > 1,
                    "range requests must overlap"
                );
            }
            _ => {}
        }
        assert!(peak.load(Ordering::SeqCst) <= harness.config.transfer.concurrency);
    }
    if failed {
        assert_eq!(result["error"]["code"], "INTEGRITY");
        assert_eq!(
            writes.load(Ordering::SeqCst),
            0,
            "unverified layer must never be uploaded"
        );
    } else {
        assert_eq!(result["data"]["stats"]["copied_blobs"], layers + 1);
    }
    println!(
        "range mode={mode}, elapsed={elapsed:?}, layer_requests={}, peak_requests={}",
        requests.len(),
        peak.load(Ordering::SeqCst)
    );
    elapsed
}

#[test]
fn parallel_ranges_share_the_download_limit_across_blobs() {
    range_copy("valid", 2, Duration::ZERO);
}

#[test]
fn parallel_ranges_resume_only_the_missing_part_bytes() {
    range_copy("resume", 1, Duration::ZERO);
}

#[test]
fn parallel_ranges_fall_back_without_duplicate_full_downloads() {
    for mode in ["ignore", "reject", "mixed"] {
        range_copy(mode, 1, Duration::ZERO);
    }
}

#[test]
fn parallel_ranges_verify_full_digest_and_response_boundaries_before_upload() {
    for mode in ["corrupt", "invalid"] {
        range_copy(mode, 1, Duration::ZERO);
    }
}

#[test]
#[ignore = "local per-connection throughput benchmark; optionally set QUAYSIDE_TEST_BINARY"]
fn copy_range_throughput_benchmark() {
    range_copy("benchmark", 1, Duration::from_millis(4));
}

#[test]
fn index_create_downloads_next_source_while_previous_source_uploads() {
    let root = tempfile::tempdir().unwrap();
    let fetched = Arc::new((Mutex::new(0usize), Condvar::new()));
    let source = |arch: &str, size| {
        let image = support::image_layout_for(&root.path().join(arch), 1, size, arch);
        let fetched = fetched.clone();
        Server::new(move |request| {
            if request.path.contains("/manifests/") {
                return Response::new(200, image.manifest.clone())
                    .header("Content-Type", quayside::model::OCI_MANIFEST);
            }
            let body = image.blobs[request.path.rsplit('/').next().unwrap()].clone();
            if body.len() == size {
                *fetched.0.lock().unwrap() += 1;
                fetched.1.notify_all();
            }
            Response::new(200, body)
        })
    };
    let first = source("amd64", 8192);
    let second = source("arm64", 16384);
    let observed = fetched.clone();
    let target = destination(move |_| {
        let (seen, timeout) = observed
            .1
            .wait_timeout_while(observed.0.lock().unwrap(), Duration::from_secs(3), |seen| {
                *seen < 2
            })
            .unwrap();
        !timeout.timed_out() && *seen == 2
    });
    let mut harness = Harness::new(&[
        (&first.host, true),
        (&second.host, true),
        (&target.host, true),
    ]);
    harness.config.transfer.concurrency = 1;
    harness.config.transfer.idle_timeout = "5s".into();
    let result = harness.json(
        &[
            "index",
            "create",
            &format!("{}/app:multi", target.host),
            "--from",
            &format!("{}/app:v1", first.host),
            "--from",
            &format!("{}/app:v1", second.host),
        ],
        0,
    );
    assert_eq!(result["data"]["stats"]["copied_blobs"], 4);
    assert_eq!(*fetched.0.lock().unwrap(), 2);
    assert_eq!(
        fs::read_dir(harness.root.path().join("tmp"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn interrupted_parallel_download_cleans_temporary_files_without_uploading() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 1, 32 * 1024 * 1024);
    let manifest: Value = serde_json::from_slice(&image.manifest).unwrap();
    let config = manifest["config"]["digest"].as_str().unwrap().to_owned();
    let config_size = manifest["config"]["size"].as_u64().unwrap();
    let ranges = Arc::new(AtomicUsize::new(0));
    let seen = ranges.clone();
    let source = Server::new(move |request| {
        if request.path.contains("/manifests/") {
            return Response::new(200, image.manifest.clone())
                .header("Content-Type", quayside::model::OCI_MANIFEST);
        }
        let bytes = &image.blobs[request.path.rsplit('/').next().unwrap()];
        let Some(range) = request.headers.get("range") else {
            return Response::new(200, bytes.clone());
        };
        let (start, end) = range
            .strip_prefix("bytes=")
            .unwrap()
            .split_once('-')
            .unwrap();
        let start = start.parse::<usize>().unwrap();
        let end = end.parse::<usize>().unwrap();
        seen.fetch_add(1, Ordering::SeqCst);
        let mut response = Response::new(206, bytes[start..=end].to_vec()).header(
            "Content-Range",
            &format!("bytes {start}-{end}/{}", bytes.len()),
        );
        response.chunk_delay = Duration::from_millis(4);
        response
    });
    let target = Server::new(move |request| {
        assert!(matches!(request.method.as_str(), "GET" | "HEAD"));
        if request.method == "HEAD" && request.path.ends_with(&config) {
            Response::new(200, vec![]).header("Content-Length", &config_size.to_string())
        } else {
            Response::new(404, vec![])
        }
    });
    let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    let mut child = harness
        .command(&[
            "--json",
            "image",
            "copy",
            &format!("{}/app:v1", source.host),
            &format!("{}/app:v1", target.host),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while ranges.load(Ordering::SeqCst) < 3 {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("parallel downloads did not start");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        std::process::Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(130),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["error"]["code"], "INTERRUPTED");
    assert_eq!(result["data"]["remote_writes_may_have_occurred"], false);
    assert_eq!(
        fs::read_dir(harness.root.path().join("tmp"))
            .unwrap()
            .count(),
        0
    );
}
