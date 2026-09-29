use super::*;
use std::sync::atomic::AtomicBool;

#[test]
fn resumes_partial_download_in_a_new_process_and_checks_cached_bytes() {
    for (corrupt, pull) in [(false, false), (true, false), (false, true)] {
        let root = tempfile::tempdir().unwrap();
        let image = image_layout(root.path(), 1, 512 * 1024);
        let fail = Arc::new(AtomicBool::new(true));
        let broken = fail.clone();
        let ranges = Arc::new(Mutex::new(Vec::new()));
        let seen = ranges.clone();
        let source = Server::new(move |request| {
            if request.path.contains("/manifests/") {
                return Response::new(200, image.manifest.clone())
                    .header("Content-Type", quayside::model::OCI_MANIFEST);
            }
            let raw = &image.blobs[request.path.rsplit('/').next().unwrap()];
            if raw.len() < 512 * 1024 {
                return Response::new(200, raw.clone());
            }
            if broken.load(Ordering::SeqCst) {
                return Response::new(200, raw[..128 * 1024].to_vec())
                    .header("Content-Length", &raw.len().to_string());
            }
            match request.headers.get("range") {
                Some(range) => {
                    seen.lock().unwrap().push(range.clone());
                    let start: usize = range
                        .strip_prefix("bytes=")
                        .unwrap()
                        .split('-')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    Response::new(206, raw[start..].to_vec()).header(
                        "Content-Range",
                        &format!("bytes {}-{}/{}", start, raw.len() - 1, raw.len()),
                    )
                }
                None => Response::new(200, raw.clone()),
            }
        });
        let target = destination(|_| true);
        let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
        harness.config.transfer.resume_dir = Some(harness.root.path().join("resume"));
        let src = format!("{}/app:v1", source.host);
        let dst = format!("{}/app:v1", target.host);
        let output_path = harness.root.path().join("resumed.tar");
        let args = if pull {
            vec![
                "image",
                "pull",
                &src,
                "-o",
                output_path.to_str().unwrap(),
                "--resume",
            ]
        } else {
            vec!["image", "copy", &src, &dst, "--resume"]
        };
        let output = harness.command(&args).output().unwrap();
        assert!(!output.status.success());
        let directory = fs::read_dir(harness.root.path().join("resume"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        if corrupt {
            let path = fs::read_dir(&directory)
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| {
                    p.extension().is_some_and(|e| e == "blob")
                        && fs::metadata(p).unwrap().len() == 128 * 1024
                })
                .unwrap();
            use std::io::Write;
            fs::OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap()
                .write_all(b"bad!")
                .unwrap();
        }
        fail.store(false, Ordering::SeqCst);
        if corrupt {
            let output = harness
                .command(&["--json", "image", "copy", &src, &dst, "--resume"])
                .output()
                .unwrap();
            let value: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(value["error"]["code"], "INTEGRITY");
        }
        harness.json(&args, 0);
        assert_eq!(ranges.lock().unwrap()[0], "bytes=131072-524287");
        assert!(
            fs::read_dir(directory)
                .unwrap()
                .all(|e| e.unwrap().file_name() == "lock")
        );
    }
}

#[test]
fn resumes_upload_session_without_downloading_again() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 1, 512 * 1024);
    let fetched = Arc::new(AtomicUsize::new(0));
    let fetched_in = fetched.clone();
    let source = Server::new(move |request| {
        if request.path.contains("/manifests/") {
            return Response::new(200, image.manifest.clone())
                .header("Content-Type", quayside::model::OCI_MANIFEST);
        }
        let raw = image.blobs[request.path.rsplit('/').next().unwrap()].clone();
        if raw.len() == 512 * 1024 {
            fetched_in.fetch_add(1, Ordering::SeqCst);
        }
        Response::new(200, raw)
    });
    let fail = Arc::new(AtomicBool::new(true));
    let broken = fail.clone();
    let sessions = Arc::new(AtomicUsize::new(0));
    let starts = sessions.clone();
    let status = Arc::new(AtomicUsize::new(0));
    let statuses = status.clone();
    let state = Mutex::new(Store::default());
    let target = Server::new(move |request| {
        let mut state = state.lock().unwrap();
        if request.path.contains("/manifests/") {
            if request.method == "PUT" {
                state.manifests.insert(request.path, request.body);
                return Response::new(201, vec![]);
            }
            return state
                .manifests
                .get(&request.path)
                .map(|b| {
                    Response::new(200, b.clone())
                        .header("Content-Type", quayside::model::OCI_MANIFEST)
                })
                .unwrap_or_else(|| Response::new(404, vec![]));
        }
        if request.method == "HEAD" {
            return state
                .blobs
                .get(request.path.rsplit('/').next().unwrap())
                .map(|b| Response::new(200, vec![]).header("Content-Length", &b.len().to_string()))
                .unwrap_or_else(|| Response::new(404, vec![]));
        }
        if request.method == "POST" {
            let id = starts.fetch_add(1, Ordering::SeqCst);
            let path = format!("/v2/app/blobs/uploads/{id}");
            state.uploads.insert(path.clone(), vec![]);
            return Response::new(202, vec![]).header("Location", &path);
        }
        let url = url::Url::parse(&format!("http://example.invalid{}", request.path)).unwrap();
        let bytes = state.uploads.get_mut(url.path()).unwrap();
        if request.method == "GET" {
            statuses.fetch_add(1, Ordering::SeqCst);
            assert_eq!(bytes.len(), 65536);
            return Response::new(204, vec![])
                .header("Location", url.path())
                .header("Range", "0-65535");
        }
        if broken.load(Ordering::SeqCst) && !bytes.is_empty() {
            return Response::new(500, vec![]);
        }
        assert_eq!(
            request.headers["content-range"],
            format!("{}-{}", bytes.len(), bytes.len() + request.body.len() - 1)
        );
        bytes.extend_from_slice(&request.body);
        if request.method == "PATCH" {
            return Response::new(202, vec![]).header("Location", url.path());
        }
        let digest = url
            .query_pairs()
            .find(|(k, _)| k == "digest")
            .unwrap()
            .1
            .into_owned();
        assert_eq!(Digest::sha256(bytes).to_string(), digest);
        let bytes = state.uploads.remove(url.path()).unwrap();
        state.blobs.insert(digest, bytes);
        Response::new(201, vec![])
    });
    let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    harness.config.transfer.resume_dir = Some(harness.root.path().join("resume"));
    let src = format!("{}/app:v1", source.host);
    let dst = format!("{}/app:v1", target.host);
    let args = ["image", "copy", &src, &dst, "--resume"];
    harness.json(&args, 9);
    let before = sessions.load(Ordering::SeqCst);
    fail.store(false, Ordering::SeqCst);
    harness.json(&args, 0);
    assert_eq!(fetched.load(Ordering::SeqCst), 1);
    assert_eq!(sessions.load(Ordering::SeqCst), before);
    assert_eq!(status.load(Ordering::SeqCst), 1);
}

#[test]
fn resumes_parallel_ranges_and_remembers_servers_without_range_support() {
    for supports_range in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let image = image_layout(root.path(), 1, 32 * 1024 * 1024);
        let fail = Arc::new(AtomicBool::new(true));
        let broken = fail.clone();
        let offsets = Arc::new(Mutex::new(Vec::new()));
        let seen = offsets.clone();
        let source = Server::new(move |request| {
            if request.path.contains("/manifests/") {
                return Response::new(200, image.manifest.clone())
                    .header("Content-Type", quayside::model::OCI_MANIFEST);
            }
            let raw = &image.blobs[request.path.rsplit('/').next().unwrap()];
            if raw.len() < 1024 {
                return Response::new(200, raw.clone());
            }
            let range = request.headers.get("range").map(|value| {
                let (start, end) = value
                    .strip_prefix("bytes=")
                    .unwrap()
                    .split_once('-')
                    .unwrap();
                (
                    start.parse::<usize>().unwrap(),
                    end.parse::<usize>().unwrap() + 1,
                )
            });
            let failing = broken.load(Ordering::SeqCst);
            let (start, end) = if supports_range || !failing {
                range.unwrap_or((0, raw.len()))
            } else {
                (0, raw.len())
            };
            if !failing {
                seen.lock().unwrap().push(start);
            }
            let bytes = &raw[start..if failing { start + 128 * 1024 } else { end }];
            let partial = range.is_some() && (supports_range || !failing);
            let mut response = Response::new(if partial { 206 } else { 200 }, bytes.to_vec())
                .header("Content-Length", &(end - start).to_string());
            if partial {
                response = response.header(
                    "Content-Range",
                    &format!("bytes {}-{}/{}", start, end - 1, raw.len()),
                );
            }
            response
        });
        let mut harness = Harness::new(&[(&source.host, true)]);
        harness.config.transfer.resume_dir = Some(harness.root.path().join("resume"));
        let src = format!("{}/app:v1", source.host);
        let output = harness.root.path().join("layout");
        let args = [
            "image",
            "pull",
            &src,
            "-o",
            output.to_str().unwrap(),
            "--format",
            "oci-layout",
            "--resume",
        ];
        harness.json(&args, 6);
        fail.store(false, Ordering::SeqCst);
        harness.json(&args, 0);
        let mut actual = offsets.lock().unwrap().clone();
        actual.sort();
        let expected: Vec<_> = (0..if supports_range { 4 } else { 1 })
            .map(|i| i * 8 * 1024 * 1024 + 128 * 1024)
            .collect();
        assert_eq!(actual, expected);
    }
}
