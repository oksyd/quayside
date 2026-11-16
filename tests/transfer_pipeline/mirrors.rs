use super::*;
use quayside::{
    auth::{AuthFile, Credential},
    model::OCI_MANIFEST,
};
use support::Image;

fn serve_image(image: &Image, request: &Request) -> Response {
    assert_eq!(request.method, "GET");
    if request.path.contains("/manifests/") {
        Response::new(200, image.manifest.clone()).header("Content-Type", OCI_MANIFEST)
    } else {
        let digest = request.path.rsplit('/').next().unwrap();
        Response::new(200, image.blobs[digest].clone())
    }
}

fn harness(origin: &Server, mirrors: &[String]) -> Harness {
    let harness = Harness::new(&[("docker.io", true)]);
    fs::write(
        harness.daemon_config(),
        serde_json::to_vec(&json!({
            "registry-mirrors": mirrors,
            "proxies": {
                "http-proxy": format!("http://{}", origin.host),
                "no-proxy": "127.0.0.1"
            }
        }))
        .unwrap(),
    )
    .unwrap();
    harness
}

fn pull(harness: &Harness, extra: &[&str], exit: i32) -> Value {
    let output = harness.root.path().join("image");
    let mut args = vec![
        "image",
        "pull",
        "nginx:v1",
        "-o",
        output.to_str().unwrap(),
        "--format",
        "oci-layout",
    ];
    args.extend(extra);
    harness.json(&args, exit)
}

#[test]
fn copy_and_pull_use_docker_mirrors_without_contacting_hub_or_rewriting_sources() {
    for copying in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let image = image_layout(root.path(), 2, 8192);
        let digest = image.digest.clone();
        let mirror = Server::new(move |request| {
            assert!(request.path.starts_with("/v2/library/nginx/"));
            serve_image(&image, &request)
        });
        let origin = Server::new(|_| Response::new(500, vec![]));
        let target = destination(|_| true);
        let mut harness = harness(&origin, &[format!("http://{}", mirror.host)]);
        harness.config.registries.insert(
            target.host.clone(),
            quayside::config::RegistryConfig {
                plain_http: true,
                ..Default::default()
            },
        );
        let result = if copying {
            harness.json(
                &[
                    "image",
                    "copy",
                    "nginx:v1",
                    &format!("{}/app:v1", target.host),
                ],
                0,
            )
        } else {
            pull(&harness, &[], 0)
        };
        assert_eq!(result["data"]["source"], "docker.io/library/nginx:v1");
        assert_eq!(result["data"]["target_digest"], digest);
        assert_eq!(origin.connections.load(Ordering::SeqCst), 0);
        assert!(mirror.connections.load(Ordering::SeqCst) >= 4);
    }
}

#[test]
fn mirrors_are_tried_in_order_and_missing_content_falls_back_to_the_origin() {
    for status in [404, 403, 503] {
        let root = tempfile::tempdir().unwrap();
        let image = Arc::new(image_layout(root.path(), 2, 1024));
        let original = image.clone();
        let origin = Server::new(move |request| {
            assert!(
                request
                    .path
                    .starts_with("http://registry-1.docker.io/v2/library/nginx/")
            );
            serve_image(&original, &request)
        });
        let missing = Server::new(move |_| Response::new(status, vec![]));
        let cached = image.clone();
        let partial = Server::new(move |request| {
            if request.path.contains("/manifests/") {
                serve_image(&cached, &request)
            } else {
                Response::new(404, vec![])
            }
        });
        let harness = harness(
            &origin,
            &[
                format!("http://{}", missing.host),
                format!("http://{}", partial.host),
            ],
        );
        let result = pull(&harness, &[], 0);
        assert_eq!(result["data"]["target_digest"], image.digest);
        assert!(partial.connections.load(Ordering::SeqCst) >= 1);
        assert_eq!(origin.connections.load(Ordering::SeqCst), 3);
        if status == 503 {
            assert_eq!(missing.connections.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn interrupted_mirror_downloads_fail_over_and_preserve_verified_resume_offsets() {
    for resume in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let image = Arc::new(image_layout(root.path(), 1, 512 * 1024));
        let original = image.clone();
        let range_seen = Arc::new(Mutex::new(None));
        let ranges = range_seen.clone();
        let origin = Server::new(move |request| {
            let raw = &original.blobs[request.path.rsplit('/').next().unwrap()];
            if let Some(range) = request.headers.get("range") {
                *ranges.lock().unwrap() = Some(range.clone());
                assert_eq!(range, "bytes=131072-524287");
                Response::new(206, raw[128 * 1024..].to_vec())
                    .header("Content-Range", "bytes 131072-524287/524288")
            } else {
                Response::new(200, raw.clone())
            }
        });
        let cached = image.clone();
        let mirror = Server::new(move |request| {
            let mut response = serve_image(&cached, &request);
            if response.body.len() == 512 * 1024 {
                response.body.truncate(128 * 1024);
                response = response.header("Content-Length", "524288");
            }
            response
        });
        let harness = harness(&origin, &[format!("http://{}", mirror.host)]);
        pull(&harness, if resume { &["--resume"] } else { &[] }, 0);
        assert_eq!(range_seen.lock().unwrap().is_some(), resume);
        let blob = image
            .blobs
            .iter()
            .find(|(_, raw)| raw.len() == 512 * 1024)
            .unwrap();
        assert_eq!(
            fs::read(
                harness
                    .root
                    .path()
                    .join("image/blobs/sha256")
                    .join(blob.0.strip_prefix("sha256:").unwrap())
            )
            .unwrap(),
            *blob.1
        );
    }
}

#[test]
fn mirror_credentials_stay_on_their_origin_and_hub_credentials_are_only_used_after_fallback() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let root = tempfile::tempdir().unwrap();
    let image = Arc::new(image_layout(root.path(), 1, 128));
    let hub_auth = format!("Basic {}", STANDARD.encode("hub-user:hub-secret"));
    let mirror_auth = format!("Basic {}", STANDARD.encode("mirror-user:mirror-secret"));
    let original = image.clone();
    let origin = Server::new(move |request| match request.headers.get("authorization") {
        None => Response::new(401, vec![]).header("WWW-Authenticate", "Basic realm=\"hub\""),
        Some(auth) => {
            assert_eq!(auth, &hub_auth);
            serve_image(&original, &request)
        }
    });
    let cached = image.clone();
    let mirror = Server::new(move |request| match request.headers.get("authorization") {
        None => Response::new(401, vec![]).header("WWW-Authenticate", "Basic realm=\"mirror\""),
        Some(auth) => {
            assert_eq!(auth, &mirror_auth);
            if request.path.contains("/manifests/") {
                serve_image(&cached, &request)
            } else {
                Response::new(404, vec![])
            }
        }
    });
    let anonymous = Server::new(|request| {
        assert!(!request.headers.contains_key("authorization"));
        Response::new(401, vec![]).header("WWW-Authenticate", "Basic realm=\"anonymous\"")
    });
    let harness = harness(
        &origin,
        &[
            format!("http://{}", anonymous.host),
            format!("http://{}", mirror.host),
        ],
    );
    for (host, username, secret) in [
        ("docker.io", "hub-user", "hub-secret"),
        (mirror.host.as_str(), "mirror-user", "mirror-secret"),
    ] {
        AuthFile::put(
            &harness.root.path().join("auth.json"),
            &harness.root.path().join("keys/master.key"),
            host,
            Credential {
                username: username.into(),
                secret: secret.into(),
            },
        )
        .unwrap();
    }
    let result = pull(&harness, &[], 0);
    assert_eq!(result["data"]["target_digest"], image.digest);
    assert!(origin.connections.load(Ordering::SeqCst) > 0);
    assert!(mirror.connections.load(Ordering::SeqCst) > 0);
}

#[test]
fn mirror_digest_mismatches_are_fatal_without_falling_back() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 0, 0);
    let mirror = Server::new(move |request| {
        let mut response = serve_image(&image, &request);
        if request.path.contains("/blobs/") {
            response.body.fill(b'x');
        }
        response
    });
    let origin = Server::new(|_| Response::new(500, vec![]));
    let harness = harness(&origin, &[format!("http://{}", mirror.host)]);
    let result = pull(&harness, &[], 7);
    assert_eq!(result["error"]["code"], "INTEGRITY");
    assert_eq!(origin.connections.load(Ordering::SeqCst), 0);
    assert!(!harness.root.path().join("image").exists());
}

#[test]
fn tag_queries_and_explicit_mirror_bypass_use_the_origin() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 0, 0);
    let origin = Server::new(move |request| {
        if request.path.contains("tags/list") {
            Response::new(200, br#"{"tags":["1.2.3"]}"#.to_vec())
        } else {
            serve_image(&image, &request)
        }
    });
    let mirror = Server::new(|_| Response::new(500, vec![]));
    let harness = harness(&origin, &[format!("http://{}", mirror.host)]);
    harness.json(&["tag", "ls", "nginx"], 0);
    harness.json(&["tag", "latest", "nginx"], 0);
    pull(&harness, &["--no-mirrors"], 0);
    assert_eq!(mirror.connections.load(Ordering::SeqCst), 0);
    assert!(origin.connections.load(Ordering::SeqCst) >= 4);
}

#[test]
fn mirror_notices_are_deduplicated_and_respect_quiet_and_json_output() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 2, 512);
    let mirror = Server::new(move |request| serve_image(&image, &request));
    let origin = Server::new(|_| Response::new(500, vec![]));
    let harness = harness(
        &origin,
        &[
            format!("http://{}", mirror.host),
            format!("http://{}/", mirror.host),
        ],
    );
    for flag in [None, Some("--quiet"), Some("--json")] {
        let mut args = vec!["image", "pull", "nginx:v1", "-o", "unused.tar", "--dry-run"];
        if let Some(flag) = flag {
            args.push(flag);
        }
        let output = harness.output(&args, 0);
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(
            stderr.matches("Using Docker Hub mirror").count(),
            usize::from(flag.is_none()),
            "{stderr}"
        );
        if flag.is_none() {
            assert!(stderr.contains(&mirror.host));
            assert!(stderr.contains("daemon.json"));
        }
        if flag == Some("--json") {
            let value: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(value["status"], "success");
        }
    }
    assert_eq!(origin.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn invalid_mirror_urls_are_rejected_without_requests_or_disclosing_secrets() {
    let origin = Server::new(|_| Response::new(500, vec![]));
    for url in [
        "not-a-url-secret",
        "ftp://secret.example",
        "https://user:secret@mirror.example",
        "https://mirror.example/private-secret",
        "https://mirror.example/?secret",
        "https://mirror.example/#secret",
    ] {
        let harness = harness(&origin, &[url.into()]);
        let result = pull(&harness, &[], 2);
        assert_eq!(result["error"]["code"], "INVALID_INPUT");
        assert!(!result.to_string().contains("secret"));
    }
    assert_eq!(origin.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn unreachable_mirror_uses_the_next_configured_mirror() {
    // Reserve the port without listening; refusal and timeout both permit mirror fallback.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 1, 128);
    let mirror = Server::new(move |request| serve_image(&image, &request));
    let origin = Server::new(|_| Response::new(500, vec![]));
    let harness = harness(
        &origin,
        &[
            format!("http://{}", socket.local_addr().unwrap()),
            format!("http://{}", mirror.host),
        ],
    );
    pull(&harness, &[], 0);
    assert_eq!(origin.connections.load(Ordering::SeqCst), 0);
    assert!(mirror.connections.load(Ordering::SeqCst) >= 3);
}

#[test]
fn mirror_certificate_errors_stop_without_contacting_other_sources() {
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    let mirror = Server::start(Some(Arc::new(tls)), |_| Response::new(500, vec![]));
    let origin = Server::new(|_| Response::new(500, vec![]));
    let harness = harness(&origin, &[format!("https://{}", mirror.host)]);
    let result = pull(&harness, &[], 6);
    assert_eq!(result["error"]["code"], "TLS_UNKNOWN_ISSUER");
    assert_eq!(mirror.connections.load(Ordering::SeqCst), 1);
    assert_eq!(origin.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn mirror_handles_do_not_change_writes_to_docker_hub_destinations() {
    let root = tempfile::tempdir().unwrap();
    let image = Arc::new(image_layout(root.path(), 1, 128));
    let cached = image.clone();
    let mirror = Server::new(move |request| {
        assert!(request.path.starts_with("/v2/library/nginx/"));
        serve_image(&cached, &request)
    });
    let original = image.clone();
    let stored = Arc::new(Mutex::new(None::<Vec<u8>>));
    let manifests = stored.clone();
    let origin = Server::new(move |request| {
        assert!(
            request
                .path
                .starts_with("http://registry-1.docker.io/v2/team/copy/")
        );
        match request.method.as_str() {
            "HEAD" => Response::new(200, vec![]).header(
                "Content-Length",
                &original.blobs[request.path.rsplit('/').next().unwrap()]
                    .len()
                    .to_string(),
            ),
            "GET" => manifests.lock().unwrap().as_ref().map_or_else(
                || Response::new(404, vec![]),
                |body| Response::new(200, body.clone()).header("Content-Type", OCI_MANIFEST),
            ),
            "PUT" => {
                assert_eq!(request.body, original.manifest);
                *manifests.lock().unwrap() = Some(request.body);
                Response::new(201, vec![])
            }
            _ => panic!("unexpected destination request"),
        }
    });
    let harness = harness(&origin, &[format!("http://{}", mirror.host)]);
    harness.json(&["image", "copy", "nginx:v1", "docker.io/team/copy:v1"], 0);
    assert_eq!(stored.lock().unwrap().as_ref(), Some(&image.manifest));
}

#[test]
fn referrer_discovery_and_fallback_tags_bypass_mirrors() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 0, 0);
    let mirror = Server::new(move |request| {
        assert!(!request.path.contains("/referrers/"));
        assert!(!request.path.contains("/manifests/sha256-"));
        serve_image(&image, &request)
    });
    let origin = Server::new(|request| {
        assert!(
            request.path.contains("/referrers/") || request.path.contains("/manifests/sha256-")
        );
        Response::new(404, vec![])
    });
    let harness = harness(&origin, &[format!("http://{}", mirror.host)]);
    pull(&harness, &["--referrers", "all"], 0);
    assert_eq!(origin.connections.load(Ordering::SeqCst), 2);
}

#[test]
fn parallel_mirror_failover_flushes_writers_and_never_hides_integrity_errors() {
    fn response(image: &Image, request: &Request, broken: bool, corrupt: bool) -> Response {
        let Some(range) = request.headers.get("range") else {
            return serve_image(image, request);
        };
        let (start, end) = range
            .strip_prefix("bytes=")
            .unwrap()
            .split_once('-')
            .unwrap();
        let start = start.parse::<usize>().unwrap();
        let end = end.parse::<usize>().unwrap();
        if broken && start == 8 * 1024 * 1024 {
            return Response::new(503, vec![]);
        }
        if corrupt && start == 16 * 1024 * 1024 {
            return Response::new(206, vec![]).header("Content-Range", "bytes 1-2/3");
        }
        let raw = &image.blobs[request.path.rsplit('/').next().unwrap()];
        Response::new(206, raw[start..=end].to_vec()).header(
            "Content-Range",
            &format!("bytes {start}-{end}/{}", raw.len()),
        )
    }
    for (resume, corrupt) in [(false, false), (true, false), (false, true)] {
        let root = tempfile::tempdir().unwrap();
        let image = Arc::new(image_layout(root.path(), 1, 32 * 1024 * 1024));
        let original = image.clone();
        let origin = Server::new(move |request| response(&original, &request, false, false));
        let cached = image.clone();
        let mirror = Server::new(move |request| response(&cached, &request, true, corrupt));
        let harness = harness(&origin, &[format!("http://{}", mirror.host)]);
        let result = pull(
            &harness,
            if resume { &["--resume"] } else { &[] },
            if corrupt { 7 } else { 0 },
        );
        if corrupt {
            assert_eq!(result["error"]["code"], "INTEGRITY");
            assert_eq!(origin.connections.load(Ordering::SeqCst), 0);
        } else {
            assert_eq!(
                origin.connections.load(Ordering::SeqCst),
                if resume { 1 } else { 4 }
            );
            let (digest, raw) = image
                .blobs
                .iter()
                .find(|(_, raw)| raw.len() == 32 * 1024 * 1024)
                .unwrap();
            assert_eq!(
                fs::read(
                    harness
                        .root
                        .path()
                        .join("image/blobs/sha256")
                        .join(digest.strip_prefix("sha256:").unwrap())
                )
                .unwrap(),
                *raw
            );
        }
    }
}
