mod support;
use quayside::model::OCI_MANIFEST;
use serde_json::json;
use std::{
    fs,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use support::{Harness, Image, Request, Response, Server, image_layout};

fn source(image: Image) -> Server {
    Server::new(move |request| {
        if request.path.contains("/manifests/") {
            Response::new(200, image.manifest.clone()).header("Content-Type", OCI_MANIFEST)
        } else if let Some((_, digest)) = request.path.split_once("/blobs/") {
            match image.blobs.get(digest) {
                Some(body) => Response::new(200, body.clone()),
                None => Response::new(404, vec![]),
            }
        } else {
            Response::new(200, b"{}".to_vec())
        }
    })
}

#[test]
fn inspect_single_platform_uses_config_and_preserves_json_with_debug_logs() {
    let data = tempfile::tempdir().unwrap();
    let server = source(image_layout(data.path(), 2, 4096));
    let harness = Harness::new(&[(&server.host, true)]);
    let reference = format!("{}/team/app:v1", server.host);
    let out = harness.output(
        &[
            "--json",
            "--log-level",
            "debug",
            "image",
            "inspect",
            &reference,
        ],
        0,
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["data"]["platforms"], json!(["linux/arm64/v8"]));
    assert_eq!(
        value["data"]["config"]["config"]["Labels"]["fixture"],
        "quayside"
    );
    let diagnostics = String::from_utf8(out.stderr).unwrap();
    assert!(diagnostics.contains("Debug: HTTP GET"));
    let quiet = harness.output(
        &[
            "--json",
            "--quiet",
            "--log-level",
            "trace",
            "image",
            "inspect",
            &reference,
        ],
        0,
    );
    assert!(!String::from_utf8_lossy(&quiet.stderr).contains("Debug:"));
    let raw = harness.output(
        &[
            "--log-level",
            "trace",
            "manifest",
            "get",
            &reference,
            "--raw",
        ],
        0,
    );
    assert!(serde_json::from_slice::<serde_json::Value>(&raw.stdout).is_ok());
}

#[test]
fn quiet_suppresses_plain_http_warnings_but_preserves_errors() {
    let server = Server::new(|_| Response::new(200, b"{}".to_vec()));
    let harness = Harness::new(&[(&server.host, true)]);
    let result = harness.output(&["--quiet", "registry", "ping", &server.host], 0);
    assert!(result.stderr.is_empty());
    assert!(!result.stdout.is_empty());
    let error = harness.output(
        &[
            "--quiet",
            "--log-level",
            "off",
            "image",
            "digest",
            "invalid",
        ],
        2,
    );
    assert!(String::from_utf8_lossy(&error.stderr).contains("error"));
}

fn tls_server(name: &str, expired: bool) -> (Server, String) {
    tls_server_with(name, expired, |_| Response::new(200, b"{}".to_vec()))
}

fn tls_server_with(
    name: &str,
    expired: bool,
    handler: impl Fn(Request) -> Response + Send + Sync + 'static,
) -> (Server, String) {
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose, date_time_ymd,
    };
    let mut ca = CertificateParams::new(vec![]).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let cert = ca.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca, ca_key);
    let mut leaf = CertificateParams::new(vec![name.into()]).unwrap();
    if expired {
        leaf.not_before = date_time_ymd(2010, 1, 1);
        leaf.not_after = date_time_ymd(2011, 1, 1);
    }
    let key = KeyPair::generate().unwrap();
    let leaf = leaf.signed_by(&key, &issuer).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    (Server::start(Some(Arc::new(config)), handler), cert.pem())
}

#[test]
fn real_tls_certificate_errors_are_distinct_and_not_retried() {
    for (name, expired, trust, code) in [
        ("127.0.0.1", false, false, "TLS_UNKNOWN_ISSUER"),
        ("wrong.example", false, true, "TLS_NAME_MISMATCH"),
        ("127.0.0.1", true, true, "TLS_CERTIFICATE_EXPIRED"),
    ] {
        let (server, ca) = tls_server(name, expired);
        let mut harness = Harness::new(&[(&server.host, false)]);
        harness.config.transfer.max_retries = 3;
        if trust {
            let path = harness.root.path().join("ca.pem");
            fs::write(&path, ca).unwrap();
            harness
                .config
                .registries
                .get_mut(&server.host)
                .unwrap()
                .ca_file = Some(path);
        }
        let result = harness.json(&["registry", "ping", &server.host], 6);
        assert_eq!(result["error"]["code"], code, "{result}");
        assert_eq!(
            server.connections.load(Ordering::SeqCst),
            1,
            "certificate failures must not be retried"
        );
    }
    let (server, ca) = tls_server("127.0.0.1", false);
    let mut harness = Harness::new(&[(&server.host, false)]);
    let path = harness.root.path().join("ca.pem");
    fs::write(&path, ca).unwrap();
    harness
        .config
        .registries
        .get_mut(&server.host)
        .unwrap()
        .ca_file = Some(path);
    harness.json(&["registry", "ping", &server.host], 0);
}

#[test]
fn signed_redirects_and_credentials_never_appear_in_trace_logs() {
    let server = Server::new(|request: Request| {
        if request.path == "/v2/" {
            Response::new(307, vec![]).header("Location", "/signed?signature=very-secret-signature")
        } else {
            Response::new(403, b"very-secret-response".to_vec())
        }
    });
    let harness = Harness::new(&[(&server.host, true)]);
    let out = harness.output(
        &[
            "--json",
            "--log-level",
            "trace",
            "registry",
            "ping",
            &server.host,
        ],
        3,
    );
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!all.contains("very-secret"));
    assert!(!all.contains("/signed"));
    assert!(all.contains("Debug: HTTP GET"));
}

#[test]
fn metadata_deadline_covers_body_reads() {
    let data = tempfile::tempdir().unwrap();
    let image = image_layout(data.path(), 0, 0);
    let server = Server::new(move |_| {
        let mut response =
            Response::new(200, image.manifest.clone()).header("Content-Type", OCI_MANIFEST);
        response.delay = Duration::from_millis(400);
        response
    });
    let mut harness = Harness::new(&[(&server.host, true)]);
    harness.config.transfer.metadata_timeout = "50ms".into();
    let result = harness.json(
        &["manifest", "get", &format!("{}/test/image:v1", server.host)],
        6,
    );
    assert_eq!(result["error"]["code"], "NETWORK");
}

#[test]
fn export_counts_staging_and_tar_before_writing() {
    let data = tempfile::tempdir().unwrap();
    let image = image_layout(data.path(), 1, 4096);
    let server = source(image);
    let mut harness = Harness::new(&[(&server.host, true)]);
    harness.config.transfer.max_temp_size = "6KiB".into();
    let reference = format!("{}/team/app:v1", server.host);
    let archive = harness.root.path().join("image.tar");
    let result = harness.json(
        &[
            "image",
            "pull",
            &reference,
            "--output",
            archive.to_str().unwrap(),
        ],
        2,
    );
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("max_temp_size")
    );
    assert!(!archive.exists());
    let layout = harness.root.path().join("export");
    harness.json(
        &[
            "image",
            "pull",
            &reference,
            "--output",
            layout.to_str().unwrap(),
            "--format",
            "oci-layout",
        ],
        0,
    );
    assert!(layout.join("index.json").exists());
}

#[test]
fn oversized_archive_fails_before_registry_access() {
    let harness = Harness::new(&[]);
    let path = harness.root.path().join("oversized.tar");
    let mut tar = tar::Builder::new(fs::File::create(&path).unwrap());
    let mut header = tar::Header::new_gnu();
    header.set_size(2048);
    header.set_mode(0o600);
    header.set_cksum();
    tar.append_data(&mut header, "oci-layout", &vec![b'x'; 2048][..])
        .unwrap();
    tar.finish().unwrap();
    drop(tar);
    let mut harness = harness;
    harness.config.transfer.max_temp_size = "1KiB".into();
    let result = harness.json(
        &[
            "image",
            "push",
            path.to_str().unwrap(),
            "127.0.0.1:1/test/app:v1",
        ],
        2,
    );
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("max_temp_size")
    );
    assert_eq!(
        fs::read_dir(harness.root.path().join("tmp"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn rejected_bearer_token_is_refreshed_and_retry_after_is_bounded() {
    use std::sync::atomic::AtomicUsize;
    let tokens = Arc::new(AtomicUsize::new(0));
    let issued = tokens.clone();
    let server = Server::new(move |request| {
        if request.path.starts_with("/token") {
            let token = if issued.fetch_add(1, Ordering::SeqCst) == 0 {
                "expired-token"
            } else {
                "valid-token"
            };
            Response::new(
                200,
                serde_json::to_vec(&json!({"token":token,"expires_in":60})).unwrap(),
            )
        } else if request
            .headers
            .get("authorization")
            .is_some_and(|value| value == "Bearer valid-token")
        {
            Response::new(200, b"{}".to_vec())
        } else {
            Response::new(401, vec![]).header(
                "WWW-Authenticate",
                &format!(
                    "Bearer realm=\"http://{}/token\",service=\"fixture\"",
                    request.headers["host"]
                ),
            )
        }
    });
    let harness = Harness::new(&[(&server.host, true)]);
    let value = harness.json(&["registry", "ping", &server.host], 0);
    assert_eq!(value["data"]["authenticated_request"], true);
    assert_eq!(tokens.load(Ordering::SeqCst), 2);

    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let server = Server::new(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        Response::new(429, vec![]).header("Retry-After", "0")
    });
    let mut harness = Harness::new(&[(&server.host, true)]);
    harness.config.transfer.max_retries = 2;
    harness.json(&["registry", "ping", &server.host], 6);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn basic_auth_is_not_exposed_by_trace_diagnostics() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::os::unix::fs::PermissionsExt;
    let encoded = STANDARD.encode("robot$account:private-password");
    let expected = format!("Basic {encoded}");
    let server = Server::new(move |request| {
        if request.headers.get("authorization") == Some(&expected) {
            Response::new(200, b"{}".to_vec())
        } else {
            Response::new(401, vec![]).header("WWW-Authenticate", "Basic realm=\"fixture\"")
        }
    });
    let harness = Harness::new(&[(&server.host, true)]);
    let auth = harness.root.path().join("auth.json");
    fs::write(&auth,serde_json::to_vec(&json!({"version":1,"registries":{&server.host:{"username":"robot$account","secret":"private-password"}}})).unwrap()).unwrap();
    fs::set_permissions(&auth, fs::Permissions::from_mode(0o600)).unwrap();
    harness.json(&["auth", "migrate"], 0);
    let out = harness.output(
        &[
            "--log-level",
            "trace",
            "--json",
            "registry",
            "ping",
            &server.host,
        ],
        0,
    );
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    for secret in ["robot$account", "private-password", encoded.as_str()] {
        assert!(!all.contains(secret));
    }
}

#[test]
fn interruption_returns_structured_error_and_stops_request() {
    use std::{
        process::{Command, Stdio},
        time::Instant,
    };
    let data = tempfile::tempdir().unwrap();
    let image = image_layout(data.path(), 0, 0);
    let server = Server::new(move |_| {
        let mut response =
            Response::new(200, image.manifest.clone()).header("Content-Type", OCI_MANIFEST);
        response.delay = Duration::from_millis(750);
        response
    });
    let harness = Harness::new(&[(&server.host, true)]);
    let mut child = harness
        .command(&[
            "--json",
            "manifest",
            "get",
            &format!("{}/test/image:v1", server.host),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while server.connections.load(Ordering::SeqCst) == 0 {
        if start.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            panic!("CLI did not connect");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(130));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "INTERRUPTED");
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}

#[test]
fn artifacts_preserve_content_without_parsing_opaque_config() {
    for opaque in [false, true] {
        let data = tempfile::tempdir().unwrap();
        let artifact = support::artifact_layout(data.path(), false, opaque);
        let digest = artifact.digest.clone();
        let raw = artifact.manifest.clone();
        let server = source(artifact);
        let harness = Harness::new(&[(&server.host, true)]);
        let reference = format!("{}/team/db:2", server.host);
        let result = harness.json(&["image", "inspect", &reference], 0);
        assert_eq!(result["data"]["platforms"], json!([]));
        assert_eq!(result["data"]["digest"], digest);
        assert!(result["data"]["config"].is_null());
        let out = harness.output(&["manifest", "get", &reference, "--raw"], 0);
        assert_eq!(out.stdout, raw);
        let rejected = harness.json(
            &["image", "inspect", &reference, "--platform", "linux/amd64"],
            2,
        );
        assert!(
            rejected["error"]["message"]
                .as_str()
                .unwrap()
                .contains("OCI artifacts")
        );
        let archive = data.path().join("artifact.tar");
        harness.json(
            &["image", "pull", &reference, "-o", archive.to_str().unwrap()],
            0,
        );
        assert!(archive.exists());
    }
}

#[test]
fn platform_selection_skips_artifacts_in_mixed_index() {
    use quayside::{
        digest::Digest,
        model::{Descriptor, OCI_INDEX},
    };
    let data = tempfile::tempdir().unwrap();
    let artifact = support::artifact_layout(&data.path().join("db"), false, false);
    let image = image_layout(&data.path().join("image"), 0, 0);
    let expected = image.digest.clone();
    let mut artifact_desc = Descriptor::new(
        OCI_MANIFEST,
        artifact.digest.parse().unwrap(),
        artifact.manifest.len() as u64,
    );
    // Even a misleading platform descriptor cannot make an artifact an image.
    artifact_desc.platform = Some("linux/arm64/v8".parse().unwrap());
    let index = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":[
        artifact_desc,
        Descriptor::new(OCI_MANIFEST, image.digest.parse().unwrap(), image.manifest.len() as u64)
    ]})).unwrap();
    let index_digest = Digest::sha256(&index).to_string();
    let server = Server::new(move |request| {
        if request.path.ends_with("/manifests/v1") {
            Response::new(200, index.clone()).header("Content-Type", OCI_INDEX)
        } else if request.path.ends_with(&artifact.digest) {
            Response::new(200, artifact.manifest.clone()).header("Content-Type", OCI_MANIFEST)
        } else if request.path.ends_with(&image.digest) {
            Response::new(200, image.manifest.clone()).header("Content-Type", OCI_MANIFEST)
        } else if let Some((_, digest)) = request.path.split_once("/blobs/") {
            match image
                .blobs
                .get(digest)
                .or_else(|| artifact.blobs.get(digest))
            {
                Some(body) => Response::new(200, body.clone()),
                None => Response::new(404, vec![]),
            }
        } else {
            Response::new(404, vec![])
        }
    });
    let harness = Harness::new(&[(&server.host, true)]);
    let reference = format!("{}/mixed:v1", server.host);
    let selected = harness.json(
        &["image", "inspect", &reference, "--platform", "linux/arm64"],
        0,
    );
    assert_eq!(selected["data"]["digest"], expected);
    assert_eq!(selected["data"]["source_digest"], index_digest);
    let archive = data.path().join("mixed.tar");
    harness.json(
        &["image", "pull", &reference, "-o", archive.to_str().unwrap()],
        0,
    );
}

#[test]
fn malformed_container_config_is_not_treated_as_artifact() {
    let data = tempfile::tempdir().unwrap();
    let mut artifact = support::artifact_layout(data.path(), true, false);
    let mut manifest: serde_json::Value = serde_json::from_slice(&artifact.manifest).unwrap();
    manifest["config"]["mediaType"] = json!("application/vnd.oci.image.config.v1+json");
    artifact.manifest = serde_json::to_vec(&manifest).unwrap();
    let server = source(artifact);
    let harness = Harness::new(&[(&server.host, true)]);
    let reference = format!("{}/bad:v1", server.host);
    let result = harness.json(&["image", "inspect", &reference], 2);
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no operating system")
    );
}

fn trust_tls(harness: &mut Harness, host: &str, ca: &str, name: &str) {
    let path = harness.root.path().join(format!("{name}.pem"));
    fs::write(&path, ca).unwrap();
    harness.config.registries.get_mut(host).unwrap().ca_file = Some(path);
}

#[test]
fn https_registry_discovers_token_service_without_allowlist_and_keeps_ca_isolation() {
    use std::{io::Write, process::Stdio, sync::atomic::AtomicUsize};
    let requests = Arc::new(AtomicUsize::new(0));
    let seen = requests.clone();
    let (token, token_ca) = tls_server_with("127.0.0.1", false, move |request| {
        assert_eq!(
            request.headers.get("authorization").unwrap(),
            "Basic cm9ib3Q6c2VjcmV0"
        );
        assert!(request.path.contains("service=fixture"));
        seen.fetch_add(1, Ordering::SeqCst);
        Response::new(
            200,
            br#"{"token":"discovered-token","expires_in":60}"#.to_vec(),
        )
    });
    let realm = format!("https://{}/token", token.host);
    let (registry, registry_ca) = tls_server_with("127.0.0.1", false, move |request| {
        if request.headers.get("authorization").map(String::as_str)
            == Some("Bearer discovered-token")
        {
            Response::new(200, b"{}".to_vec())
        } else {
            assert!(!request.headers.contains_key("authorization"));
            Response::new(401, vec![]).header(
                "WWW-Authenticate",
                &format!("Bearer realm=\"{realm}\",service=\"fixture\""),
            )
        }
    });
    let mut harness = Harness::new(&[(&registry.host, false), (&token.host, false)]);
    trust_tls(&mut harness, &registry.host, &registry_ca, "registry");
    let login = |harness: &Harness, expected: i32| {
        let mut child = harness
            .command(&[
                "--json",
                "login",
                &registry.host,
                "-u",
                "robot",
                "--password-stdin",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"secret\n").unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let rejected = login(&harness, 6);
    assert_eq!(rejected["error"]["code"], "TLS_UNKNOWN_ISSUER");
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    trust_tls(&mut harness, &token.host, &token_ca, "token");
    assert_eq!(login(&harness, 0)["data"]["verified"], true);
    harness.json(&["registry", "ping", &registry.host], 0);
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    harness
        .config
        .registries
        .get_mut(&registry.host)
        .unwrap()
        .auth_hosts = vec!["other.example".into()];
    harness.json(&["registry", "ping", &registry.host], 3);
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    harness
        .config
        .registries
        .get_mut(&registry.host)
        .unwrap()
        .auth_hosts = vec![token.host.clone()];
    harness.json(&["registry", "ping", &registry.host], 0);
    assert_eq!(requests.load(Ordering::SeqCst), 3);
}

#[test]
fn https_token_downgrade_is_rejected_before_contacting_service() {
    let token = Server::new(|_| panic!("HTTP token service must not receive a request"));
    let realm = format!("http://{}/token", token.host);
    let (registry, ca) = tls_server_with("127.0.0.1", false, move |_| {
        Response::new(401, vec![]).header("WWW-Authenticate", &format!("Bearer realm=\"{realm}\""))
    });
    let mut harness = Harness::new(&[(&registry.host, false), (&token.host, true)]);
    trust_tls(&mut harness, &registry.host, &ca, "registry");
    harness
        .config
        .registries
        .get_mut(&registry.host)
        .unwrap()
        .auth_hosts = vec![token.host.clone()];
    let error = harness.json(&["registry", "ping", &registry.host], 3);
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("downgrade")
    );
    assert_eq!(token.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn http_registry_delegation_requires_explicit_trust() {
    let token = Server::new(|_| Response::new(200, br#"{"token":"test-token"}"#.to_vec()));
    let realm = format!("http://{}/token", token.host);
    let registry = Server::new(move |request| {
        if request.headers.get("authorization").map(String::as_str) == Some("Bearer test-token") {
            Response::new(200, b"{}".to_vec())
        } else {
            Response::new(401, vec![])
                .header("WWW-Authenticate", &format!("Bearer realm=\"{realm}\""))
        }
    });
    let mut harness = Harness::new(&[(&registry.host, true), (&token.host, true)]);
    harness.json(&["registry", "ping", &registry.host], 3);
    assert_eq!(token.connections.load(Ordering::SeqCst), 0);
    harness
        .config
        .registries
        .get_mut(&registry.host)
        .unwrap()
        .auth_hosts = vec![token.host.clone()];
    harness.json(&["registry", "ping", &registry.host], 0);
}

#[test]
fn token_redirects_and_redirected_registry_challenges_never_forward_credentials() {
    let sink = Server::new(|_| panic!("redirect destination must never be contacted"));
    let redirect = format!("http://{}/steal", sink.host);
    let (token, token_ca) = tls_server_with("127.0.0.1", false, move |_| {
        Response::new(302, vec![]).header("Location", &redirect)
    });
    let realm = format!("https://{}/token", token.host);
    let challenge = format!("Bearer realm=\"{realm}\"");
    let registry_challenge = challenge.clone();
    let (registry, ca) = tls_server_with("127.0.0.1", false, move |_| {
        Response::new(401, vec![]).header("WWW-Authenticate", &registry_challenge)
    });
    let mut harness = Harness::new(&[(&registry.host, false), (&token.host, false)]);
    trust_tls(&mut harness, &registry.host, &ca, "registry");
    trust_tls(&mut harness, &token.host, &token_ca, "token");
    quayside::auth::AuthFile::put(
        &harness.root.path().join("auth.json"),
        &harness.root.path().join("keys/master.key"),
        &registry.host,
        quayside::auth::Credential {
            username: "robot".into(),
            secret: "secret".into(),
        },
    )
    .unwrap();
    harness.json(&["registry", "ping", &registry.host], 1);
    assert_eq!(sink.connections.load(Ordering::SeqCst), 0);
    let calls = token.connections.load(Ordering::SeqCst);
    let (foreign, foreign_ca) = tls_server_with("127.0.0.1", false, move |request| {
        assert!(!request.headers.contains_key("authorization"));
        Response::new(401, vec![]).header("WWW-Authenticate", &challenge)
    });
    let foreign_url = format!("https://{}/v2/", foreign.host);
    let (redirecting, ca) = tls_server_with("127.0.0.1", false, move |_| {
        Response::new(302, vec![]).header("Location", &foreign_url)
    });
    let mut redirected = Harness::new(&[(&redirecting.host, false)]);
    trust_tls(&mut redirected, &redirecting.host, &ca, "registry");
    // Trust the foreign CA independently through the system-store override, allowing its
    // 401 to reach the client. It must not be accepted as a registry authentication challenge.
    let roots = redirected.root.path().join("system-roots.pem");
    fs::write(&roots, foreign_ca).unwrap();
    quayside::auth::AuthFile::put(
        &redirected.root.path().join("auth.json"),
        &redirected.root.path().join("keys/master.key"),
        &redirecting.host,
        quayside::auth::Credential {
            username: "robot".into(),
            secret: "secret".into(),
        },
    )
    .unwrap();
    let output = redirected
        .command(&["--json", "registry", "ping", &redirecting.host])
        .env("SSL_CERT_FILE", roots)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(foreign.connections.load(Ordering::SeqCst), 1);
    assert_eq!(token.connections.load(Ordering::SeqCst), calls);
}
