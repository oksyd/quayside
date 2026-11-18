mod support;

use clap::Parser;
use quayside::{
    auth::{AuthFile, Credential},
    cli::Cli,
};
use std::{collections::BTreeMap, ffi::OsString, fs, sync::atomic::Ordering};
use support::{Harness, Response, Server};

#[test]
fn remote_metadata_cannot_execute_terminal_controls_in_error_output() {
    let media_type = "application/\u{1b}[2J\r\u{7}\u{9b}forged";
    let body = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2, "mediaType": media_type
    }))
    .unwrap();
    let server = Server::new(move |_| Response::new(200, body.clone()));
    let harness = Harness::new(&[(&server.host, true)]);
    let reference = format!("{}/app:v1", server.host);
    let output = harness
        .command(&["manifest", "get", &reference])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("unsupported manifest media type"));
    assert!(
        stderr
            .chars()
            .all(|c| !c.is_control() || matches!(c, '\n' | '\t'))
    );
    let result = harness.json(&["manifest", "get", &reference], 5);
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains(media_type)
    );
}

#[test]
fn invalid_login_options_fail_before_reading_a_password_or_contacting_the_registry() {
    let server = Server::new(|_| panic!("invalid login options must not start a request"));
    let harness = Harness::new(&[(&server.host, true)]);
    for (username, options, message) in [
        (
            "robot",
            vec!["--repository", "../private"],
            "invalid repository path",
        ),
        ("robot\tadmin", vec![], "invalid login username"),
        ("robot\u{1b}[2J", vec![], "invalid login username"),
    ] {
        let mut args = vec!["login", &server.host, "-u", username, "--password-stdin"];
        args.extend(options);
        let result = harness.json(&args, 2);
        assert_eq!(result["error"]["code"], "INVALID_INPUT");
        assert!(
            result["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with(message)
        );
    }
    harness.json(
        &[
            "login",
            &server.host,
            "-u",
            "robot",
            "--repository",
            "private",
            "--save-unverified",
        ],
        2,
    );
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    assert!(!harness.root.path().join("auth.json").exists());
    assert!(!harness.root.path().join("keys/master.key").exists());
}

#[test]
fn copy_resolves_short_sources_to_docker_hub() {
    let root = tempfile::tempdir().unwrap();
    let image = support::image_layout(root.path(), 1, 32);
    let digest = image.digest.clone();
    let proxy = Server::new(move |request| {
        if let Some(path) = request.path.strip_prefix("http://registry-1.docker.io/v2/") {
            assert_eq!(request.method, "GET");
            let resource = path
                .strip_prefix("apache/skywalking-banyandb/")
                .or_else(|| path.strip_prefix("library/nginx/"))
                .expect("source requests must use the normalized repository");
            match resource.split('?').next().unwrap() {
                "tags/list" => Response::new(
                    200,
                    br#"{"name":"library/nginx","tags":["latest","1.2.3"]}"#.to_vec(),
                ),
                "manifests/0.11.0" | "manifests/latest" => {
                    Response::new(200, image.manifest.clone())
                        .header("Content-Type", quayside::model::OCI_MANIFEST)
                }
                _ => {
                    let digest = resource.strip_prefix("blobs/").expect("config request");
                    Response::new(200, image.blobs[digest].clone())
                }
            }
        } else {
            assert!(
                request
                    .path
                    .starts_with("http://registry.invalid/v2/team/app/")
            );
            assert!(matches!(request.method.as_str(), "GET" | "HEAD"));
            Response::new(404, vec![])
        }
    });
    let harness = Harness::new(&[("docker.io", true), ("registry.invalid", true)]);
    fs::write(
        harness.daemon_config(),
        serde_json::to_vec(&serde_json::json!({"proxies": {
            "http-proxy": format!("http://{}", proxy.host)
        }}))
        .unwrap(),
    )
    .unwrap();
    for (source, normalized) in [
        (
            "apache/skywalking-banyandb:0.11.0",
            "docker.io/apache/skywalking-banyandb:0.11.0",
        ),
        ("nginx", "docker.io/library/nginx:latest"),
    ] {
        let result = harness.json(
            &[
                "image",
                "copy",
                source,
                "registry.invalid/team/app:v1",
                "--dry-run",
            ],
            0,
        );
        assert_eq!(result["data"]["source"], normalized);
        assert_eq!(result["data"]["source_digest"], digest);
        assert_eq!(result["data"]["stats"]["planned_blobs"], 2);
    }
    for args in [
        vec!["tag", "ls", "nginx"],
        vec!["manifest", "get", "nginx"],
        vec!["image", "digest", "nginx"],
        vec!["image", "inspect", "nginx"],
        vec![
            "image",
            "pull",
            "nginx",
            "-o",
            "unused.oci.tar",
            "--dry-run",
        ],
        vec![
            "index",
            "create",
            "registry.invalid/team/app:multi",
            "--from",
            "nginx",
            "--dry-run",
        ],
        vec![
            "image",
            "tag",
            "nginx",
            "docker.io/library/nginx:latest",
            "--dry-run",
        ],
    ] {
        harness.json(&args, 0);
    }
    let latest = harness.json(&["tag", "latest", "nginx"], 0);
    assert_eq!(latest["command"], "tag latest");
    assert_eq!(latest["data"]["reference"], "docker.io/library/nginx:1.2.3");
}

#[test]
fn latest_tag_prints_a_copyable_reference_and_reports_missing_versions() {
    let server = Server::new(|request| {
        assert_eq!(request.method, "GET");
        let tags = match request.path.as_str() {
            "/v2/app/tags/list?n=1000" => vec![
                "1.9.0",
                "1.10.0",
                "1.10.0-alpine",
                "1.10.0-alpine3.9-slim",
                "1.10.0-alpine3.24-slim",
            ],
            "/v2/aliases/tags/list?n=1000" => vec!["latest", "stable", "2", "2.1", "3.0.0-rc.1"],
            "/v2/empty/tags/list?n=1000" => vec![],
            _ => panic!("unexpected request: {}", request.path),
        };
        Response::new(
            200,
            serde_json::to_vec(&serde_json::json!({"tags": tags})).unwrap(),
        )
    });
    let harness = Harness::new(&[(&server.host, true)]);
    let repository = format!("{}/app", server.host);
    let expected = format!("{repository}:1.10.0");
    let output = harness.output(&["tag", "latest", &repository], 0);
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{expected}\n")
    );
    let latest = harness.json(&["tag", "latest", &repository, "--variant", "alpine"], 0);
    assert_eq!(latest["command"], "tag latest");
    assert_eq!(
        latest["data"],
        serde_json::json!({
            "repository": repository, "tag": "1.10.0-alpine", "reference": format!("{expected}-alpine")
        })
    );
    for repository in ["aliases", "empty"] {
        let reference = format!("{}/{repository}", server.host);
        let result = harness.json(&["tag", "latest", &reference], 4);
        assert_eq!(result["command"], "tag latest");
        assert_eq!(result["error"]["code"], "NOT_FOUND");
        assert!(
            result["error"]["message"]
                .as_str()
                .unwrap()
                .contains("no version tag matching *.*.*")
        );
        assert!(
            result["error"]["message"]
                .as_str()
                .unwrap()
                .contains("tag ls")
        );
    }
    let output = harness.output(
        &[
            "tag",
            "latest",
            &repository,
            "--match",
            "*.*.*-alpine*.*-slim",
        ],
        0,
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{expected}-alpine3.24-slim\n")
    );
    assert_eq!(server.connections.load(Ordering::SeqCst), 5);
}

#[test]
fn latest_tag_rejects_selectors_and_invalid_variants_before_network_requests() {
    let server = Server::new(|_| panic!("invalid latest options must not start a request"));
    let harness = Harness::new(&[(&server.host, true)]);
    let repository = format!("{}/app", server.host);
    for variant in ["", "../alpine", "alpine\nforged", "-alpine"] {
        let result = harness.json(
            &[
                "tag",
                "latest",
                &repository,
                &format!("--variant={variant}"),
            ],
            2,
        );
        assert_eq!(result["error"]["code"], "INVALID_INPUT");
    }
    for reference in [
        format!("{repository}:latest"),
        format!(
            "{repository}@{}",
            quayside::digest::Digest::sha256(b"manifest")
        ),
    ] {
        let result = harness.json(&["tag", "latest", &reference], 2);
        assert_eq!(result["error"]["code"], "INVALID_INPUT");
    }
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn latest_tag_patterns_reject_invalid_options_without_network_requests() {
    let server = Server::new(|_| panic!("invalid pattern options must not start a request"));
    let harness = Harness::new(&[(&server.host, true)]);
    let repository = format!("{}/app", server.host);
    let destination = format!("{}/target:v1", server.host);
    for mut args in [
        vec!["tag", "latest", &repository],
        vec!["image", "copy", &repository, &destination, "--latest"],
    ] {
        args.push("--match");
        for pattern in [
            "",
            "../*",
            "*.*.*-alpine?",
            "*.*.*-alpine[0-9]",
            "*.*.*\n",
            "**.*.*",
        ] {
            let result = harness.json(&[&args[..], &[pattern]].concat(), 2);
            assert_eq!(result["error"]["code"], "INVALID_INPUT");
            assert!(
                result["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("--match")
            );
        }
        let output = harness.output(&[&args[..], &["*.*.*", "--variant", "alpine"]].concat(), 2);
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("cannot be used")
        );
    }
    harness.output(
        &[
            "image",
            "copy",
            &repository,
            &destination,
            "--match",
            "*.*.*",
        ],
        2,
    );
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn auth_host_configuration_preserves_literal_hosts_and_explicit_ports() {
    let harness = Harness::new(&[]);
    let result = harness.json(
        &[
            "registry",
            "set",
            "REGISTRY-1.DOCKER.IO:443",
            "--auth-host",
            "REGISTRY-1.DOCKER.IO:443",
            "--auth-host",
            "INDEX.DOCKER.IO:0443",
            "--auth-host",
            "[2001:DB8::1]:443",
            "--auth-host",
            "REGISTRY-1.DOCKER.IO:443",
        ],
        0,
    );
    let expected = [
        "[2001:db8::1]:443",
        "index.docker.io:443",
        "registry-1.docker.io:443",
    ];
    assert_eq!(result["data"]["registry"], "docker.io:443");
    assert_eq!(
        result["data"]["config"]["auth_hosts"],
        serde_json::json!(expected)
    );
    let config = quayside::config::Config::load(&harness.root.path().join("config.toml")).unwrap();
    assert_eq!(config.registries.len(), 1);
    assert_eq!(config.registries["docker.io:443"].auth_hosts, expected);
}

#[test]
fn registry_configuration_does_not_require_decrypting_credentials() {
    let server = Server::new(|_| panic!("unreadable credentials must fail before a request"));
    let harness = Harness::new(&[(&server.host, true)]);
    let auth = harness.root.path().join("auth.json");
    let key = harness.root.path().join("keys/master.key");
    AuthFile::put(
        &auth,
        &key,
        &server.host,
        Credential {
            username: "robot".into(),
            secret: "secret".into(),
        },
    )
    .unwrap();
    fs::remove_file(&key).unwrap();
    let encrypted = fs::read(&auth).unwrap();
    harness.json(
        &[
            "registry",
            "set",
            "example.com",
            "--auth-host",
            "AUTH.EXAMPLE.COM:443",
        ],
        0,
    );
    assert_eq!(fs::read(&auth).unwrap(), encrypted);
    assert!(!key.exists());
    let output = harness
        .command(&["--json", "registry", "ping", &server.host])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn logout_discards_cached_clients_in_the_same_context() {
    let harness = Harness::new(&[]);
    let auth = harness.root.path().join("auth.json");
    let key = harness.root.path().join("keys/master.key");
    AuthFile::put(
        &auth,
        &key,
        "example.com",
        Credential {
            username: "robot".into(),
            secret: "secret".into(),
        },
    )
    .unwrap();
    let command = harness.command(&["logout", "example.com"]);
    let cli = Cli::try_parse_from(
        std::iter::once(OsString::from("quayside")).chain(command.get_args().map(OsString::from)),
    )
    .unwrap();
    let ctx = quayside::app::Context::new(&cli).unwrap();
    ctx.registry("EXAMPLE.COM").unwrap();
    quayside::app::run(&ctx, &cli.command).await.unwrap();
    assert!(AuthFile::load(&auth, &key).unwrap().registries.is_empty());
    // A cached authenticated client would hide this changed store and remain usable after logout.
    fs::write(&auth, b"invalid encrypted store").unwrap();
    assert!(ctx.registry("example.com").is_err());
}

fn index_limit_case(mode: &str) {
    let root = tempfile::tempdir().unwrap();
    let count = if mode == "manifest" { 8 } else { 2 };
    let mut manifests = BTreeMap::new();
    let mut blobs = BTreeMap::new();
    for i in 0..count {
        let arch = format!("arch{i}");
        let image = support::image_layout_for(&root.path().join(&arch), 1, 32, &arch);
        assert!(image.manifest.len() < 1024);
        manifests.insert(format!("/v2/{arch}/manifests/v1"), image.manifest);
        blobs.extend(image.blobs);
    }
    let source = Server::new(move |request| {
        assert_eq!(request.method, "GET");
        if let Some(manifest) = manifests.get(&request.path) {
            Response::new(200, manifest.clone())
                .header("Content-Type", quayside::model::OCI_MANIFEST)
        } else {
            Response::new(200, blobs[request.path.rsplit('/').next().unwrap()].clone())
        }
    });
    let target = Server::new(|request| {
        assert!(
            matches!(request.method.as_str(), "GET" | "HEAD"),
            "dry run must not write"
        );
        Response::new(404, vec![])
    });
    let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    match mode {
        "manifest" => harness.config.transfer.max_manifest_size = "1KiB".into(),
        "metadata" => {
            harness.config.transfer.max_manifest_size = "1KiB".into();
            harness.config.transfer.max_metadata_size = "1KiB".into();
        }
        "objects" => harness.config.transfer.max_objects = 5,
        "boundary" => harness.config.transfer.max_objects = 6,
        _ => unreachable!(),
    }
    let mut args = vec![
        "index".into(),
        "create".into(),
        format!("{}/app:all", target.host),
        "--dry-run".into(),
    ];
    for i in 0..count {
        args.extend(["--from".into(), format!("{}/arch{i}:v1", source.host)]);
    }
    let result = harness.json(
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        if mode == "boundary" { 0 } else { 2 },
    );
    if mode == "boundary" {
        // Two image manifests, two configs, one shared layer, and the new index: six objects.
        assert_eq!(result["data"]["stats"]["planned_blobs"], 3);
    } else {
        assert_eq!(target.connections.load(Ordering::SeqCst), 0, "mode={mode}");
    }
}

#[test]
fn generated_index_is_checked_before_transfer_and_shared_blobs_count_once() {
    for mode in ["manifest", "metadata", "objects", "boundary"] {
        index_limit_case(mode);
    }
}
