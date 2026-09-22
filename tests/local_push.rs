mod support;

use quayside::{digest::Digest, model::OCI_MANIFEST};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use support::{Harness, Response, Server};

fn archive(path: &Path, mode: &str) -> Vec<u8> {
    let layer = b"a synthetic uncompressed layer".to_vec();
    let config = serde_json::to_vec(&json!({"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[Digest::sha256(&layer)]}})).unwrap();
    let config_name = format!("{}.json", Digest::sha256(&config).encoded());
    let mut manifest = json!([{"Config":config_name,"RepoTags":["example:v1","example:alias"],"Layers":["layer/layer.tar"]}]);
    if mode == "multiple" {
        manifest.as_array_mut().unwrap().push(
            json!({"Config":config_name,"RepoTags":["example:v2"],"Layers":["layer/layer.tar"]}),
        );
    }
    if mode == "traversal" {
        manifest[0]["Layers"][0] = json!("../outside");
    }
    if mode == "missing" {
        manifest[0]["Layers"][0] = json!("missing/layer.tar");
    }
    let mut tar = tar::Builder::new(fs::File::create(path).unwrap());
    let mut append = |name: &str, bytes: &[u8]| {
        let mut h = tar::Header::new_gnu();
        h.set_size(bytes.len() as u64);
        h.set_mode(0o600);
        h.set_cksum();
        tar.append_data(&mut h, name, bytes).unwrap();
    };
    append(&config_name, if mode == "config" { b"{}" } else { &config });
    append(
        "layer/layer.tar",
        if mode == "layer" {
            b"corrupted"
        } else {
            &layer
        },
    );
    // Real Docker archives need not place manifest.json before their layers.
    append("manifest.json", &serde_json::to_vec(&manifest).unwrap());
    if mode == "duplicate" {
        append("manifest.json", &serde_json::to_vec(&manifest).unwrap());
    }
    tar.finish().unwrap();
    layer
}

type Manifests = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

fn registry() -> (Server, Manifests) {
    let manifests = Arc::new(Mutex::new(BTreeMap::<String, Vec<u8>>::new()));
    let saved = manifests.clone();
    let blobs = Mutex::new(BTreeMap::<String, Vec<u8>>::new());
    let next = AtomicUsize::new(0);
    (
        Server::new(move |request| {
            if request.path.contains("/manifests/") {
                return match request.method.as_str() {
                    "GET" => saved
                        .lock()
                        .unwrap()
                        .get(&request.path)
                        .map(|body| {
                            Response::new(200, body.clone()).header(
                                "Content-Type",
                                serde_json::from_slice::<Value>(body).unwrap()["mediaType"]
                                    .as_str()
                                    .unwrap(),
                            )
                        })
                        .unwrap_or_else(|| Response::new(404, vec![])),
                    "PUT" => {
                        saved.lock().unwrap().insert(request.path, request.body);
                        Response::new(201, vec![])
                    }
                    _ => panic!("unexpected manifest method"),
                };
            }
            match request.method.as_str() {
                "HEAD" => blobs
                    .lock()
                    .unwrap()
                    .get(request.path.rsplit('/').next().unwrap())
                    .map(|body| {
                        Response::new(200, vec![]).header("Content-Length", &body.len().to_string())
                    })
                    .unwrap_or_else(|| Response::new(404, vec![])),
                "POST" => Response::new(202, vec![]).header(
                    "Location",
                    &format!(
                        "/v2/app/blobs/uploads/{}",
                        next.fetch_add(1, Ordering::SeqCst)
                    ),
                ),
                "PUT" => {
                    let url = url::Url::parse(&format!("http://example.invalid{}", request.path))
                        .unwrap();
                    let digest = url
                        .query_pairs()
                        .find(|(key, _)| key == "digest")
                        .unwrap()
                        .1
                        .into_owned();
                    assert_eq!(Digest::sha256(&request.body).to_string(), digest);
                    blobs.lock().unwrap().insert(digest, request.body);
                    Response::new(201, vec![])
                }
                _ => panic!("unexpected request"),
            }
        }),
        manifests,
    )
}

#[test]
fn docker_archives_select_tags_verify_layers_and_publish_oci() {
    let (server, manifests) = registry();
    let harness = Harness::new(&[(&server.host, true)]);
    let path = harness.root.path().join("image.data");
    let layer = archive(&path, "multiple");
    let dst = format!("{}/app:v1", server.host);
    harness.json(&["image", "push", path.to_str().unwrap(), &dst], 2);
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    let result = harness.json(
        &[
            "image",
            "push",
            path.to_str().unwrap(),
            &dst,
            "--ref",
            "example:alias",
        ],
        0,
    );
    assert_eq!(result["data"]["converted_from_docker_archive"], true);
    assert_eq!(result["data"]["stats"]["copied_blobs"], 2);
    let raw = manifests.lock().unwrap()["/v2/app/manifests/v1"].clone();
    let manifest: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(manifest["mediaType"], OCI_MANIFEST);
    assert_eq!(
        manifest["layers"][0]["digest"],
        Digest::sha256(&layer).to_string()
    );
    assert_eq!(
        manifest["layers"][0]["mediaType"],
        "application/vnd.oci.image.layer.v1.tar"
    );
    assert_eq!(
        result["data"]["target_digest"],
        Digest::sha256(&raw).to_string()
    );
    assert_eq!(
        fs::read_dir(harness.root.path().join("tmp"))
            .unwrap()
            .count(),
        0
    );
    let repeated = harness.json(
        &[
            "image",
            "push",
            path.to_str().unwrap(),
            &dst,
            "--ref",
            "example:v2",
        ],
        0,
    );
    assert_eq!(repeated["data"]["stats"]["skipped_blobs"], 2);
}

#[test]
fn invalid_docker_archives_fail_before_registry_access() {
    let (server, _) = registry();
    let mut harness = Harness::new(&[(&server.host, true)]);
    let path = harness.root.path().join("image.tar");
    let dst = format!("{}/app:v1", server.host);
    for (mode, exit) in [
        ("layer", 7),
        ("config", 7),
        ("traversal", 2),
        ("duplicate", 2),
        ("missing", 1),
    ] {
        archive(&path, mode);
        harness.json(&["image", "push", path.to_str().unwrap(), &dst], exit);
        assert_eq!(server.connections.load(Ordering::SeqCst), 0, "mode={mode}");
        assert_eq!(
            fs::read_dir(harness.root.path().join("tmp"))
                .unwrap()
                .count(),
            0
        );
    }
    archive(&path, "valid");
    harness.config.transfer.max_temp_size = "64B".into();
    harness.json(&["image", "push", path.to_str().unwrap(), &dst], 2);
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
}

fn docker_cli(harness: &Harness, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin = harness.root.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let path = bin.join("docker");
    let mut file = fs::File::create(&path).unwrap();
    writeln!(file, "#!/bin/sh\n{body}").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    bin
}

#[test]
fn docker_source_exports_only_when_requested_and_preserves_arguments() {
    let (server, _) = registry();
    let harness = Harness::new(&[(&server.host, true)]);
    let path = harness.root.path().join("image.tar");
    archive(&path, "valid");
    let bin = docker_cli(
        &harness,
        "printf '%s\\n' \"$@\" > \"$CAPTURE\"\n/bin/cat \"$ARCHIVE\"",
    );
    let capture = harness.root.path().join("args");
    let dst = format!("{}/app:v1", server.host);
    let image = "example:tag;literal";
    let output = harness
        .command(&["--json", "image", "push", "--docker", image, &dst])
        .env("PATH", &bin)
        .env("CAPTURE", &capture)
        .env("ARCHIVE", &path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        fs::read_to_string(capture).unwrap(),
        format!("image\nsave\n--\n{image}\n")
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["data"]["source"], image);
    assert_eq!(
        fs::read_dir(harness.root.path().join("tmp"))
            .unwrap()
            .count(),
        0
    );
    // Archive uploads never invoke Docker, even if it is unavailable.
    assert!(
        harness
            .command(&["image", "push", path.to_str().unwrap(), &dst])
            .env("PATH", "")
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn docker_export_failure_timeout_and_quota_leave_no_files_or_remote_writes() {
    let (server, _) = registry();
    let mut harness = Harness::new(&[(&server.host, true)]);
    let path = harness.root.path().join("image.tar");
    archive(&path, "valid");
    let dst = format!("{}/app:v1", server.host);
    for script in ["exit 1", "exec /bin/sleep 10", "/bin/cat \"$ARCHIVE\""] {
        let bin = docker_cli(&harness, script);
        harness.config.transfer.idle_timeout = "100ms".into();
        harness.config.transfer.max_temp_size = "1KiB".into();
        let output = harness
            .command(&["--json", "image", "push", "--docker", "example:v1", &dst])
            .env("PATH", bin)
            .env("ARCHIVE", &path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(server.connections.load(Ordering::SeqCst), 0);
        assert_eq!(
            fs::read_dir(harness.root.path().join("tmp"))
                .unwrap()
                .count(),
            0
        );
    }
}

#[test]
fn docker_archive_dry_run_does_not_publish() {
    let server = Server::new(|request| {
        assert!(matches!(request.method.as_str(), "GET" | "HEAD"));
        Response::new(404, vec![])
    });
    let harness = Harness::new(&[(&server.host, true)]);
    let path = harness.root.path().join("image.tar");
    archive(&path, "valid");
    let result = harness.json(
        &[
            "image",
            "push",
            path.to_str().unwrap(),
            &format!("{}/app:v1", server.host),
            "--dry-run",
        ],
        0,
    );
    assert_eq!(result["data"]["stats"]["planned_blobs"], 2);
}

#[test]
fn oci_archives_ignore_docker_metadata_and_preserve_manifest_bytes() {
    let (server, manifests) = registry();
    let mut harness = Harness::new(&[(&server.host, true)]);
    let image = support::image_layout(harness.root.path(), 1, 8192);
    let path = harness.root.path().join("mixed.tar");
    let mut tar = tar::Builder::new(fs::File::create(&path).unwrap());
    let mut header = tar::Header::new_gnu();
    header.set_size(32768);
    header.set_mode(0o600);
    header.set_cksum();
    tar.append_data(&mut header, "manifest.json", vec![b'x'; 32768].as_slice())
        .unwrap();
    tar.append_dir_all(".", &image.directory).unwrap();
    tar.finish().unwrap();
    drop(tar);
    harness.config.transfer.max_temp_size = "12KiB".into();
    let result = harness.json(
        &[
            "image",
            "push",
            path.to_str().unwrap(),
            &format!("{}/app:v1", server.host),
        ],
        0,
    );
    assert_eq!(result["data"]["converted_from_docker_archive"], false);
    assert_eq!(result["data"]["target_digest"], image.digest);
    assert_eq!(
        manifests.lock().unwrap()["/v2/app/manifests/v1"],
        image.manifest
    );
}

fn hybrid_archive(root: &Path, path: &Path, mode: &str) -> Vec<String> {
    use quayside::model::{Descriptor, OCI_INDEX};
    let mut blobs = BTreeMap::new();
    let mut children = Vec::new();
    let mut saved = Vec::new();
    let mut digests = Vec::new();
    for arch in if mode == "multi" {
        vec!["amd64", "arm64"]
    } else {
        vec!["amd64"]
    } {
        let image = support::image_layout_for(&root.join(arch), 1, 32, arch);
        let manifest: Value = serde_json::from_slice(&image.manifest).unwrap();
        let config = manifest["config"]["digest"].as_str().unwrap();
        let layers: Vec<_> = manifest["layers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| format!("blobs/{}", d["digest"].as_str().unwrap().replace(':', "/")))
            .collect();
        saved.push(json!({"Config":format!("blobs/{}", config.replace(':', "/")), "RepoTags":["example:v1"],"Layers":layers}));
        digests.push(image.digest.clone());
        let mut child = Descriptor::new(
            OCI_MANIFEST,
            image.digest.parse().unwrap(),
            image.manifest.len() as u64,
        );
        child.platform =
            Some(serde_json::from_value(json!({"os":"linux","architecture":arch})).unwrap());
        children.push(child);
        blobs.extend(image.blobs);
        if mode != "missing" {
            blobs.insert(
                image.digest,
                if mode == "corrupt" {
                    b"{}".to_vec()
                } else {
                    image.manifest
                },
            );
        }
    }
    children.push(Descriptor::new(
        OCI_MANIFEST,
        Digest::sha256(b"unsaved platform"),
        1024,
    ));
    if mode == "duplicate_descriptor" {
        children.push(children[0].clone());
    }
    if mode == "conflicting_config" {
        let mut conflicting = saved[0].clone();
        conflicting["Layers"] = json!([]);
        saved.insert(0, conflicting);
    }
    let nested =
        serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":children}))
            .unwrap();
    let descriptor = Descriptor::new(OCI_INDEX, Digest::sha256(&nested), nested.len() as u64);
    blobs.insert(descriptor.digest.to_string(), nested);
    let roots = if mode == "shared_depth" {
        let branch = serde_json::to_vec(
            &json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":[descriptor.clone()]}),
        )
        .unwrap();
        let branch_descriptor =
            Descriptor::new(OCI_INDEX, Digest::sha256(&branch), branch.len() as u64);
        blobs.insert(branch_descriptor.digest.to_string(), branch);
        // The shared subtree is visited on the shallow path before the deeper branch.
        vec![branch_descriptor, descriptor]
    } else {
        vec![descriptor]
    };
    let mut tar = tar::Builder::new(fs::File::create(path).unwrap());
    for (name, raw) in blobs
        .into_iter()
        .map(|(digest, raw)| (format!("blobs/{}", digest.replace(':', "/")), raw))
        .chain([
            (
                "oci-layout".into(),
                br#"{"imageLayoutVersion":"1.0.0"}"#.to_vec(),
            ),
            (
                "index.json".into(),
                serde_json::to_vec(
                    &json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":roots}),
                )
                .unwrap(),
            ),
            ("manifest.json".into(), serde_json::to_vec(&saved).unwrap()),
        ])
    {
        let mut h = tar::Header::new_gnu();
        h.set_size(raw.len() as u64);
        h.set_mode(0o600);
        h.set_cksum();
        tar.append_data(&mut h, name, raw.as_slice()).unwrap();
    }
    tar.finish().unwrap();
    digests
}

#[test]
fn docker_oci_archives_preserve_saved_platforms_and_reject_missing_selected_images() {
    for mode in [
        "single",
        "multi",
        "missing",
        "corrupt",
        "conflicting_config",
    ] {
        let (server, manifests) = registry();
        let harness = Harness::new(&[(&server.host, true)]);
        let path = harness.root.path().join("docker.tar");
        let digests = hybrid_archive(harness.root.path(), &path, mode);
        let bad = matches!(mode, "missing" | "corrupt" | "conflicting_config");
        let result = harness.json(
            &[
                "image",
                "push",
                path.to_str().unwrap(),
                &format!("{}/app:v1", server.host),
                "--ref",
                "example:v1",
            ],
            if bad { 7 } else { 0 },
        );
        if bad {
            assert_eq!(server.connections.load(Ordering::SeqCst), 0);
        } else if mode == "single" {
            assert_eq!(result["data"]["target_digest"], digests[0]);
            assert_eq!(result["data"]["converted_from_docker_archive"], false);
        } else {
            let root: Value =
                serde_json::from_slice(&manifests.lock().unwrap()["/v2/app/manifests/v1"]).unwrap();
            let actual: std::collections::BTreeSet<_> = root["manifests"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| d["digest"].as_str().unwrap().to_owned())
                .collect();
            assert_eq!(actual, digests.into_iter().collect());
            assert_eq!(result["data"]["stats"]["copied_blobs"], 3);
        }
    }
}

#[test]
fn docker_oci_selection_counts_metadata_and_accepts_shared_descriptors_at_the_limit() {
    let (server, _) = registry();
    let mut harness = Harness::new(&[(&server.host, true)]);
    let path = harness.root.path().join("docker.tar");
    hybrid_archive(harness.root.path(), &path, "duplicate_descriptor");
    let mut archive = tar::Archive::new(fs::File::open(&path).unwrap());
    let manifest_bytes: u64 = archive
        .entries()
        .unwrap()
        .map(|entry| {
            use std::io::Read;
            let mut entry = entry.unwrap();
            let mut raw = Vec::new();
            entry.read_to_end(&mut raw).unwrap();
            serde_json::from_slice::<Value>(&raw)
                .ok()
                .filter(|value| value.get("schemaVersion").is_some())
                .map_or(0, |_| raw.len() as u64)
        })
        .sum();
    harness.config.transfer.max_manifest_size = manifest_bytes.to_string();
    harness.config.transfer.max_metadata_size = manifest_bytes.to_string();
    let destination = format!("{}/app:v1", server.host);
    let error = harness.json(&["image", "push", path.to_str().unwrap(), &destination], 2);
    let message = error["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("Docker archive metadata exceeds limit")
            || message.contains("layout metadata exceeds size limit"),
        "{error}"
    );
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);

    harness.config.transfer.max_metadata_size = "64MiB".into();
    harness.config.transfer.max_objects = 3;
    harness.json(&["image", "push", path.to_str().unwrap(), &destination], 0);
}

#[test]
fn docker_oci_shared_subtrees_obey_depth_limits_on_every_path() {
    let (server, _) = registry();
    let mut harness = Harness::new(&[(&server.host, true)]);
    let path = harness.root.path().join("docker.tar");
    hybrid_archive(harness.root.path(), &path, "shared_depth");
    let destination = format!("{}/app:v1", server.host);
    harness.config.transfer.max_depth = 2;
    let error = harness.json(&["image", "push", path.to_str().unwrap(), &destination], 2);
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Docker archive manifest graph exceeds limits"),
        "{error}"
    );
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);

    harness.config.transfer.max_depth = 3;
    harness.json(&["image", "push", path.to_str().unwrap(), &destination], 0);
}

#[test]
fn cancelling_docker_export_terminates_child_and_cleans_staging() {
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let harness = Harness::new(&[]);
    let pid_file = harness.root.path().join("docker.pid");
    let bin = docker_cli(
        &harness,
        "printf '%s' \"$$\" > \"$PID_FILE\"\nexec /bin/sleep 30",
    );
    let mut child = harness
        .command(&[
            "--json",
            "image",
            "push",
            "--docker",
            "example:v1",
            "example.invalid/app:v1",
        ])
        .env("PATH", bin)
        .env("PID_FILE", &pid_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while fs::read_to_string(&pid_file).unwrap_or_default().is_empty() {
        if Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("Docker exporter did not start");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let docker_pid = fs::read_to_string(pid_file).unwrap();
    assert!(
        Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(130));
    let deadline = Instant::now() + Duration::from_secs(5);
    while Command::new("kill")
        .args(["-0", &docker_pid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
    {
        assert!(
            Instant::now() < deadline,
            "Docker exporter survived cancellation"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fs::read_dir(harness.root.path().join("tmp"))
            .unwrap()
            .count(),
        0
    );
}
