use super::{destination, support};
use quayside::{
    digest::Digest,
    model::{Descriptor, OCI_INDEX, OCI_MANIFEST},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use support::{Harness, Response, Server};

struct Fixture {
    _root: tempfile::TempDir,
    source: Server,
    target: Server,
    harness: Harness,
    blobs: BTreeMap<String, Vec<u8>>,
    local: BTreeMap<String, Vec<u8>>,
    reads: Arc<Mutex<BTreeMap<String, usize>>>,
    digest: String,
    selected_digest: String,
}

impl Fixture {
    fn new(multiple: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut blobs = BTreeMap::new();
        let mut manifests = BTreeMap::new();
        let mut children = vec![];
        let mut local = BTreeMap::new();
        let mut single = vec![];
        let mut selected_digest = String::new();
        for (arch, size) in if multiple {
            vec![("amd64", 16384), ("arm64", 32768)]
        } else {
            vec![("amd64", 16384)]
        } {
            let image = support::image_layout_for(&root.path().join(arch), 3, size, arch);
            let mut descriptor = Descriptor::new(
                OCI_MANIFEST,
                image.digest.parse().unwrap(),
                image.manifest.len() as u64,
            );
            descriptor.platform = Some(format!("linux/{arch}").parse().unwrap());
            children.push(descriptor);
            if arch == "amd64" {
                local = image.blobs.clone();
                selected_digest = image.digest.clone();
            }
            blobs.extend(image.blobs);
            single = image.manifest.clone();
            manifests.insert(image.digest, image.manifest);
        }
        let manifest = if multiple {
            serde_json::to_vec(
                &json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":children}),
            )
            .unwrap()
        } else {
            single
        };
        let digest = Digest::sha256(&manifest).to_string();
        manifests.insert("latest".into(), manifest);
        let reads = Arc::new(Mutex::new(BTreeMap::new()));
        let recorded = reads.clone();
        let bodies = blobs.clone();
        let source = Server::new(move |request| {
            assert_eq!(request.method, "GET");
            let key = request.path.rsplit('/').next().unwrap();
            if request.path.contains("/manifests/") {
                let raw = manifests[key].clone();
                let kind = serde_json::from_slice::<Value>(&raw).unwrap()["mediaType"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                Response::new(200, raw).header("Content-Type", &kind)
            } else {
                *recorded.lock().unwrap().entry(key.into()).or_default() += 1;
                Response::new(200, bodies[key].clone())
            }
        });
        let target = destination(|_| true);
        let mut harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
        harness.config.transfer.max_temp_size = "1MiB".into();
        Self {
            _root: root,
            source,
            target,
            harness,
            blobs,
            local,
            reads,
            digest,
            selected_digest,
        }
    }

    fn docker(&self, entries: &BTreeMap<String, Vec<u8>>) -> PathBuf {
        let path = self.harness.root.path().join("docker.tar");
        let mut tar = tar::Builder::new(fs::File::create(&path).unwrap());
        for (digest, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            tar.append_data(
                &mut header,
                format!("blobs/{}", digest.replace(':', "/")),
                bytes.as_slice(),
            )
            .unwrap();
        }
        tar.finish().unwrap();
        let bin = self.harness.root.path().join("docker-bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(
            bin.join("docker"),
            r##"#!/bin/sh
printf '%s\n' "$2" >> "$DOCKER_CALLS"
[ "$1" = image ] || exit 21
case "$2" in
  inspect)
    [ "$3" = --format ] && [ "$5" = -- ] || exit 22
    [ "$DOCKER_BEHAVIOR" = missing ] && exit 1
    [ "$DOCKER_BEHAVIOR" = legacy ] && exit 0
    [ "$DOCKER_BEHAVIOR" = inspect_timeout ] && exec sleep 30
    printf '%s\n' "$DOCKER_IMAGE_ID"
    ;;
  save)
    [ "$3" = -- ] && [ "$4" = "$DOCKER_IMAGE_ID" ] || exit 23
    [ "$DOCKER_BEHAVIOR" = export_failure ] && exit 1
    [ "$DOCKER_BEHAVIOR" = export_timeout ] && exec sleep 30
    cat "$DOCKER_ARCHIVE"
    ;;
  *) exit 24 ;;
esac
"##,
        )
        .unwrap();
        fs::set_permissions(bin.join("docker"), fs::Permissions::from_mode(0o700)).unwrap();
        bin
    }

    fn run(&self, bin: &Path, behavior: &str, extra: &[&str]) -> Value {
        let mut command = self.harness.command(&[
            "--json",
            "image",
            "copy",
            &format!("{}/app:latest", self.source.host),
            &format!("{}/app:v1", self.target.host),
        ]);
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut child = command
            .args(extra)
            .env(
                "PATH",
                std::env::join_paths(
                    std::iter::once(bin.to_path_buf()).chain(std::env::split_paths(&path)),
                )
                .unwrap(),
            )
            .env(
                "DOCKER_IMAGE_ID",
                Digest::sha256(b"local image snapshot").to_string(),
            )
            .env(
                "DOCKER_ARCHIVE",
                self.harness.root.path().join("docker.tar"),
            )
            .env("DOCKER_CALLS", self.harness.root.path().join("calls"))
            .env("DOCKER_BEHAVIOR", behavior)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if start.elapsed() > Duration::from_secs(10) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("Docker cache stalled the copy pipeline");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_dir(self.harness.root.path().join("tmp"))
                .unwrap()
                .count(),
            0
        );
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            result["data"]["target_digest"],
            if extra.contains(&"--platform") {
                self.selected_digest.as_str()
            } else {
                self.digest.as_str()
            }
        );
        result
    }
}

#[test]
fn matching_docker_blobs_skip_downloads_and_export_once() {
    let fixture = Fixture::new(false);
    let bin = fixture.docker(&fixture.local);
    let result = fixture.run(&bin, "", &[]);
    assert_eq!(result["data"]["stats"]["reused_blobs"], 3);
    assert_eq!(result["data"]["stats"]["copied_blobs"], 4);
    let reads = fixture.reads.lock().unwrap();
    assert_eq!(
        reads.values().sum::<usize>(),
        1,
        "only config metadata is fetched"
    );
    let config_size = fixture
        .blobs
        .iter()
        .find(|(digest, _)| reads.contains_key(*digest))
        .unwrap()
        .1
        .len() as u64;
    assert_eq!(
        result["data"]["stats"]["bytes_transferred"],
        3 * 16384 + 2 * config_size
    );
    assert_eq!(
        fs::read_to_string(fixture.harness.root.path().join("calls")).unwrap(),
        "inspect\nsave\n"
    );
}

#[test]
fn partial_local_platforms_preserve_the_complete_remote_index() {
    let fixture = Fixture::new(true);
    let bin = fixture.docker(&fixture.local);
    let result = fixture.run(&bin, "", &[]);
    assert_eq!(result["data"]["stats"]["reused_blobs"], 4);
    assert_eq!(result["data"]["stats"]["copied_blobs"], 8);
    assert_eq!(
        result["data"]["platforms"],
        json!(["linux/amd64", "linux/arm64"])
    );
    let reads = fixture.reads.lock().unwrap();
    assert!(
        fixture
            .local
            .keys()
            .all(|digest| !reads.contains_key(digest))
    );
    assert_eq!(reads.values().sum::<usize>(), 4);
}

#[test]
fn docker_cache_respects_explicit_platform_selection() {
    let fixture = Fixture::new(true);
    let bin = fixture.docker(&fixture.local);
    let result = fixture.run(&bin, "", &["--platform", "linux/amd64"]);
    assert_eq!(result["data"]["stats"]["reused_blobs"], 4);
    assert_eq!(result["data"]["stats"]["copied_blobs"], 4);
    assert_eq!(result["data"]["platforms"], json!(["linux/amd64"]));
    assert_eq!(fixture.reads.lock().unwrap().values().sum::<usize>(), 0);
}

#[test]
fn stale_and_corrupt_local_blobs_fall_back_without_changing_remote_content() {
    for stale in [false, true] {
        let fixture = Fixture::new(false);
        let mut local = fixture.local.clone();
        let key = local
            .iter()
            .find(|(_, bytes)| bytes.len() == 16384)
            .unwrap()
            .0
            .clone();
        let mut raw = local.remove(&key).unwrap();
        raw[0] ^= 1;
        local.insert(
            if stale {
                Digest::sha256(&raw).to_string()
            } else {
                key.clone()
            },
            raw,
        );
        let bin = fixture.docker(&local);
        let result = fixture.run(&bin, "", &[]);
        assert_eq!(result["data"]["stats"]["reused_blobs"], 2);
        assert_eq!(fixture.reads.lock().unwrap()[&key], 1);
    }
}

#[test]
fn unavailable_or_failing_docker_is_an_optional_cache_miss() {
    for behavior in [
        "missing",
        "legacy",
        "export_failure",
        "inspect_timeout",
        "export_timeout",
    ] {
        let mut fixture = Fixture::new(false);
        fixture.harness.config.transfer.connect_timeout = "500ms".into();
        fixture.harness.config.transfer.idle_timeout = "500ms".into();
        let bin = fixture.docker(&fixture.local);
        let result = fixture.run(&bin, behavior, &[]);
        assert_eq!(result["data"]["stats"]["reused_blobs"], 0, "{behavior}");
        assert_eq!(fixture.reads.lock().unwrap().values().sum::<usize>(), 4);
        if matches!(behavior, "missing" | "legacy" | "inspect_timeout") {
            assert_eq!(
                fs::read_to_string(fixture.harness.root.path().join("calls")).unwrap(),
                "inspect\n"
            );
        }
    }
}

#[test]
fn insufficient_cache_space_falls_back_without_starving_workers() {
    for limit in ["16KiB", "18KiB", "80KiB"] {
        let mut fixture = Fixture::new(false);
        fixture.harness.config.transfer.max_temp_size = limit.into();
        let bin = fixture.docker(&fixture.local);
        let result = fixture.run(&bin, "", &[]);
        assert_eq!(
            result["data"]["stats"]["reused_blobs"],
            if limit == "80KiB" { 3 } else { 0 }
        );
    }
}

#[test]
fn dry_runs_and_existing_destinations_never_probe_docker() {
    let fixture = Fixture::new(false);
    let bin = fixture.docker(&fixture.local);
    let result = fixture.run(&bin, "", &["--dry-run"]);
    assert_eq!(result["data"]["stats"]["planned_blobs"], 4);
    assert!(!fixture.harness.root.path().join("calls").exists());
    fixture.run(&bin, "", &[]);
    fs::remove_file(fixture.harness.root.path().join("calls")).unwrap();
    let result = fixture.run(&bin, "", &[]);
    assert_eq!(result["data"]["stats"]["skipped_blobs"], 4);
    assert!(!fixture.harness.root.path().join("calls").exists());
}

#[test]
fn malformed_docker_exports_fall_back_before_uploading_unverified_bytes() {
    let fixture = Fixture::new(false);
    let bin = fixture.docker(&fixture.local);
    fs::write(
        fixture.harness.root.path().join("docker.tar"),
        b"invalid archive",
    )
    .unwrap();
    let result = fixture.run(&bin, "", &[]);
    assert_eq!(result["data"]["stats"]["reused_blobs"], 0);
}
