//! Opt-in tests against disposable Distribution registries, with an optional local Docker export.
mod support;
use std::{env, fs};
use support::{Harness, image_layout, image_layout_for};

#[test]
#[ignore = "requires QUAYSIDE_TEST_SOURCE and QUAYSIDE_TEST_TARGET disposable HTTP registries"]
fn distribution_round_trip_copy_limits_and_mount() {
    let source = env::var("QUAYSIDE_TEST_SOURCE").expect("set QUAYSIDE_TEST_SOURCE=127.0.0.1:port");
    let target = env::var("QUAYSIDE_TEST_TARGET").expect("set QUAYSIDE_TEST_TARGET=127.0.0.1:port");
    assert_ne!(source, target);
    let mut harness = Harness::new(&[(&source, true), (&target, true)]);
    let image = image_layout(harness.root.path(), 4, 4096);
    let run = format!("quayside-{}", std::process::id());
    let src = format!("{source}/{run}/source:v1");
    let dst = format!("{target}/{run}/target:v1");
    harness.json(
        &["image", "push", image.directory.to_str().unwrap(), &src],
        0,
    );
    harness.config.transfer.max_temp_size = "1KiB".into();
    let rejected = harness.json(&["image", "copy", &src, &dst], 2);
    assert!(
        rejected["error"]["message"]
            .as_str()
            .unwrap()
            .contains("max_temp_size")
    );
    harness.json(&["image", "digest", &dst], 4);
    harness.config.transfer.max_temp_size = "4KiB".into();
    let copied = harness.json(&["image", "copy", &src, &dst], 0);
    assert_eq!(copied["data"]["target_digest"], image.digest);
    assert_eq!(
        copied["data"]["platforms"],
        serde_json::json!(["linux/arm64/v8"])
    );
    assert_eq!(copied["data"]["stats"]["copied_blobs"], 5);
    assert_eq!(
        fs::read_dir(harness.root.path().join("tmp"))
            .unwrap()
            .count(),
        0
    );
    let repeated = harness.json(&["image", "copy", &src, &dst], 0);
    assert_eq!(repeated["data"]["stats"]["copied_blobs"], 0);
    assert_eq!(repeated["data"]["stats"]["skipped_blobs"], 5);
    let mounted = format!("{source}/{run}/mounted:v1");
    let result = harness.json(&["image", "copy", &src, &mounted], 0);
    assert_eq!(result["data"]["stats"]["mounted_blobs"], 5);
    let dry = format!("{target}/{run}/dry:v1");
    harness.json(&["image", "copy", &src, &dry, "--dry-run"], 0);
    harness.json(&["image", "digest", &dry], 4);
    harness.config.transfer.max_temp_size = "1MiB".into();
    let archive = harness.root.path().join("image.tar");
    harness.json(
        &["image", "pull", &src, "--output", archive.to_str().unwrap()],
        0,
    );
    let restored = format!("{target}/{run}/restored:v1");
    let result = harness.json(&["image", "push", archive.to_str().unwrap(), &restored], 0);
    assert_eq!(result["data"]["target_digest"], image.digest);
    let other = image_layout_for(&harness.root.path().join("other"), 4, 4096, "amd64");
    let amd64 = format!("{source}/{run}/amd64:v1");
    harness.json(
        &["image", "push", other.directory.to_str().unwrap(), &amd64],
        0,
    );
    let index = format!("{target}/{run}/index:v1");
    let aggregated = harness.json(
        &["index", "create", &index, "--from", &dst, "--from", &amd64],
        0,
    );
    let all = format!("{source}/{run}/all:v1");
    let copied = harness.json(&["image", "copy", &index, &all], 0);
    assert_eq!(
        copied["data"]["target_digest"],
        aggregated["data"]["target_digest"]
    );
    assert_eq!(
        copied["data"]["platforms"],
        serde_json::json!(["linux/amd64", "linux/arm64/v8"])
    );
    let selected = format!("{target}/{run}/selected:v1");
    let selected = harness.json(
        &[
            "image",
            "copy",
            &index,
            &selected,
            "--platform",
            "linux/amd64",
        ],
        0,
    );
    assert_eq!(selected["data"]["target_digest"], other.digest);
    harness.json(&["image", "copy", &index, &dst], 8);
    harness.json(&["image", "copy", &index, &dst, "--overwrite"], 0);
    let tags = harness.json(&["tag", "ls", &format!("{target}/{run}/target")], 0);
    assert_eq!(tags["data"]["tags"], serde_json::json!(["v1"]));

    // Exercise adaptive PATCH chunks followed by a final PUT containing the remaining bytes.
    let chunked = image_layout(&harness.root.path().join("chunked"), 2, 1024 * 1024);
    let src = format!("{source}/{run}/chunked:v1");
    let dst = format!("{target}/{run}/chunked:v1");
    harness.config.transfer.max_temp_size = "2MiB".into();
    harness.json(
        &["image", "push", chunked.directory.to_str().unwrap(), &src],
        0,
    );
    let copied = harness.json(&["image", "copy", &src, &dst], 0);
    assert_eq!(copied["data"]["target_digest"], chunked.digest);
    assert_eq!(copied["data"]["stats"]["copied_blobs"], 3);

    // A large layer exercises Range downloads in both remote copy and persistent layout pull.
    let large = image_layout(&harness.root.path().join("large"), 1, 32 * 1024 * 1024);
    let src = format!("{source}/{run}/large:v1");
    let dst = format!("{target}/{run}/large:v1");
    harness.config.transfer.max_temp_size = "64MiB".into();
    harness.config.transfer.chunk_size = "8MiB".into();
    harness.config.transfer.idle_timeout = "10s".into();
    harness.json(
        &["image", "push", large.directory.to_str().unwrap(), &src],
        0,
    );
    let copied = harness.json(&["image", "copy", &src, &dst], 0);
    assert_eq!(copied["data"]["target_digest"], large.digest);
    let output = harness.root.path().join("large-pull");
    harness.json(
        &[
            "image",
            "pull",
            &dst,
            "--format",
            "oci-layout",
            "-o",
            output.to_str().unwrap(),
        ],
        0,
    );
    for (digest, bytes) in large.blobs {
        let path = output
            .join("blobs/sha256")
            .join(digest.split_once(':').unwrap().1);
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

#[test]
#[ignore = "requires two disposable registries, release build, and at least 40GiB free disk"]
fn ten_gib_layer_has_bounded_memory() {
    use quayside::{
        digest::Digest,
        model::{Descriptor, OCI_INDEX, OCI_MANIFEST},
    };
    use sha2::{Digest as _, Sha256};
    use std::{
        process::Stdio,
        time::{Duration, Instant},
    };
    let source = env::var("QUAYSIDE_TEST_SOURCE").expect("set QUAYSIDE_TEST_SOURCE");
    let target = env::var("QUAYSIDE_TEST_TARGET").expect("set QUAYSIDE_TEST_TARGET");
    assert_ne!(source, target);
    let mut harness = Harness::new(&[(&source, true), (&target, true)]);
    harness.config.transfer.chunk_size = "8MiB".into();
    harness.config.transfer.idle_timeout = "60s".into();
    harness.config.transfer.metadata_timeout = "60s".into();
    harness.config.transfer.max_temp_size = "16GiB".into();
    let image = image_layout(harness.root.path(), 0, 0);
    let size = 10u64 * 1024 * 1024 * 1024;
    let chunk = vec![0; 1024 * 1024];
    let mut hasher = Sha256::new();
    for _ in 0..size / chunk.len() as u64 {
        hasher.update(&chunk);
    }
    let digest: Digest = format!("sha256:{}", hex::encode(hasher.finalize()))
        .parse()
        .unwrap();
    let file =
        fs::File::create(image.directory.join("blobs/sha256").join(digest.encoded())).unwrap();
    file.set_len(size).unwrap();
    drop(file);
    let mut manifest: serde_json::Value = serde_json::from_slice(&image.manifest).unwrap();
    manifest["layers"] = serde_json::json!([Descriptor::new(
        "application/vnd.oci.image.layer.v1.tar",
        digest,
        size
    )]);
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let manifest_digest = Digest::sha256(&bytes);
    fs::write(
        image
            .directory
            .join("blobs/sha256")
            .join(manifest_digest.encoded()),
        &bytes,
    )
    .unwrap();
    fs::write(image.directory.join("index.json"),serde_json::to_vec(&serde_json::json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":[Descriptor::new(OCI_MANIFEST,manifest_digest.clone(),bytes.len() as u64)]})).unwrap()).unwrap();
    let src = format!("{source}/large-{}/source:v1", std::process::id());
    let dst = format!("{target}/large-{}/target:v1", std::process::id());
    harness.json(
        &["image", "push", image.directory.to_str().unwrap(), &src],
        0,
    );
    let start = Instant::now();
    let mut child = harness
        .command(&["--json", "image", "copy", &src, &dst])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut peak_kib = 0u64;
    loop {
        if let Ok(status) = fs::read_to_string(format!("/proc/{}/status", child.id())) {
            for line in status
                .lines()
                .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
            {
                peak_kib = peak_kib.max(line.split_whitespace().nth(1).unwrap().parse().unwrap());
            }
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if start.elapsed() > Duration::from_secs(600) {
            child.kill().unwrap();
            panic!("large transfer timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["data"]["target_digest"], manifest_digest.to_string());
    assert!(
        peak_kib > 0 && peak_kib <= 256 * 1024,
        "peak RSS {peak_kib}KiB exceeds 256MiB"
    );
    let elapsed = start.elapsed();
    println!(
        "10GiB cross-registry copy: elapsed={elapsed:?}, peak_rss_kib={peak_kib}, payload_bytes={}, logical_mib_per_sec={:.2}",
        value["data"]["stats"]["bytes_transferred"],
        size as f64 / elapsed.as_secs_f64() / 1048576.0
    );
    let repeated = harness.json(&["image", "copy", &src, &dst], 0);
    assert_eq!(repeated["data"]["stats"]["bytes_transferred"], 0);
    assert_eq!(
        fs::read_dir(harness.root.path().join("tmp"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
#[ignore = "requires QUAYSIDE_TEST_SOURCE and QUAYSIDE_TEST_TARGET disposable HTTP registries"]
fn distribution_artifact_round_trip() {
    let source = env::var("QUAYSIDE_TEST_SOURCE").unwrap();
    let target = env::var("QUAYSIDE_TEST_TARGET").unwrap();
    let harness = Harness::new(&[(&source, true), (&target, true)]);
    for java in [false, true] {
        let root = harness.root.path().join(format!("artifact-{java}"));
        let artifact = support::artifact_layout(&root, java, false);
        let src = format!("{source}/artifact-{}/{java}:2", std::process::id());
        let dst = format!("{target}/artifact-{}/{java}:2", std::process::id());
        harness.json(
            &["image", "push", artifact.directory.to_str().unwrap(), &src],
            0,
        );
        let copied = harness.json(&["image", "copy", &src, &dst], 0);
        assert_eq!(copied["data"]["target_digest"], artifact.digest);
        assert_eq!(copied["data"]["platforms"], serde_json::json!([]));
        let raw = harness.output(&["manifest", "get", &dst, "--raw"], 0);
        assert_eq!(raw.stdout, artifact.manifest);
        let repeated = harness.json(&["image", "copy", &src, &dst], 0);
        assert_eq!(repeated["data"]["stats"]["copied_blobs"], 0);
        let archive = root.join("db.tar");
        harness.json(&["image", "pull", &dst, "-o", archive.to_str().unwrap()], 0);
        let restored = format!("{source}/artifact-{}/restored-{java}:2", std::process::id());
        let result = harness.json(&["image", "push", archive.to_str().unwrap(), &restored], 0);
        assert_eq!(result["data"]["target_digest"], artifact.digest);
        harness.json(
            &["image", "copy", &src, &dst, "--platform", "linux/amd64"],
            2,
        );
        harness.json(&["index", "create", &restored, "--from", &src], 2);
    }
}

#[test]
#[ignore = "requires Docker, QUAYSIDE_TEST_DOCKER_IMAGE and QUAYSIDE_TEST_TARGET disposable HTTP registry"]
fn docker_local_image_round_trip() {
    let image = env::var("QUAYSIDE_TEST_DOCKER_IMAGE").expect("set QUAYSIDE_TEST_DOCKER_IMAGE");
    let target = env::var("QUAYSIDE_TEST_TARGET").expect("set QUAYSIDE_TEST_TARGET");
    let mut harness = Harness::new(&[(&target, true)]);
    harness.config.transfer.chunk_size = "8MiB".into();
    harness.config.transfer.idle_timeout = "30s".into();
    let dst = format!("{target}/quayside-{}/docker:v1", std::process::id());
    let result = harness.json(&["image", "push", "--docker", &image, &dst], 0);
    let digest = harness.json(&["image", "digest", &dst], 0);
    assert_eq!(result["data"]["target_digest"], digest["data"]["digest"]);
    let output = harness.root.path().join("docker.oci.tar");
    harness.json(&["image", "pull", &dst, "-o", output.to_str().unwrap()], 0);
    let restored = format!(
        "{target}/quayside-{}/docker-restored:v1",
        std::process::id()
    );
    let pushed = harness.json(&["image", "push", output.to_str().unwrap(), &restored], 0);
    assert_eq!(
        pushed["data"]["target_digest"],
        result["data"]["target_digest"]
    );
    assert_eq!(
        fs::read_dir(harness.root.path().join("tmp"))
            .unwrap()
            .count(),
        0
    );
}
