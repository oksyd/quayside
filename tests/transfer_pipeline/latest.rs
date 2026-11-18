use super::*;
use quayside::model::{OCI_INDEX, OCI_MANIFEST};
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

#[test]
fn latest_copy_inherits_versions_and_repeated_runs_skip_existing_content() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 1, 1024);
    let digest = image.digest.clone();
    let version = Arc::new(AtomicUsize::new(9));
    let current = version.clone();
    let source = Server::new(move |request| {
        if request.path == "/v2/app/tags/list?n=1000" {
            Response::new(
                200,
                serde_json::to_vec(&json!({"tags": [
                    "latest", "stable", "2", "2.8.99", "3.0.0-rc.1",
                    format!("2.{}.0", current.load(Ordering::SeqCst))
                ]}))
                .unwrap(),
            )
        } else {
            if request.path.contains("/manifests/") {
                assert_eq!(
                    request.path,
                    format!("/v2/app/manifests/2.{}.0", current.load(Ordering::SeqCst))
                );
            }
            serve_image(&image, &request)
        }
    });
    let uploads = Arc::new(AtomicUsize::new(0));
    let count = uploads.clone();
    let target = destination(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        true
    });
    let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    let src = format!("{}/app", source.host);
    let dst = format!("{}/app", target.host);
    let args = ["image", "copy", &src, &dst, "--latest"];
    let first = harness.json(&args, 0);
    assert_eq!(first["data"]["source"], format!("{src}:2.9.0"));
    assert_eq!(first["data"]["destination"], format!("{dst}:2.9.0"));
    assert_eq!(first["data"]["source_digest"], digest);
    assert_eq!(first["data"]["target_digest"], digest);
    assert_eq!(first["data"]["stats"]["copied_blobs"], 2);
    let written = uploads.load(Ordering::SeqCst);
    assert!(written > 0);
    let again = harness.json(&args, 0);
    assert_eq!(again["data"]["already_present"], true);
    assert_eq!(again["data"]["stats"]["copied_blobs"], 0);
    assert_eq!(again["data"]["stats"]["skipped_blobs"], 2);
    assert_eq!(uploads.load(Ordering::SeqCst), written);

    version.store(10, Ordering::SeqCst);
    let next = harness.json(&args, 0);
    assert_eq!(next["data"]["source"], format!("{src}:2.10.0"));
    assert_eq!(next["data"]["destination"], format!("{dst}:2.10.0"));
    assert_eq!(next["data"]["already_present"], false);
    assert_eq!(next["data"]["stats"]["copied_blobs"], 0);
    let previous = harness.json(&["image", "digest", &format!("{dst}:2.9.0")], 0);
    assert_eq!(previous["data"]["digest"], digest);
}

#[test]
fn latest_copy_tracks_image_and_base_versions_without_replacing_old_version_tags() {
    let roots: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    let images: Vec<_> = roots
        .iter()
        .enumerate()
        .map(|(i, root)| image_layout(root.path(), i + 1, 1024))
        .collect();
    let digests: Vec<_> = images.iter().map(|image| image.digest.clone()).collect();
    let versions = [
        "1.31.8-alpine3.24-slim",
        "1.31.8-alpine3.25-slim",
        "1.32.0-alpine3.24-slim",
    ];
    let current = Arc::new(AtomicUsize::new(0));
    let published = current.clone();
    let source = Server::new(move |request| {
        let index = published.load(Ordering::SeqCst);
        if request.path.contains("/tags/list") {
            let mut tags = versions[..=index].to_vec();
            tags.extend(["1.31.8-alpine3.9-slim", "9.99.99-alpine-slim", "latest"]);
            return Response::new(200, serde_json::to_vec(&json!({"tags":tags})).unwrap());
        }
        if request.path.contains("/manifests/") {
            assert_eq!(
                request.path,
                format!("/v2/app/manifests/{}", versions[index])
            );
        }
        serve_image(&images[index], &request)
    });
    let target = destination(|_| true);
    let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    let src = format!("{}/app", source.host);
    let dst = format!("{}/app", target.host);
    let args = [
        "image",
        "copy",
        &src,
        &dst,
        "--latest",
        "--match",
        "*.*.*-alpine*.*-slim",
    ];
    for (i, version) in versions.iter().enumerate() {
        current.store(i, Ordering::SeqCst);
        let result = harness.json(&args, 0);
        assert_eq!(result["data"]["source"], format!("{src}:{version}"));
        assert_eq!(result["data"]["destination"], format!("{dst}:{version}"));
        assert_eq!(result["data"]["target_digest"], digests[i]);
        assert_eq!(result["data"]["already_present"], false);
        let repeat = harness.json(&args, 0);
        assert_eq!(repeat["data"]["already_present"], true);
        assert_eq!(repeat["data"]["stats"]["copied_blobs"], 0);
    }
    for (version, digest) in versions.iter().zip(digests) {
        let result = harness.json(&["image", "digest", &format!("{dst}:{version}")], 0);
        assert_eq!(result["data"]["digest"], digest);
    }
}

#[test]
fn latest_copy_preserves_exact_version_prefixes_and_variant_suffixes_in_dry_runs() {
    for (selector, expected) in [
        (&[][..], "v2.10.0"),
        (&["--variant", "alpine"], "v2.10.1-alpine"),
        (&["--match", "*.*-trixie"], "18.10-trixie"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let image = image_layout(root.path(), 1, 1024);
        let source = Server::new(move |request| {
            if request.path.contains("/tags/list") {
                return Response::new(
                    200,
                    br#"{"tags":[
                        "2.9.99","v2.10.0","2.10.0-alpine","v2.10.1-alpine","3.0.0-alpine3.22","3.0.0-rc.1",
                        "18.9-trixie","18.10-trixie","19-trixie","19.0.1-trixie","19.0-bookworm","19rc1-trixie"
                    ]}"#.to_vec(),
                );
            }
            if request.path.contains("/manifests/") {
                assert!(request.path.ends_with(expected));
            }
            serve_image(&image, &request)
        });
        let target = Server::new(|request| {
            assert!(matches!(request.method.as_str(), "GET" | "HEAD"));
            Response::new(404, vec![])
        });
        let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
        let src = format!("{}/app", source.host);
        let dst = format!("{}/app", target.host);
        let mut args = vec!["image", "copy", &src, &dst, "--latest", "--dry-run"];
        args.extend_from_slice(selector);
        let result = harness.json(&args, 0);
        assert_eq!(result["data"]["source"], format!("{src}:{expected}"));
        assert_eq!(result["data"]["destination"], format!("{dst}:{expected}"));
        assert_eq!(result["data"]["dry_run"], true);
        assert_eq!(result["data"]["stats"]["planned_blobs"], 2);
        let output = harness.output(&args, 0);
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(&format!("Selected {src}:{expected} -> {dst}:{expected}")));
        args.push("--quiet");
        let output = harness.output(&args, 0);
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn latest_copy_keeps_explicit_destinations_and_requires_overwrite_for_tag_updates() {
    let old_root = tempfile::tempdir().unwrap();
    let new_root = tempfile::tempdir().unwrap();
    let old = image_layout(old_root.path(), 1, 1024);
    let new = image_layout(new_root.path(), 2, 1024);
    let digest = new.digest.clone();
    let updated = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let current = updated.clone();
    let source = Server::new(move |request| {
        let image = if current.load(Ordering::SeqCst) {
            &new
        } else {
            &old
        };
        if request.path.contains("/tags/list") {
            let tags = if current.load(Ordering::SeqCst) {
                vec!["1.0.0", "1.0.1"]
            } else {
                vec!["1.0.0"]
            };
            return Response::new(200, serde_json::to_vec(&json!({"tags":tags})).unwrap());
        }
        serve_image(image, &request)
    });
    let target = destination(|_| true);
    let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    let src = format!("{}/app", source.host);
    let dst = format!("{}/app:stable", target.host);
    let mut args = vec!["image", "copy", &src, &dst, "--latest"];
    let first = harness.json(&args, 0);
    assert_eq!(first["data"]["destination"], dst);
    updated.store(true, Ordering::SeqCst);
    let conflict = harness.json(&args, 8);
    assert_eq!(conflict["error"]["code"], "CONFLICT");
    assert_eq!(conflict["data"]["remote_writes_may_have_occurred"], false);
    args.push("--overwrite");
    let next = harness.json(&args, 0);
    assert_eq!(next["data"]["source"], format!("{src}:1.0.1"));
    assert_eq!(next["data"]["destination"], dst);
    assert_eq!(next["data"]["target_digest"], digest);

    let pinned = format!("{}/app@{digest}", target.host);
    let result = harness.json(&["image", "copy", &src, &pinned, "--latest"], 0);
    assert_eq!(result["data"]["destination"], pinned);
    assert_eq!(result["data"]["target_digest"], digest);
}

#[test]
fn latest_copy_rejects_invalid_inputs_before_network_requests() {
    let server = Server::new(|_| panic!("invalid options must not start a request"));
    let harness = Harness::new(&[(&server.host, true)]);
    let repo = format!("{}/app", server.host);
    let tagged = format!("{repo}:latest");
    let pinned = format!("{repo}@{}", Digest::sha256(b"manifest"));
    for source in [&tagged, &pinned] {
        let result = harness.json(&["image", "copy", source, &repo, "--latest"], 2);
        assert_eq!(result["error"]["code"], "INVALID_INPUT");
        assert_eq!(result["data"]["remote_writes_may_have_occurred"], false);
    }
    for variant in ["", "bad/suffix", "bad suffix"] {
        let result = harness.json(
            &[
                "image",
                "copy",
                &repo,
                &repo,
                "--latest",
                "--variant",
                variant,
            ],
            2,
        );
        assert!(
            result["error"]["message"]
                .as_str()
                .unwrap()
                .contains("variant")
        );
    }
    harness.json(&["image", "copy", &tagged, &repo], 2);
    harness.json(&["image", "copy", &repo, "nginx", "--latest"], 2);
    let output = harness.output(&["image", "copy", &repo, &tagged, "--variant", "alpine"], 2);
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("--latest")
    );
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn latest_copy_does_not_fall_back_to_aliases_or_older_versions() {
    for tags in [
        vec!["latest", "stable", "2", "2.0.0-rc.1"],
        vec!["1.0.0", "2.0.0"],
    ] {
        let missing_release = tags.contains(&"2.0.0");
        let source = Server::new(move |request| {
            if request.path.contains("/tags/list") {
                Response::new(200, serde_json::to_vec(&json!({"tags": tags})).unwrap())
            } else {
                assert!(missing_release);
                assert_eq!(request.path, "/v2/app/manifests/2.0.0");
                Response::new(404, vec![])
            }
        });
        let target = Server::new(|_| panic!("failed selection must not contact the destination"));
        let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
        let result = harness.json(
            &[
                "image",
                "copy",
                &format!("{}/app", source.host),
                &format!("{}/app", target.host),
                "--latest",
            ],
            4,
        );
        assert_eq!(result["error"]["code"], "NOT_FOUND");
        assert_eq!(result["data"]["remote_writes_may_have_occurred"], false);
        assert_eq!(target.connections.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn latest_copy_resolves_once_at_the_origin_and_downloads_pinned_content_from_mirrors() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 1, 1024);
    let index = serde_json::to_vec(&json!({
        "schemaVersion": 2, "mediaType": OCI_INDEX,
        "manifests": [{"mediaType": OCI_MANIFEST, "digest": image.digest, "size": image.manifest.len()}]
    })).unwrap();
    let digest = Digest::sha256(&index).to_string();
    let reads = Arc::new(AtomicUsize::new(0));
    let tag_reads = reads.clone();
    let origin = Server::new(move |request| {
        assert_eq!(request.method, "GET");
        let path = request
            .path
            .strip_prefix("http://registry-1.docker.io/v2/library/nginx/")
            .unwrap();
        match path {
            "tags/list?n=1000" => Response::new(200, br#"{"tags":["2.9.0"]}"#.to_vec()).header(
                "Link",
                "</v2/library/nginx/tags/list?last=2.9.0>; rel=\"next\"",
            ),
            "tags/list?last=2.9.0" => Response::new(200, br#"{"tags":["2.10.0"]}"#.to_vec()),
            "manifests/2.10.0" => {
                // A mutable tag disappearing after resolution must not affect the transfer.
                if tag_reads.fetch_add(1, Ordering::SeqCst) == 0 {
                    Response::new(200, index.clone()).header("Content-Type", OCI_INDEX)
                } else {
                    Response::new(404, vec![])
                }
            }
            _ => panic!("all pinned content is available on the mirror: {path}"),
        }
    });
    let mirror = Server::new(move |request| {
        if request.path.contains("/manifests/") {
            assert_eq!(
                request.path,
                format!("/v2/library/nginx/manifests/{}", image.digest)
            );
        } else {
            assert!(request.path.starts_with("/v2/library/nginx/blobs/sha256:"));
        }
        serve_image(&image, &request)
    });
    let target = destination(|_| true);
    let harness = Harness::new(&[("docker.io", true), (&target.host, true)]);
    fs::write(
        harness.daemon_config(),
        serde_json::to_vec(&json!({
            "registry-mirrors": [format!("http://{}", mirror.host)],
            "proxies": {"http-proxy": format!("http://{}", origin.host), "no-proxy": "127.0.0.1"}
        }))
        .unwrap(),
    )
    .unwrap();
    let result = harness.json(
        &[
            "image",
            "copy",
            "nginx",
            &format!("{}/app", target.host),
            "--latest",
            "--all",
        ],
        0,
    );
    assert_eq!(result["data"]["source"], "docker.io/library/nginx:2.10.0");
    assert_eq!(
        result["data"]["destination"],
        format!("{}/app:2.10.0", target.host)
    );
    assert_eq!(result["data"]["source_digest"], digest);
    assert_eq!(result["data"]["target_digest"], digest);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert!(mirror.connections.load(Ordering::SeqCst) >= 3);
}
