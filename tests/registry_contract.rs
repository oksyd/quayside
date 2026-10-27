mod support;

use bytes::Bytes;
use quayside::{
    Result,
    config::{Config, RegistryConfig},
    digest::Digest,
    error::Code,
    model::{Descriptor, Manifest, OCI_INDEX},
    reference::Reference,
    registry::Registry,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use support::{Response, Server, image_layout};

fn client(server: &Server) -> (Registry, Arc<AtomicBool>) {
    let mut config = Config::default();
    config.transfer.max_retries = 0;
    config.registries.insert(
        server.host.clone(),
        RegistryConfig {
            plain_http: true,
            ..RegistryConfig::default()
        },
    );
    let changed = Arc::new(AtomicBool::new(false));
    (
        Registry::new(&server.host, Arc::new(config), None, changed.clone()).unwrap(),
        changed,
    )
}

fn rejected<T>(result: Result<T>, expected: Code) {
    assert_eq!(
        result.err().expect("invalid input must be rejected").code,
        expected
    );
}

#[tokio::test]
async fn listings_reject_invalid_names_before_exposing_them_to_callers() {
    for (field, invalid) in [
        ("tags", "v1\nforged output"),
        ("tags", "\u{1b}[2J"),
        ("tags", "../other"),
        ("repositories", "team/image\nforged output"),
        ("repositories", "Team/image"),
        ("repositories", "../other"),
    ] {
        let body = serde_json::to_vec(&serde_json::json!({field: [invalid]})).unwrap();
        let server = Server::new(move |_| Response::new(200, body.clone()));
        let (registry, _) = client(&server);
        let result = if field == "tags" {
            registry.list_tags("team/image").await
        } else {
            registry.list_repositories().await
        };
        let error = result.unwrap_err();
        assert_eq!(error.code, Code::InvalidInput);
        assert!(error.message.starts_with(if field == "tags" {
            "invalid image tag"
        } else {
            "invalid repository path"
        }));
        assert!(!error.message.contains(invalid));
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn listing_pages_share_one_metadata_budget_even_with_duplicate_items() {
    let body = serde_json::to_vec(&serde_json::json!({
        "tags": ["v1"], "padding": "x".repeat(700),
    }))
    .unwrap();
    let server = Server::new(move |request| {
        let response = Response::new(200, body.clone());
        if request.path.contains("page=2") {
            response
        } else {
            response.header("Link", "</v2/team/image/tags/list?page=2>; rel=\"next\"")
        }
    });
    let (registry, changed) = client(&server);
    let mut config = registry.config().clone();
    config.transfer.max_manifest_size = "1KiB".into();
    config.transfer.max_metadata_size = "1KiB".into();
    let registry = Registry::new(&server.host, Arc::new(config), None, changed).unwrap();
    rejected(registry.list_tags("team/image").await, Code::InvalidInput);
    assert_eq!(server.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn referrer_listings_validate_duplicates_and_retain_inline_content() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde_json::json;

    let raw = Bytes::from_static(
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#,
    );
    let manifest = Manifest::parse(raw.clone(), None, None).unwrap();
    for mode in ["single", "paginated", "fallback"] {
        for corrupt in [false, true] {
            let descriptor = manifest.descriptor.clone();
            let mut inline = descriptor.clone();
            inline.data = Some(STANDARD.encode(if corrupt { b"corrupt" } else { raw.as_ref() }));
            let server = Server::new(move |request| {
                assert_eq!(request.method, "GET");
                if mode == "fallback" && request.path.contains("/referrers/") {
                    return Response::new(404, vec![]);
                }
                let more = mode == "paginated" && !request.path.contains('?');
                let descriptors = if more {
                    vec![&descriptor]
                } else if mode == "paginated" {
                    vec![&inline]
                } else {
                    vec![&descriptor, &inline]
                };
                let body = serde_json::to_vec(&json!({
                    "schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": descriptors,
                }))
                .unwrap();
                let response = Response::new(200, body).header("Content-Type", OCI_INDEX);
                if more {
                    response.header("Link", &format!("<{}?page=2>; rel=\"next\"", request.path))
                } else {
                    response
                }
            });
            let (registry, changed) = client(&server);
            let reference = format!("{}/team/image@{}", server.host, Digest::sha256(b"subject"))
                .parse()
                .unwrap();
            let result = registry.list_referrers(&reference).await;
            if corrupt {
                rejected(result, Code::Integrity);
            } else {
                let entries = result.unwrap();
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].embedded().unwrap(), Some(raw.clone()), "{mode}");
            }
            assert!(!changed.load(Ordering::SeqCst));
        }
    }
}

#[tokio::test]
async fn manifest_references_cannot_select_another_client_or_escape_repository_paths() {
    let server = Server::new(|_| Response::new(500, vec![]));
    let (registry, changed) = client(&server);
    let directory = tempfile::tempdir().unwrap();
    let image = image_layout(directory.path(), 0, 0);
    let manifest = Manifest::parse(image.manifest.into(), None, None).unwrap();
    let reference: Reference = format!("{}/team/image:v1", server.host).parse().unwrap();
    let mut inputs = vec![Reference {
        registry: "other.example".into(),
        ..reference.clone()
    }];
    for repository in [
        "../other",
        "team/image?other",
        "team/image#other",
        "Team/image",
    ] {
        inputs.push(Reference {
            repository: repository.into(),
            ..reference.clone()
        });
    }
    for selector in [
        "",
        "../other",
        "v1?other",
        "v1#other",
        "%2e%2e",
        "sha256:invalid",
    ] {
        inputs.push(Reference {
            selector: selector.into(),
            ..reference.clone()
        });
    }
    for reference in inputs {
        rejected(registry.get_manifest(&reference).await, Code::InvalidInput);
        rejected(
            registry.manifest_optional(&reference).await,
            Code::InvalidInput,
        );
        rejected(
            registry.put_manifest(&reference, &manifest).await,
            Code::InvalidInput,
        );
    }
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    assert!(!changed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn blob_operations_validate_repositories_before_requests_or_local_writes() {
    let server = Server::new(|_| Response::new(500, vec![]));
    let (registry, changed) = client(&server);
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("existing");
    std::fs::write(&output, b"preserve").unwrap();
    let descriptor = Descriptor::new("application/octet-stream", Digest::sha256(b"blob"), 4);
    let upload = registry
        .endpoint()
        .join("v2/team/image/blobs/uploads/session")
        .unwrap();
    for repo in [
        "../other",
        "team/image?other",
        "team/image#other",
        "Team/image",
    ] {
        rejected(
            registry.blob_exists(repo, &descriptor).await,
            Code::InvalidInput,
        );
        rejected(
            registry.get_blob_bytes(repo, &descriptor, 4).await,
            Code::InvalidInput,
        );
        rejected(
            registry.download_blob(repo, &descriptor, &output).await,
            Code::InvalidInput,
        );
        rejected(
            registry.start_upload(repo, &descriptor.digest, None).await,
            Code::InvalidInput,
        );
        rejected(
            registry
                .start_upload("team/image", &descriptor.digest, Some(repo))
                .await,
            Code::InvalidInput,
        );
        rejected(
            registry
                .patch_upload(repo, upload.clone(), 0, Bytes::from_static(b"blob"))
                .await,
            Code::InvalidInput,
        );
        rejected(
            registry.upload_status(repo, upload.clone()).await,
            Code::InvalidInput,
        );
        rejected(
            registry
                .finish_upload(repo, upload.clone(), &descriptor.digest)
                .await,
            Code::InvalidInput,
        );
        rejected(registry.list_tags(repo).await, Code::InvalidInput);
        rejected(registry.verify_repository(repo).await, Code::InvalidInput);
    }
    assert_eq!(std::fs::read(output).unwrap(), b"preserve");
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    assert!(!changed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn mount_rejection_falls_back_to_one_ordinary_upload_attempt() {
    for (status, expected) in [
        (400, Code::Execution),
        (404, Code::NotFound),
        (405, Code::Unsupported),
    ] {
        let server = Server::new(move |request| {
            assert_eq!(request.method, "POST");
            if request.path.contains("?mount=") {
                Response::new(401, vec![])
            } else {
                assert_eq!(request.path, "/v2/team/image/blobs/uploads/");
                Response::new(status, vec![])
            }
        });
        let (registry, changed) = client(&server);
        rejected(
            registry
                .start_upload("team/image", &Digest::sha256(b"blob"), Some("source/image"))
                .await,
            expected,
        );
        assert_eq!(server.connections.load(Ordering::SeqCst), 2);
        assert!(!changed.load(Ordering::SeqCst));
    }
}

#[tokio::test]
async fn mount_fallback_cannot_claim_that_an_ordinary_upload_was_mounted() {
    for rejected_status in [400, 401] {
        let server = Server::new(move |request| {
            assert_eq!(request.method, "POST");
            if request.path.contains("?mount=") {
                Response::new(rejected_status, vec![])
            } else {
                assert_eq!(request.path, "/v2/team/image/blobs/uploads/");
                Response::new(201, vec![])
            }
        });
        let (registry, changed) = client(&server);
        rejected(
            registry
                .start_upload("team/image", &Digest::sha256(b"blob"), Some("source/image"))
                .await,
            Code::Execution,
        );
        assert_eq!(server.connections.load(Ordering::SeqCst), 2);
        assert!(changed.load(Ordering::SeqCst));
    }
}

#[tokio::test]
async fn upload_chunks_reject_offset_overflow_before_remote_writes() {
    let server = Server::new(|_| panic!("an overflowing upload must fail before a request"));
    let (registry, changed) = client(&server);
    let upload = registry
        .endpoint()
        .join("v2/team/image/blobs/uploads/session")
        .unwrap();
    for (offset, chunk) in [(u64::MAX, "x"), (u64::MAX - 1, "xy")] {
        let error = registry
            .patch_upload("team/image", upload.clone(), offset, Bytes::from(chunk))
            .await
            .unwrap_err();
        assert_eq!(error.code, Code::InvalidInput);
        assert_eq!(error.message, "upload offset overflow");
    }
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    assert!(!changed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn upload_sessions_reject_foreign_origins_before_sending_payloads() {
    let registry_server = Server::new(|_| Response::new(500, vec![]));
    let foreign = Server::new(|_| Response::new(500, vec![]));
    let (registry, changed) = client(&registry_server);
    let digest = Digest::sha256(b"blob");
    let upload = format!("http://{}/upload", foreign.host)
        .parse::<url::Url>()
        .unwrap();
    rejected(
        registry
            .patch_upload("team/image", upload.clone(), 0, Bytes::from_static(b"blob"))
            .await,
        Code::Unsupported,
    );
    rejected(
        registry.upload_status("team/image", upload.clone()).await,
        Code::Unsupported,
    );
    rejected(
        registry.finish_upload("team/image", upload, &digest).await,
        Code::Unsupported,
    );
    assert_eq!(registry_server.connections.load(Ordering::SeqCst), 0);
    assert_eq!(foreign.connections.load(Ordering::SeqCst), 0);
    assert!(!changed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn referrer_discovery_distinguishes_missing_unauthorized_and_unsafe_pagination() {
    for (status, link, expected) in [
        (404, None, None),
        (403, None, Some(Code::Forbidden)),
        (500, None, Some(Code::Network)),
        (
            200,
            Some("<https://other.example/referrers>; rel=\"next\""),
            Some(Code::InvalidInput),
        ),
        (
            200,
            Some("<?page=again>; rel=\"next\""),
            Some(Code::InvalidInput),
        ),
    ] {
        let server = Server::new(move |request| {
            if request.path.contains("/manifests/") {
                assert_eq!(status, 404);
                return Response::new(404, vec![]);
            }
            let mut response = Response::new(status, br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#.to_vec());
            if let Some(link) = link {
                response = response.header("Link", link);
            }
            response
        });
        let (registry, _) = client(&server);
        let reference = format!("{}/app@{}", server.host, Digest::sha256(b"subject"))
            .parse()
            .unwrap();
        let result = registry.list_referrers(&reference).await;
        match expected {
            Some(code) => rejected(result, code),
            None => assert!(result.unwrap().is_empty()),
        }
    }
}
