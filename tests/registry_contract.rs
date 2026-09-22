mod support;

use bytes::Bytes;
use quayside::{
    Result,
    config::{Config, RegistryConfig},
    digest::Digest,
    error::Code,
    model::{Descriptor, Manifest},
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
