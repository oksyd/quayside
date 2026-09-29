use super::{destination, destination_with_commit};
use crate::support::{Response, Server};
use quayside::{
    config::{Config, RegistryConfig},
    graph::Graph,
    model::{Manifest, OCI_MANIFEST},
    observer::{BlobOutcome, BlobPhase, BlobProgress, Observer, Operation, Phase},
    registry::Registry,
    transfer::transfer_remote_blobs,
};
use serde_json::json;
use std::sync::{Arc, Mutex, atomic::AtomicBool};

#[derive(Clone, Default)]
struct Outcomes(Arc<Mutex<Vec<BlobOutcome>>>);
impl Observer for Outcomes {
    fn begin(&self, _: Phase, _: usize) -> Box<dyn Operation> {
        Box::new(self.clone())
    }
}
impl Operation for Outcomes {
    fn blob(&self, _: String, _: u64) -> Box<dyn BlobProgress> {
        Box::new(self.clone())
    }
}
impl BlobProgress for Outcomes {
    fn phase(&self, _: BlobPhase) {}
    fn position(&self, _: u64) {}
    fn finish(&self) {
        panic!("transfers must report a specific outcome");
    }
    fn finish_with(&self, outcome: BlobOutcome) {
        self.0.lock().unwrap().push(outcome);
    }
}

fn client(server: &Server) -> Registry {
    let mut config = Config::default();
    config.transfer.max_retries = 0;
    config.registries.insert(
        server.host.clone(),
        RegistryConfig {
            plain_http: true,
            ..Default::default()
        },
    );
    Registry::new(
        &server.host,
        Arc::new(config),
        None,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap()
}

#[tokio::test]
async fn completion_reports_verified_outcomes_and_never_finishes_failed_uploads() {
    // Inline content keeps this observer contract test independent of Docker and remote downloads.
    let manifest = Manifest::parse(
        serde_json::to_vec(&json!({
            "schemaVersion": 2, "mediaType": OCI_MANIFEST,
            "config": {
                "mediaType": "application/octet-stream",
                "digest": quayside::digest::Digest::sha256(b"blob"),
                "size": 4, "data": "YmxvYg=="
            }, "layers": []
        }))
        .unwrap()
        .into(),
        None,
        None,
    )
    .unwrap();
    let graph = Graph::build(manifest, &Config::default().transfer, |_| async {
        panic!("no child manifests")
    })
    .await
    .unwrap();
    let source = Server::new(|_| panic!("inline content needs no source request"));
    let source_client = client(&source);
    let source_ref = format!("{}/source:v1", source.host).parse().unwrap();
    let target = destination(|_| true);
    let target_client = client(&target);
    let target_ref = format!("{}/app:v1", target.host).parse().unwrap();
    let outcomes = Outcomes::default();
    for (dry_run, expected) in [
        (true, BlobOutcome::Planned),
        (false, BlobOutcome::Copied),
        (false, BlobOutcome::AlreadyExists),
    ] {
        outcomes.0.lock().unwrap().clear();
        transfer_remote_blobs(
            &source_client,
            &source_ref,
            &target_client,
            &target_ref,
            &graph,
            dry_run,
            &outcomes,
        )
        .await
        .unwrap();
        assert_eq!(*outcomes.0.lock().unwrap(), [expected]);
    }

    let failed = destination_with_commit(|_| true, || false);
    outcomes.0.lock().unwrap().clear();
    assert!(
        transfer_remote_blobs(
            &source_client,
            &source_ref,
            &client(&failed),
            &format!("{}/app:v1", failed.host).parse().unwrap(),
            &graph,
            false,
            &outcomes
        )
        .await
        .is_err()
    );
    assert!(outcomes.0.lock().unwrap().is_empty());

    let mounted = AtomicBool::new(false);
    let mount = Server::new(move |request| match request.method.as_str() {
        "HEAD" if mounted.load(std::sync::atomic::Ordering::SeqCst) => {
            Response::new(200, vec![]).header("Content-Length", "4")
        }
        "HEAD" => Response::new(404, vec![]),
        "POST" => {
            assert!(request.path.contains("mount="));
            mounted.store(true, std::sync::atomic::Ordering::SeqCst);
            Response::new(201, vec![])
        }
        _ => panic!("mounts need no payload transfer"),
    });
    let mount_client = client(&mount);
    let stats = transfer_remote_blobs(
        &mount_client,
        &format!("{}/source:v1", mount.host).parse().unwrap(),
        &mount_client,
        &format!("{}/app:v1", mount.host).parse().unwrap(),
        &graph,
        false,
        &outcomes,
    )
    .await
    .unwrap();
    assert_eq!(*outcomes.0.lock().unwrap(), [BlobOutcome::Mounted]);
    assert_eq!(stats.mounted_blobs, 1);
    assert_eq!(stats.copied_blobs, 0);
}
