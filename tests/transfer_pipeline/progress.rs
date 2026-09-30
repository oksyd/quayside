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
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, atomic::AtomicBool},
};

#[derive(Clone, Default)]
struct Outcomes(
    Arc<Mutex<Vec<BlobOutcome>>>,
    Arc<std::sync::atomic::AtomicUsize>,
);
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
    fn fail(&self) {
        self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
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
    assert_eq!(outcomes.1.load(std::sync::atomic::Ordering::SeqCst), 1);

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

#[derive(Default)]
struct Events {
    stages: Vec<Phase>,
    blobs: BTreeMap<String, BlobEvents>,
}
#[derive(Default)]
struct BlobEvents {
    size: u64,
    phases: Vec<BlobPhase>,
    position: u64,
    outcome: Option<BlobOutcome>,
}
#[derive(Clone, Default)]
struct Recording(Arc<Mutex<Events>>);
struct RecordedBlob(Recording, String);
impl Observer for Recording {
    fn begin(&self, phase: Phase, _: usize) -> Box<dyn Operation> {
        self.0.lock().unwrap().stages.push(phase);
        Box::new(self.clone())
    }
}
impl Operation for Recording {
    fn blob(&self, digest: String, size: u64) -> Box<dyn BlobProgress> {
        self.0.lock().unwrap().blobs.insert(
            digest.clone(),
            BlobEvents {
                size,
                ..Default::default()
            },
        );
        Box::new(RecordedBlob(self.clone(), digest))
    }
}
impl BlobProgress for RecordedBlob {
    fn phase(&self, phase: BlobPhase) {
        self.0
            .0
            .lock()
            .unwrap()
            .blobs
            .get_mut(&self.1)
            .unwrap()
            .phases
            .push(phase);
    }
    fn position(&self, position: u64) {
        let mut events = self.0.0.lock().unwrap();
        let blob = events.blobs.get_mut(&self.1).unwrap();
        assert!(position <= blob.size);
        blob.position = position;
    }
    fn finish(&self) {
        panic!("expected a specific transfer outcome");
    }
    fn finish_with(&self, outcome: BlobOutcome) {
        let mut events = self.0.0.lock().unwrap();
        let blob = events.blobs.get_mut(&self.1).unwrap();
        assert!(
            blob.outcome.replace(outcome).is_none(),
            "duplicate completion"
        );
    }
}

#[tokio::test]
async fn pull_and_push_observe_verified_bytes_plans_skips_and_failures() {
    use quayside::{
        layout,
        options::{ArchiveFormat, WriteOptions},
    };
    let root = tempfile::tempdir().unwrap();
    let image = crate::support::image_layout(&root.path().join("source"), 2, 8192);
    let count = image.blobs.len();
    let source = Server::new(move |request| {
        if request.path.contains("/manifests/") {
            Response::new(200, image.manifest.clone()).header("Content-Type", OCI_MANIFEST)
        } else {
            Response::new(
                200,
                image.blobs[request.path.rsplit('/').next().unwrap()].clone(),
            )
        }
    });
    let source_client = client(&source);
    let reference = format!("{}/app:v1", source.host).parse().unwrap();
    let write = WriteOptions::default();
    let dry = WriteOptions {
        dry_run: true,
        ..write
    };
    for (index, format) in [ArchiveFormat::OciLayout, ArchiveFormat::OciArchive]
        .into_iter()
        .enumerate()
    {
        let path = root.path().join(format!("export-{index}"));
        let planned = Recording::default();
        layout::pull_with_observer(
            &source_client,
            &reference,
            &path,
            format,
            None,
            &dry,
            &planned,
        )
        .await
        .unwrap();
        assert!(!path.exists());
        assert!(
            planned
                .0
                .lock()
                .unwrap()
                .blobs
                .values()
                .all(|b| b.outcome == Some(BlobOutcome::Planned) && b.phases.is_empty())
        );

        let pulled = Recording::default();
        layout::pull_with_observer(
            &source_client,
            &reference,
            &path,
            format,
            None,
            &write,
            &pulled,
        )
        .await
        .unwrap();
        {
            let events = pulled.0.lock().unwrap();
            assert_eq!(
                events.stages,
                [Phase::Resolving, Phase::Pulling, Phase::Saving]
            );
            assert_eq!(events.blobs.len(), count);
            for blob in events.blobs.values() {
                assert!(blob.phases.contains(&BlobPhase::Downloading));
                assert_eq!(blob.position, blob.size);
                assert_eq!(blob.outcome, Some(BlobOutcome::Downloaded));
            }
        }
        let target = destination(|_| true);
        let target_client = client(&target);
        let dst = format!("{}/app:v1", target.host).parse().unwrap();
        for (write, outcome) in [
            (&dry, BlobOutcome::Planned),
            (&write, BlobOutcome::Uploaded),
            (&write, BlobOutcome::AlreadyExists),
        ] {
            let recorded = Recording::default();
            layout::push_with_observer(&path, None, &target_client, &dst, write, &recorded)
                .await
                .unwrap();
            let events = recorded.0.lock().unwrap();
            assert_eq!(events.blobs.len(), count);
            assert!(events.stages.contains(&Phase::VerifyingLocal));
            assert_eq!(events.stages.contains(&Phase::Publishing), !write.dry_run);
            for blob in events.blobs.values() {
                assert_eq!(blob.outcome, Some(outcome));
                assert_eq!(
                    blob.phases.contains(&BlobPhase::Uploading),
                    outcome == BlobOutcome::Uploaded
                );
                if outcome == BlobOutcome::Uploaded {
                    assert_eq!(blob.position, blob.size);
                }
            }
        }
        let failed = destination_with_commit(|_| true, || false);
        let recorded = Recording::default();
        assert!(
            layout::push_with_observer(
                &path,
                None,
                &client(&failed),
                &format!("{}/app:v1", failed.host).parse().unwrap(),
                &write,
                &recorded
            )
            .await
            .is_err()
        );
        let events = recorded.0.lock().unwrap();
        assert!(!events.stages.contains(&Phase::Publishing));
        assert!(events.blobs.values().all(|b| b.outcome.is_none()));
    }
}
