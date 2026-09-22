mod support;

use clap::Parser;
use quayside::{
    auth::{AuthFile, Credential},
    cli::Cli,
};
use std::{collections::BTreeMap, ffi::OsString, fs, sync::atomic::Ordering};
use support::{Harness, Response, Server};

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
