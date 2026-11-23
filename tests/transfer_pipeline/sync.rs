use super::*;
use quayside::model::OCI_MANIFEST;
use support::image_layout_for;

#[test]
fn batch_reuses_source_lookups_tracks_each_write_and_refreshes_on_the_next_run() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout_for(root.path(), 1, 32, "amd64");
    let digest = image.digest.clone();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    let source = Server::new(move |req| {
        seen.lock().unwrap().push(req.path.clone());
        match req.path.as_str() {
            "/v2/app/tags/list?n=1000" => {
                Response::new(200, br#"{"tags":["18.9-trixie","18.10-trixie"]}"#.to_vec())
            }
            "/v2/app/manifests/18.10-trixie" | "/v2/fixed/manifests/lts-jdk25" => {
                Response::new(200, image.manifest.clone()).header("Content-Type", OCI_MANIFEST)
            }
            p if p.contains("/blobs/") => {
                Response::new(200, image.blobs[p.rsplit('/').next().unwrap()].clone())
            }
            _ => Response::new(404, vec![]),
        }
    });
    let target = destination(|_| true);
    let h = Harness::new(&[(&source.host, true), (&target.host, true)]);
    let file = h.root.path().join("sync.toml");
    let src = &source.host;
    let dst = &target.host;
    fs::write(
        &file,
        format!(
            r#"
platform = "linux/arm64"

[[sync]]
from = "{src}/app:18.*-trixie"
to = "{dst}/app"

[[sync]]
from = "{src}/app:19.*-trixie"
to = "{dst}/next"

[[sync]]
from = "{src}/app:*.*-trixie"
to = "{dst}/app"

[[sync]]
from = "{src}/app:18.10-trixie"
to = "{dst}/other:stable"

[[sync]]
from = "{src}/fixed:lts-jdk25"
to = "{dst}/fixed"
"#
        ),
    )
    .unwrap();
    let args = ["sync", file.to_str().unwrap(), "--platform", "linux/amd64"];
    let run = h.json(&args, 9);
    assert_eq!(run["status"], "partial");
    let data = &run["data"];
    assert_eq!(
        (
            data["copied"].as_u64(),
            data["up_to_date"].as_u64(),
            data["failed"].as_u64()
        ),
        (Some(3), Some(1), Some(1))
    );
    let items = data["results"].as_array().unwrap();
    assert_eq!(items[0]["to"], format!("{dst}/app:18.10-trixie"));
    assert_eq!(items[0]["digest"], digest);
    assert_eq!(items[0]["platforms"], json!(["linux/amd64"]));
    assert_eq!(items[1]["error"]["code"], "NOT_FOUND");
    assert_eq!(items[1]["remote_writes_may_have_occurred"], false);
    assert_eq!(items[2]["status"], "up_to_date");
    assert_eq!(items[3]["to"], format!("{dst}/other:stable"));
    assert_eq!(items[4]["to"], format!("{dst}/fixed:lts-jdk25"));
    let out = h.output(&args, 9);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 6, "{stdout}");
    assert!(lines[0].starts_with(&format!(
        "Up to date  {src}/app:18.10-trixie -> {dst}/app:18.10-trixie"
    )));
    assert!(lines[1].starts_with(&format!("Failed  {src}/app:19.*-trixie -> {dst}/next")));
    assert_eq!(lines[5], "Sync complete: 0 copied, 4 up to date, 1 failed");
    let seen = requests.lock().unwrap();
    assert_eq!(seen.iter().filter(|p| p.contains("/tags/list")).count(), 2);
    assert_eq!(
        seen.iter()
            .filter(|p| *p == "/v2/app/manifests/18.10-trixie")
            .count(),
        2
    );
    assert_eq!(
        seen.iter()
            .filter(|p| *p == "/v2/fixed/manifests/lts-jdk25")
            .count(),
        2
    );
}

#[test]
fn validates_the_entire_file_before_copying() {
    let registry = Server::new(|_| Response::new(500, vec![]));
    let h = Harness::new(&[(&registry.host, true)]);
    let file = h.root.path().join("sync.toml");
    let valid = format!(
        "[[sync]]\nfrom = '{}/app:stable'\nto = '{}/dest'\n",
        registry.host, registry.host
    );
    for (text, message) in [
        ("sync = []".to_owned(), "at least one [[sync]]"),
        (
            format!("{valid}\n[[sync]]\nfrom = 'nginx:*-**'\nto = 'example.com/a'"),
            "invalid sync entry 2",
        ),
        (format!("{valid}overwite = true"), "unknown field"),
        (format!("platform = 'bad'\n{valid}"), "platform"),
    ] {
        fs::write(&file, text).unwrap();
        let result = h.json(&["sync", file.to_str().unwrap()], 2);
        assert!(
            result["error"]["message"]
                .as_str()
                .unwrap()
                .contains(message),
            "{result}"
        );
    }
    assert_eq!(registry.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn changing_a_named_tag_requires_overwrite_on_that_job() {
    let root = tempfile::tempdir().unwrap();
    let images = [
        image_layout_for(&root.path().join("one"), 1, 32, "amd64"),
        image_layout_for(&root.path().join("two"), 2, 32, "amd64"),
    ];
    let version = Arc::new(AtomicUsize::new(0));
    let current = version.clone();
    let source = Server::new(move |req| {
        let image = &images[current.load(Ordering::SeqCst)];
        if req.path == "/v2/app/manifests/lts" {
            Response::new(200, image.manifest.clone()).header("Content-Type", OCI_MANIFEST)
        } else if req.path.contains("/blobs/") {
            Response::new(
                200,
                image.blobs[req.path.rsplit('/').next().unwrap()].clone(),
            )
        } else {
            Response::new(404, vec![])
        }
    });
    let target = destination(|_| true);
    let h = Harness::new(&[(&source.host, true), (&target.host, true)]);
    let file = h.root.path().join("sync.toml");
    let config = format!(
        "platform = 'linux/amd64'\n[[sync]]\nfrom = '{}/app:lts'\nto = '{}/app'\n",
        source.host, target.host
    );
    let args = ["sync", file.to_str().unwrap()];
    fs::write(&file, &config).unwrap();
    let first = h.json(&args, 0);
    assert_eq!(first["status"], "success");
    assert_eq!(first["data"]["copied"], 1);

    version.store(1, Ordering::SeqCst);
    let conflict = h.json(&args, 8);
    assert_eq!(conflict["status"], "error");
    assert_eq!(conflict["data"]["results"][0]["error"]["code"], "CONFLICT");
    assert_eq!(
        conflict["data"]["results"][0]["remote_writes_may_have_occurred"],
        false
    );
    fs::write(&file, config + "overwrite = true\n").unwrap();
    let updated = h.json(&args, 0);
    assert_eq!(updated["data"]["copied"], 1);
    assert_ne!(
        updated["data"]["results"][0]["digest"],
        first["data"]["results"][0]["digest"]
    );
    assert_eq!(h.json(&args, 0)["data"]["up_to_date"], 1);
}
