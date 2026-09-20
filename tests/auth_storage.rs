mod support;
use std::{fs, io::Write, process::Stdio};
use support::{Harness, Response, Server};

#[test]
fn login_encrypts_and_following_process_authenticates_then_logout_removes() {
    let server = Server::new(|request| {
        if request.headers.get("authorization").map(String::as_str)
            == Some("Basic cm9ib3Q6c2VjcmV0")
        {
            Response::new(200, b"{}".to_vec())
        } else {
            Response::new(401, vec![]).header("WWW-Authenticate", "Basic realm=\"test\"")
        }
    });
    let harness = Harness::new(&[(&server.host, true)]);
    let mut child = harness
        .command(&[
            "--json",
            "login",
            &server.host,
            "-u",
            "robot",
            "--password-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"secret\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["data"]["encrypted"], true);
    let stored = fs::read_to_string(harness.root.path().join("auth.json")).unwrap();
    assert!(!stored.contains("secret"));
    assert!(!stored.contains("robot"));
    harness.json(&["registry", "ping", &server.host], 0);
    harness.json(&["logout", &server.host], 0);
    harness.json(&["registry", "ping", &server.host], 3);
}

#[test]
fn default_key_directory_and_explicit_migration_work_without_registry_config() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let auth = root.path().join("config/quayside/auth.json");
    fs::create_dir_all(auth.parent().unwrap()).unwrap();
    fs::set_permissions(auth.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        &auth,
        br#"{"version":1,"registries":{"example.com":{"username":"user","secret":"secret"}}}"#,
    )
    .unwrap();
    fs::set_permissions(&auth, fs::Permissions::from_mode(0o600)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_quayside"))
        .args(["--json", "auth", "migrate"])
        .env_remove("QUAYSIDE_AUTHFILE")
        .env_remove("QUAYSIDE_KEYFILE")
        .env("QUAYSIDE_CONFIG", "/does/not/exist/config.toml")
        .env("HOME", root.path())
        .env("XDG_CONFIG_HOME", root.path().join("config"))
        .env("XDG_DATA_HOME", root.path().join("data"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let key = root.path().join("data/quayside/master.key");
    assert!(key.is_file());
    assert!(!auth.parent().unwrap().join("master.key").exists());
    assert_eq!(
        quayside::auth::AuthFile::load(&auth, &key)
            .unwrap()
            .registries["example.com"]
            .secret,
        "secret"
    );
}
