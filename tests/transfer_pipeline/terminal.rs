use super::*;
use rustix::{fs as unix_fs, pty, termios};
use std::io::{self, Read};

fn tty(harness: &Harness, args: &[&str], env: &[(&str, &str)]) -> (std::process::Output, String) {
    let master = pty::openpt(pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY).unwrap();
    rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC).unwrap();
    pty::grantpt(&master).unwrap();
    pty::unlockpt(&master).unwrap();
    let path = pty::ptsname(&master, Vec::new()).unwrap();
    let slave = fs::File::from(
        unix_fs::open(
            &path,
            unix_fs::OFlags::RDWR | unix_fs::OFlags::NOCTTY | unix_fs::OFlags::CLOEXEC,
            unix_fs::Mode::empty(),
        )
        .unwrap(),
    );
    termios::tcsetwinsize(
        &slave,
        termios::Winsize {
            ws_row: 24,
            ws_col: 100,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )
    .unwrap();
    let flags = unix_fs::fcntl_getfl(&master).unwrap();
    unix_fs::fcntl_setfl(&master, flags | unix_fs::OFlags::NONBLOCK).unwrap();
    let mut master = fs::File::from(master);
    let mut command = harness.command(args);
    command
        .env("TERM", "xterm-256color")
        .env("CLICOLOR", "1")
        .env_remove("CLICOLOR_FORCE")
        .env_remove("NO_COLOR")
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(slave.try_clone().unwrap());
    let mut child = command.spawn().unwrap();
    let mut bytes = Vec::new();
    let mut drain = || {
        let mut buffer = [0; 8192];
        loop {
            match master.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&buffer[..n]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("read terminal: {error}"),
            }
        }
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        drain();
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("terminal command stalled: {args:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    drain();
    (output, String::from_utf8(bytes).unwrap())
}

fn source(image: support::Image) -> Server {
    Server::new(move |request| {
        assert_eq!(request.method, "GET");
        if request.path.contains("/manifests/") {
            let mut response = Response::new(200, image.manifest.clone())
                .header("Content-Type", quayside::model::OCI_MANIFEST);
            response.delay = Duration::from_millis(30);
            response
        } else {
            Response::new(
                200,
                image.blobs[request.path.rsplit('/').next().unwrap()].clone(),
            )
        }
    })
}

#[test]
fn copy_refreshes_in_place_without_sweeping_the_cursor_down_the_screen() {
    let root = tempfile::tempdir().unwrap();
    let source = source(image_layout(root.path(), 4, 1024));
    let target = destination(|_| {
        std::thread::sleep(Duration::from_millis(200));
        true
    });
    let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    let src = format!("{}/app:v1", source.host);
    let dst = format!("{}/app:v1", target.host);
    let (output, terminal) = tty(&harness, &["image", "copy", &src, &dst], &[]);
    assert!(output.status.success(), "{terminal}");
    assert!(terminal.matches("[+] Copying").count() >= 3, "{terminal}");
    assert!(terminal.contains("5/5 blobs"), "{terminal}");
    let sweeps = terminal.matches("\x1b[1B").count();
    assert_eq!(
        sweeps, 0,
        "cursor-down operations during ordinary refreshes"
    );
}

#[test]
fn copy_pull_and_push_color_terminal_icons_but_keep_stdout_plain() {
    let root = tempfile::tempdir().unwrap();
    let image = image_layout(root.path(), 1, 1024);
    let digest = image.digest.clone();
    let local = image.directory.clone();
    let source = source(image);
    let target = destination(|_| true);
    let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    let src = format!("{}/app:v1", source.host);
    let dst = format!("{}/app:v1", target.host);
    let other_tag = format!("{}/app:v2", target.host);
    let export = harness.root.path().join("image");
    for (args, status) in [
        (vec!["image", "copy", &src, &dst], "Copied"),
        (vec!["image", "copy", &src, &dst], "Up to date"),
        (vec!["image", "copy", &src, &other_tag], "Copied"),
        (vec!["image", "copy", &src, &dst, "--dry-run"], "Planned"),
        (
            vec![
                "image",
                "pull",
                &src,
                "-o",
                export.to_str().unwrap(),
                "--format",
                "oci-layout",
            ],
            "Pulled",
        ),
        (
            vec!["image", "push", local.to_str().unwrap(), &dst],
            "Pushed",
        ),
    ] {
        let (output, terminal) = tty(&harness, &args, &[]);
        assert!(output.status.success(), "{terminal}");
        let checkmark = if status == "Planned" {
            "\x1b[2m✔\x1b[0m"
        } else {
            "\x1b[32m✔\x1b[0m"
        };
        assert!(terminal.contains(checkmark), "{terminal}");
        assert!(terminal.contains(status), "{terminal}");
        let stdout = std::str::from_utf8(&output.stdout).unwrap();
        if status == "Up to date" {
            assert_eq!(stdout.trim_end(), format!("Up to date: {digest}"));
        } else if args.contains(&other_tag.as_str()) {
            assert_eq!(
                stdout.trim_end(),
                format!("Copied: 0 blobs, skipped: 2\nCompleted: {digest}")
            );
        }
        assert!(terminal.contains("\x1b[33mWarn\x1b[0m:"), "{terminal}");
        assert!(!output.stdout.contains(&b'\x1b'));
    }
}

#[test]
fn terminal_color_controls_are_independent_of_progress_and_override_forced_colors() {
    let root = tempfile::tempdir().unwrap();
    let source = source(image_layout(root.path(), 1, 1024));
    let target = Server::new(|request| {
        assert!(matches!(request.method.as_str(), "GET" | "HEAD"));
        Response::new(404, vec![])
    });
    let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    let src = format!("{}/app:v1", source.host);
    let dst = format!("{}/app:v1", target.host);
    let base = ["image", "copy", &src, &dst, "--dry-run"];
    let sgr = regex::Regex::new("\x1b\\[[0-9;]*m").unwrap();
    for (extra, env, color, progress) in [
        (vec![], vec![], true, true),
        (
            vec!["--no-color"],
            vec![("CLICOLOR_FORCE", "1")],
            false,
            true,
        ),
        (
            vec![],
            vec![("NO_COLOR", "1"), ("CLICOLOR_FORCE", "1")],
            false,
            true,
        ),
        (vec![], vec![("NO_COLOR", "")], false, true),
        (vec![], vec![("CLICOLOR", "0")], false, true),
        (
            vec![],
            vec![("TERM", "dumb"), ("CLICOLOR_FORCE", "1")],
            false,
            false,
        ),
        (vec!["--no-progress"], vec![], true, false),
        (vec!["--json"], vec![("CLICOLOR_FORCE", "1")], false, false),
        (vec!["--quiet"], vec![], false, false),
    ] {
        let mut args = base.to_vec();
        args.extend(&extra);
        let (output, terminal) = tty(&harness, &args, &env);
        assert!(output.status.success(), "{args:?} {env:?}: {terminal}");
        assert_eq!(
            sgr.is_match(&terminal),
            color,
            "{args:?} {env:?}: {terminal}"
        );
        assert_eq!(
            terminal.contains("[+] Copying"),
            progress,
            "{args:?} {env:?}: {terminal}"
        );
        assert!(!output.stdout.contains(&b'\x1b'));
        if extra.contains(&"--json") {
            let result: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["status"], "success");
        }
    }
    let output = harness
        .command(&base)
        .env("CLICOLOR_FORCE", "1")
        .env_remove("NO_COLOR")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!output.stderr.contains(&b'\x1b'));
    assert!(!output.stdout.contains(&b'\x1b'));
}

#[test]
fn terminal_failures_highlight_the_status_and_preserve_plain_error_messages() {
    let source = Server::new(|_| Response::new(500, vec![]));
    let target = Server::new(|_| panic!("unresolved source must not reach the target"));
    let harness = Harness::new(&[(&source.host, true), (&target.host, true)]);
    let args = [
        "image",
        "copy",
        &format!("{}/app:v1", source.host),
        &format!("{}/app:v1", target.host),
    ];
    let (output, terminal) = tty(&harness, &args, &[]);
    assert_eq!(output.status.code(), Some(6), "{terminal}");
    assert!(terminal.contains("\x1b[31mFailed\x1b[0m"), "{terminal}");
    assert!(
        terminal.contains("\x1b[31merror [Network]:\x1b[0m"),
        "{terminal}"
    );
    let (_, plain) = tty(&harness, &[&args[..], &["--no-color"]].concat(), &[]);
    assert!(plain.contains("error [Network]:"), "{plain}");
    assert!(
        !regex::Regex::new("\x1b\\[[0-9;]*m")
            .unwrap()
            .is_match(&plain)
    );
}
