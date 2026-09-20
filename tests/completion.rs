use serde_json::Value;
use std::{fs, path::Path, process::Command};

fn command(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_quayside"));
    command
        .args(args)
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("ZDOTDIR", root)
        .env_remove("USERPROFILE")
        .env_remove("BASH_COMPLETION_USER_DIR")
        .env_remove("BASH_COMPLETION_VERSINFO")
        // Local completion commands must work even with invalid registry configuration.
        .env("QUAYSIDE_CONFIG", root.join("invalid.toml"));
    command
}
fn run(root: &Path, args: &[&str], exit: i32) -> Value {
    let out = command(root, args).arg("--json").output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(exit),
        "{args:?}: {} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn managed_completion_lifecycle_preserves_user_profiles() {
    for shell in ["bash", "zsh", "fish"] {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("invalid.toml"), "not valid toml = [").unwrap();
        let original = "# user configuration\nexport KEEP_ME=yes\n";
        for profile in [".bashrc", ".zshrc"] {
            fs::write(root.path().join(profile), original).unwrap();
        }
        let absent = run(root.path(), &["completion", "status", shell], 0);
        assert_eq!(absent["data"]["installed"], false);
        let installed = run(root.path(), &["completion", "install", shell], 0);
        assert_eq!(installed["command"], "completion install");
        assert_eq!(installed["data"]["file_change"], "created");
        let path = Path::new(installed["data"]["target_path"].as_str().unwrap());
        assert!(path.starts_with(root.path()));
        let contents = fs::read(path).unwrap();
        let generated = command(root.path(), &["completion", shell])
            .output()
            .unwrap();
        assert!(generated.status.success());
        assert_eq!(contents, generated.stdout);
        let profiles: Vec<_> = [".bashrc", ".zshrc"]
            .iter()
            .map(|p| fs::read(root.path().join(p)).unwrap())
            .collect();
        let repeated = run(root.path(), &["completion", "install", shell], 0);
        assert_eq!(repeated["data"]["file_change"], "unchanged");
        for (profile, before) in [".bashrc", ".zshrc"].iter().zip(profiles) {
            assert_eq!(fs::read(root.path().join(profile)).unwrap(), before);
        }
        assert_eq!(
            run(root.path(), &["completion", "status", shell], 0)["data"]["installed"],
            true
        );
        assert_eq!(
            run(root.path(), &["completion", "uninstall", shell], 0)["data"]["file_change"],
            "removed"
        );
        assert!(!path.exists());
        assert_eq!(
            run(root.path(), &["completion", "uninstall", shell], 0)["data"]["file_change"],
            "absent"
        );
        for profile in [".bashrc", ".zshrc"] {
            assert_eq!(
                fs::read_to_string(root.path().join(profile))
                    .unwrap()
                    .trim(),
                original.trim()
            );
        }
    }
}

#[test]
fn custom_path_is_manual_and_invalid_target_is_reported() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("custom.bash");
    let path = path.to_str().unwrap();
    let installed = run(
        root.path(),
        &["completion", "install", "bash", "--path", path],
        0,
    );
    assert_eq!(installed["data"]["activation"]["mode"], "manual");
    assert!(!root.path().join(".bashrc").exists());
    assert_eq!(
        run(
            root.path(),
            &["completion", "status", "bash", "--path", path],
            0
        )["data"]["installed"],
        true
    );
    run(
        root.path(),
        &["completion", "uninstall", "bash", "--path", path],
        0,
    );
    assert!(!Path::new(path).exists());
    let invalid = run(
        root.path(),
        &["completion", "install", "fish", "--path", "/"],
        1,
    );
    assert_eq!(invalid["status"], "error");
    assert!(
        invalid["error"]["message"]
            .as_str()
            .unwrap()
            .contains("shellcomp.invalid_target_path")
    );
    run(root.path(), &["completion"], 2);
    run(root.path(), &["completion", "bash", "install", "zsh"], 2);
}

#[test]
fn exported_bash_script_is_valid_and_completes_subcommands() {
    let root = tempfile::tempdir().unwrap();
    let result = command(root.path(), &["completion", "bash"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let path = root.path().join("quayside.bash");
    fs::write(&path, result.stdout).unwrap();
    let output = Command::new("bash")
        .args([
            "--noprofile",
            "--norc",
            "-c",
            r#"
source "$1"
COMP_WORDS=(quayside completion ins)
COMP_CWORD=2
COMP_LINE='quayside completion ins'
COMP_POINT=${#COMP_LINE}
_quayside quayside ins completion
printf '%s\n' "${COMPREPLY[@]}"
"#,
            "completion-test",
        ])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line == "install")
    );
}

#[test]
fn failed_profile_update_reports_written_completion_and_preserves_profile() {
    let root = tempfile::tempdir().unwrap();
    // A directory where the profile should be makes activation fail after script creation.
    fs::create_dir(root.path().join(".zshrc")).unwrap();
    let result = run(root.path(), &["completion", "install", "zsh"], 1);
    let message = result["error"]["message"].as_str().unwrap();
    assert!(message.contains("completion file: created"), "{message}");
    assert!(root.path().join(".zfunc/_quayside").is_file());
    assert!(root.path().join(".zshrc").is_dir());
}

#[test]
fn custom_target_under_user_symlink_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("real");
    let alias = root.path().join("alias");
    fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let target = alias.join("quayside.bash");
    let result = run(
        root.path(),
        &[
            "completion",
            "install",
            "bash",
            "--path",
            target.to_str().unwrap(),
        ],
        1,
    );
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("shellcomp.invalid_target_path")
    );
    assert!(!real.join("quayside.bash").exists());
}
