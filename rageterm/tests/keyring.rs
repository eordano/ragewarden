//! The OS-keyring identity against a real Secret Service: the key lives in the
//! keyring, not on disk, and an item wrapped to it opens through it alone.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const SECRET: &str = "keyring-wrapped-secret-41c7";
const SECRET_KEY_PREFIX: &str = concat!("AGE-SECRET", "-KEY-1");

/// See `tests/clipboard.rs`.
fn rageterm(config_dir: &Path) -> Command {
    let bin =
        std::env::var_os("RAGETERM_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_rageterm").into());
    let mut cmd = Command::new(bin);
    cmd.env("RAGEWARDEN_CONFIG_DIR", config_dir)
        .stdin(Stdio::null());
    cmd
}

fn run(cmd: &mut Command) -> Output {
    cmd.output().expect("spawn rageterm")
}

fn run_ok(cmd: &mut Command) -> String {
    let out = run(cmd);
    assert!(
        out.status.success(),
        "{:?} failed: {}",
        cmd,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
#[ignore = "needs a session D-Bus with a Secret Service; ragewarden-e2e runs it with gnome-keyring"]
fn a_keyring_identity_keeps_its_key_in_the_secret_service_and_opens_items() {
    let config = tempfile::TempDir::new().expect("tempdir");
    let user = format!("rageterm-test-{}", std::process::id());

    run_ok(rageterm(config.path()).args(["enroll-keyring", "--user", &user]));
    let on_disk = std::fs::read_to_string(config.path().join("identities.json")).unwrap();
    assert!(
        !on_disk.contains(SECRET_KEY_PREFIX),
        "the keyring key went to disk"
    );
    let entry = keyring::Entry::new("ragewarden", &user).expect("keyring entry");
    assert!(
        entry
            .get_password()
            .expect("the key is in the Secret Service")
            .starts_with(SECRET_KEY_PREFIX)
    );

    let mut set = rageterm(config.path())
        .args(["set", "kr-item", "--from-stdin", "--offline"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn rageterm set");
    set.stdin
        .take()
        .expect("piped stdin")
        .write_all(SECRET.as_bytes())
        .expect("write plaintext");
    assert!(set.wait().expect("rageterm set").success());

    let got = run_ok(rageterm(config.path()).args(["--yes", "get", "kr-item"]));
    assert_eq!(got, SECRET);

    entry.delete_credential().expect("remove the keyring entry");
    let out = run(rageterm(config.path()).args(["--yes", "get", "kr-item"]));
    assert!(
        !out.status.success() && !String::from_utf8_lossy(&out.stdout).contains(SECRET),
        "the item opened without its keyring entry"
    );
}
