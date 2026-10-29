use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SECRET: &str = "clipboard-secret-xyz";

/// `RAGETERM_BIN` when set (ragewarden-e2e runs this test binary in its VM
/// against the installed rageterm), else the one cargo just built.
fn rageterm(config_dir: &Path) -> Command {
    let bin =
        std::env::var_os("RAGETERM_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_rageterm").into());
    let mut cmd = Command::new(bin);
    cmd.env("RAGEWARDEN_CONFIG_DIR", config_dir);
    cmd
}

fn run_ok(cmd: &mut Command) {
    let out = cmd.output().expect("spawn rageterm");
    assert!(
        out.status.success(),
        "{:?} failed: {}",
        cmd,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[ignore = "needs an X or Wayland display; ragewarden-e2e runs it under Xvfb"]
fn copy_puts_value_on_clipboard() {
    let mut clip =
        arboard::Clipboard::new().expect("a clipboard backend (DISPLAY or WAYLAND_DISPLAY)");
    let previous = clip.get_text().ok();
    let config = tempfile::TempDir::new().expect("tempdir");

    run_ok(rageterm(config.path()).arg("enroll-software-identity"));
    let mut set = rageterm(config.path())
        .args(["set", "clip-target", "--from-stdin", "--offline"])
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

    run_ok(rageterm(config.path()).args(["--yes", "copy", "clip-target", "--clear", "2"]));
    assert_eq!(
        clip.get_text()
            .expect("clipboard get after rageterm exited"),
        SECRET
    );

    let deadline = Instant::now() + Duration::from_secs(8);
    while clip.get_text().ok().as_deref() == Some(SECRET) {
        assert!(Instant::now() < deadline, "clipboard was not cleared");
        thread::sleep(Duration::from_millis(100));
    }

    if let Some(previous) = previous {
        let _ = clip.set_text(previous);
    }
}
