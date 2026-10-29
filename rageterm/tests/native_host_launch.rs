//! The browser starts the host with its own argv and no subcommand; the host
//! must still speak the frame protocol.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

fn probe_reply(args: &[&str]) -> String {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rageterm"))
        .args(args)
        .env("RAGEWARDEN_CONFIG_DIR", dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&frame(br#"{"method":"probe"}"#))
        .unwrap();
    let mut out = Vec::new();
    child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
    assert!(child.wait().unwrap().success());
    assert!(out.len() >= 4, "no framed reply: {out:?}");
    let len = u32::from_le_bytes(out[..4].try_into().unwrap()) as usize;
    String::from_utf8(out[4..4 + len].to_vec()).unwrap()
}

#[test]
fn a_chromium_launch_with_the_caller_origin_reaches_the_protocol() {
    let reply = probe_reply(&["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"]);
    assert!(reply.contains("\"protocol\":2"), "{reply}");
}

#[test]
fn a_windows_chromium_launch_with_a_parent_window_reaches_the_protocol() {
    let reply = probe_reply(&[
        "chrome-extension://abcdefghijklmnopabcdefghijklmnop/",
        "--parent-window=0",
    ]);
    assert!(reply.contains("\"protocol\":2"), "{reply}");
}

#[test]
fn a_firefox_launch_with_manifest_path_and_addon_id_reaches_the_protocol() {
    let reply = probe_reply(&[
        "/home/u/.mozilla/native-messaging-hosts/com.ragewarden.native.json",
        "ragewarden@ragewarden",
    ]);
    assert!(reply.contains("\"protocol\":2"), "{reply}");
}

#[test]
fn a_typo_in_a_subcommand_is_still_a_usage_error() {
    let status = Command::new(env!("CARGO_BIN_EXE_rageterm"))
        .arg("nativ-host")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
}
