#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

use zeroize::Zeroizing;

use crate::agent_add::{add_to_agent, AddOptions, AgentAddError};
use crate::tests_lock::ENV_LOCK;

const ED25519_FIXTURE: &str = include_str!("agent_add_test_data/ed25519");

fn spawn_fake_agent(socket_path: PathBuf) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    let listener = UnixListener::bind(&socket_path).expect("bind unix listener");
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).expect("read len");
        let n = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        stream.read_exact(&mut body).expect("read body");
        tx.send(body).expect("send body");
        let reply = [0u8, 0u8, 0u8, 1u8, 6u8];
        stream.write_all(&reply).expect("write reply");
    });
    rx
}

#[test]
fn add_to_agent_round_trips_ed25519_via_fake_agent() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("agent.sock");

    let rx = spawn_fake_agent(socket_path.clone());
    let prev = std::env::var_os("SSH_AUTH_SOCK");
    std::env::set_var("SSH_AUTH_SOCK", &socket_path);

    let plaintext = Zeroizing::new(ED25519_FIXTURE.as_bytes().to_vec());
    let outcome = add_to_agent(AddOptions {
        plaintext: &plaintext,
        comment: "round-trip-comment",
        lifetime_secs: None,
    })
    .expect("add succeeded");

    if let Some(p) = prev {
        std::env::set_var("SSH_AUTH_SOCK", p);
    } else {
        std::env::remove_var("SSH_AUTH_SOCK");
    }

    assert_eq!(outcome.algorithm, "ssh-ed25519");
    assert!(outcome.fingerprint.starts_with("SHA256:"));
    assert!(outcome.lifetime_secs.is_none());

    let body = rx.recv().expect("agent received body");
    assert_eq!(body[0], 17, "should be SSH_AGENTC_ADD_IDENTITY");
    let algo_len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    assert_eq!(&body[5..5 + algo_len], b"ssh-ed25519");

    let comment_pos = body
        .windows(b"round-trip-comment".len())
        .position(|w| w == b"round-trip-comment")
        .expect("comment bytes appear in payload");
    assert!(comment_pos > 5);
}

#[test]
fn add_to_agent_with_lifetime_uses_constrained_opcode() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("agent2.sock");

    let rx = spawn_fake_agent(socket_path.clone());
    let prev = std::env::var_os("SSH_AUTH_SOCK");
    std::env::set_var("SSH_AUTH_SOCK", &socket_path);

    let plaintext = Zeroizing::new(ED25519_FIXTURE.as_bytes().to_vec());
    let outcome = add_to_agent(AddOptions {
        plaintext: &plaintext,
        comment: "lifetime-test",
        lifetime_secs: Some(120),
    })
    .expect("add succeeded");

    if let Some(p) = prev {
        std::env::set_var("SSH_AUTH_SOCK", p);
    } else {
        std::env::remove_var("SSH_AUTH_SOCK");
    }

    assert_eq!(outcome.lifetime_secs, Some(120));
    let body = rx.recv().expect("agent received body");
    assert_eq!(body[0], 25, "should be SSH_AGENTC_ADD_ID_CONSTRAINED");
    let last_five = &body[body.len() - 5..];
    assert_eq!(last_five[0], 1, "SSH_AGENT_CONSTRAIN_LIFETIME");
    assert_eq!(
        u32::from_be_bytes([last_five[1], last_five[2], last_five[3], last_five[4]]),
        120
    );
}

#[test]
fn add_to_agent_errors_when_no_auth_sock() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::env::var_os("SSH_AUTH_SOCK");
    std::env::remove_var("SSH_AUTH_SOCK");

    let plaintext = Zeroizing::new(ED25519_FIXTURE.as_bytes().to_vec());
    let res = add_to_agent(AddOptions {
        plaintext: &plaintext,
        comment: "no-sock",
        lifetime_secs: None,
    });

    if let Some(p) = prev {
        std::env::set_var("SSH_AUTH_SOCK", p);
    }
    assert!(matches!(res, Err(AgentAddError::NoAuthSock)));
}
