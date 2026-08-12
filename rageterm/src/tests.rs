use tempfile::TempDir;

use crate::commands;
use crate::consent;
use crate::tests_lock::ENV_LOCK;

/// A consent guard for a delivery in a test. These vaults have no real device
/// enrolled, so this is the software path with `--yes`; the tests that cover
/// the hardware path live in `tests_consent`.
fn yes_guard(action: &str, name: &str) -> consent::ConsentGuard {
    consent::require(action, name, "a test", true).expect("consent guard")
}

#[test]
fn detect_scrollback_hostility_flags_each_environment() {
    let none: Vec<(&str, &str)> = vec![("PATH", "/usr/bin")];
    assert_eq!(commands::detect_scrollback_hostility_from(none), None);

    let tmux = commands::detect_scrollback_hostility_from(vec![("TMUX", "/tmp/tmux-1000/default,1234,0")]);
    assert_eq!(tmux.as_deref(), Some("tmux"));

    let screen = commands::detect_scrollback_hostility_from(vec![("STY", "1234.pts-0.host")]);
    assert_eq!(screen.as_deref(), Some("GNU screen"));

    let ssh_conn = commands::detect_scrollback_hostility_from(vec![(
        "SSH_CONNECTION",
        "10.0.0.1 22 10.0.0.2 50000",
    )]);
    assert_eq!(ssh_conn.as_deref(), Some("ssh"));

    let ssh_tty = commands::detect_scrollback_hostility_from(vec![("SSH_TTY", "/dev/pts/0")]);
    assert_eq!(ssh_tty.as_deref(), Some("ssh"));

    let combo = commands::detect_scrollback_hostility_from(vec![
        ("TMUX", "x"),
        ("SSH_CONNECTION", "y"),
    ]);
    assert_eq!(combo.as_deref(), Some("tmux, ssh"));

    let empty_value = commands::detect_scrollback_hostility_from(vec![("TMUX", "")]);
    assert_eq!(empty_value, None);
}

fn with_isolated_config<F, R>(body: F) -> R
where
    F: FnOnce(&std::path::Path) -> R,
{
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().expect("tempdir");
    let prev = std::env::var_os("RAGEWARDEN_CONFIG_DIR");
    std::env::set_var("RAGEWARDEN_CONFIG_DIR", dir.path());
    let res = body(dir.path());
    if let Some(p) = prev {
        std::env::set_var("RAGEWARDEN_CONFIG_DIR", p);
    } else {
        std::env::remove_var("RAGEWARDEN_CONFIG_DIR");
    }
    res
}

#[test]
fn enroll_then_set_then_get_round_trip() {
    with_isolated_config(|cfg_dir| {
        commands::cmd_enroll_software_identity().expect("enroll");
        assert!(cfg_dir.join("identity.age").exists());

        set_via_api("github", b"hunter2-but-better");

        let store_path = cfg_dir.join("store.json");
        assert!(store_path.exists());
        let store = crate::store::Store::load(&store_path).unwrap();
        assert!(store.get("github").is_some());

        let pt = commands::decrypt_named("github", &yes_guard("Print", "github")).expect("decrypt");
        assert_eq!(pt.as_slice(), b"hunter2-but-better");
    });
}

#[test]
fn list_shows_added_item() {
    with_isolated_config(|_cfg| {
        commands::cmd_enroll_software_identity().expect("enroll");
        set_via_api("alpha", b"value-alpha");
        set_via_api("beta", b"value-beta");

        let store_path = crate::config::store_path().unwrap();
        let store = crate::store::Store::load(&store_path).unwrap();
        let names: Vec<_> = store.items.keys().cloned().collect();

        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);
    });
}

#[test]
fn copy_puts_value_on_clipboard() {
    if arboard::Clipboard::new().is_err() {
        eprintln!("test skipped: no clipboard backend available");
        return;
    }
    with_isolated_config(|_cfg| {
        commands::cmd_enroll_software_identity().expect("enroll");
        set_via_api("clip-target", b"clipboard-secret-xyz");

        let pt = commands::decrypt_named("clip-target", &yes_guard("Copy", "clip-target")).expect("decrypt");
        let hash = crate::output::hex_sha256(&pt);

        crate::output::deliver_clipboard(pt, 0, &hash).expect("clipboard set");

        let mut clip = arboard::Clipboard::new().unwrap();
        let got = clip.get_text().expect("clipboard get");
        assert_eq!(got, "clipboard-secret-xyz");
    });
}

#[test]
fn enroll_twice_refuses_to_overwrite() {
    with_isolated_config(|_cfg| {
        commands::cmd_enroll_software_identity().expect("first enroll");
        let res = commands::cmd_enroll_software_identity();
        assert!(matches!(res, Err(commands::CmdError::InvalidArg(_))));
    });
}

#[test]
fn get_unknown_item_errors_cleanly() {
    with_isolated_config(|_cfg| {
        commands::cmd_enroll_software_identity().expect("enroll");
        let err = commands::decrypt_named("does-not-exist", &yes_guard("Print", "does-not-exist")).unwrap_err();
        assert!(matches!(err, commands::CmdError::NotFound(_)));
    });
}

#[test]
fn sha256_clipboard_gate_matches_expected_vector() {
    let h = crate::output::hex_sha256(b"abc");
    assert_eq!(
        h,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn enroll_recovery_then_full_round_trip() {
    with_isolated_config(|_cfg| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            commands::cmd_enroll_recovery("test-recovery", true)
                .await
                .expect("enroll");

            let list = crate::recipients::load().await.expect("recipient list");
            assert_eq!(list.entries.len(), 1, "exactly one recipient enrolled");
            let recipients = list.recipients();
            let plaintext = b"recovery-only-secret";
            let blob =
                ragewarden_core::encrypt(plaintext, &recipients).expect("encrypt to recovery");
            let armored = String::from_utf8(blob.0).unwrap();

            let store_path = crate::config::store_path().unwrap();
            crate::config::ensure_config_dir().unwrap();
            let mut store = crate::store::Store::load(&store_path).unwrap();
            store.upsert("secret", armored, chrono::Utc::now());
            store.save(&store_path).unwrap();

            let pt = commands::decrypt_named("secret", &yes_guard("Print", "secret")).expect("decrypt");
            assert_eq!(pt.as_slice(), plaintext);
        });
    });
}

#[test]
fn enroll_yubikey_mock_then_full_round_trip() {
    with_isolated_config(|_cfg| {
        std::env::set_var("RAGEWARDEN_MOCK_HARDWARE", "1");
        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                std::env::remove_var("RAGEWARDEN_MOCK_HARDWARE");
            }
        }
        let _cleanup = Cleanup;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // allow_untouched_slot: false -- the mock path never queries the
            // card, so the override has nothing to override here. Passing false
            // keeps this test on the strict branch a real enrolment takes.
            commands::cmd_enroll_yubikey(0x95, Some("mock yk"), None, true, false)
                .await
                .expect("enroll yubikey (mock)");

            let list = crate::recipients::load().await.expect("recipient list");
            let recipients = list.recipients();
            let plaintext = b"piv-protected-end-to-end";
            let blob = ragewarden_core::encrypt(plaintext, &recipients).expect("encrypt");
            let armored = String::from_utf8(blob.0).unwrap();

            let store_path = crate::config::store_path().unwrap();
            crate::config::ensure_config_dir().unwrap();
            let mut store = crate::store::Store::load(&store_path).unwrap();
            store.upsert("secret-piv", armored, chrono::Utc::now());
            store.save(&store_path).unwrap();

            let pt = commands::decrypt_named("secret-piv", &yes_guard("Print", "secret-piv")).expect("decrypt");
            assert_eq!(pt.as_slice(), plaintext);
        });
    });
}

fn set_via_api(name: &str, plaintext: &[u8]) {
    use age::secrecy::ExposeSecret;
    use chrono::Utc;
    use ragewarden_core::{encrypt, Recipient};

    let id_path = crate::config::identity_path().unwrap();
    let id = crate::idfile::read(&id_path).unwrap();
    let pub_armored = id.to_public().to_string();
    let _secret = id.to_string();
    let _ = _secret.expose_secret();

    let recipient = Recipient::SoftwarePassphrase {
        armored_pubkey: ragewarden_core::ArmoredAgeRecipient::from_trusted(pub_armored),
    };
    let blob = encrypt(plaintext, &[recipient]).unwrap();
    let armored = String::from_utf8(blob.0).unwrap();

    let store_path = crate::config::store_path().unwrap();
    crate::config::ensure_config_dir().unwrap();
    let mut store = crate::store::Store::load(&store_path).unwrap();
    store.upsert(name, armored, Utc::now());
    store.save(&store_path).unwrap();
}
