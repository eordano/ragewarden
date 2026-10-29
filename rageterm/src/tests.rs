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

    let tmux =
        commands::detect_scrollback_hostility_from(vec![("TMUX", "/tmp/tmux-1000/default,1234,0")]);
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

    let combo =
        commands::detect_scrollback_hostility_from(vec![("TMUX", "x"), ("SSH_CONNECTION", "y")]);
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
    crate::tests_lock::set_var("RAGEWARDEN_CONFIG_DIR", dir.path());
    let res = body(dir.path());
    if let Some(p) = prev {
        crate::tests_lock::set_var("RAGEWARDEN_CONFIG_DIR", p);
    } else {
        crate::tests_lock::remove_var("RAGEWARDEN_CONFIG_DIR");
    }
    res
}

#[test]
fn enroll_then_set_then_get_round_trip() {
    with_isolated_config(|cfg_dir| {
        commands::cmd_enroll_software_identity(true).expect("enroll");
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
        commands::cmd_enroll_software_identity(true).expect("enroll");
        set_via_api("alpha", b"value-alpha");
        set_via_api("beta", b"value-beta");

        let store_path = crate::config::store_path().unwrap();
        let store = crate::store::Store::load(&store_path).unwrap();
        let names: Vec<_> = store.items.keys().cloned().collect();

        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);
    });
}

#[test]
fn enroll_twice_refuses_to_overwrite() {
    with_isolated_config(|_cfg| {
        commands::cmd_enroll_software_identity(true).expect("first enroll");
        let res = commands::cmd_enroll_software_identity(true);
        assert!(matches!(res, Err(commands::CmdError::InvalidArg(_))));
    });
}

#[test]
fn get_unknown_item_errors_cleanly() {
    with_isolated_config(|_cfg| {
        commands::cmd_enroll_software_identity(true).expect("enroll");
        let err = commands::decrypt_named("does-not-exist", &yes_guard("Print", "does-not-exist"))
            .unwrap_err();
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
fn an_enrolled_paper_recovery_leaves_no_secret_on_disk() {
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

            assert!(!crate::config::recovery_path().unwrap().exists());
            assert!(
                commands::decrypt_named("secret", &yes_guard("Print", "secret")).is_err(),
                "a recovery-only item must not open from this disk without `recover --save`"
            );
        });
    });
}

#[test]
fn enroll_yubikey_mock_then_full_round_trip() {
    with_isolated_config(|_cfg| {
        crate::tests_lock::set_var("RAGEWARDEN_MOCK_HARDWARE", "1");
        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                crate::tests_lock::remove_var("RAGEWARDEN_MOCK_HARDWARE");
            }
        }
        let _cleanup = Cleanup;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            commands::cmd_enroll_yubikey(0x95, Some("mock yk"), None, true, false, false, false)
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

            let pt = commands::decrypt_named("secret-piv", &yes_guard("Print", "secret-piv"))
                .expect("decrypt");
            assert_eq!(pt.as_slice(), plaintext);
        });
    });
}

fn set_via_api(name: &str, plaintext: &[u8]) {
    use age::secrecy::ExposeSecret;
    use chrono::Utc;
    use ragewarden_core::{Recipient, encrypt};

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

#[test]
fn set_login_takes_a_username_and_repeatable_urls_and_secure_notes_refuse_them() {
    use clap::Parser;
    let cli = crate::Cli::try_parse_from([
        "rageterm",
        "set",
        "gh",
        "--type",
        "login",
        "--username",
        "alice",
        "--url",
        "https://github.com",
        "--url",
        "https://gist.github.com",
    ])
    .expect("parse");
    match cli.command {
        Some(crate::Command::Set { username, urls, .. }) => {
            assert_eq!(username.as_deref(), Some("alice"));
            assert_eq!(urls.len(), 2);
        }
        _ => panic!("expected set"),
    }
    let note = crate::Cli::try_parse_from(["rageterm", "set", "n", "--username", "x"]).unwrap();
    assert!(crate::run_command(note.command.unwrap(), false, false).is_err());
}

#[test]
fn browser_launch_arguments_are_recognised_and_subcommands_are_not() {
    use std::ffi::OsString;
    let v = |a: &[&str]| a.iter().map(OsString::from).collect::<Vec<_>>();
    assert!(crate::launched_by_browser(&v(&[
        "rageterm",
        "chrome-extension://x/"
    ])));
    assert!(crate::launched_by_browser(&v(&[
        "rageterm",
        "/p/host.json",
        "id@x"
    ])));
    assert!(!crate::launched_by_browser(&v(&[
        "rageterm",
        "native-host"
    ])));
    assert!(!crate::launched_by_browser(&v(&[
        "rageterm", "set", "x.json"
    ])));
}

#[test]
fn every_write_evaluates_fido2_with_a_fresh_salt() {
    with_isolated_config(|_cfg| {
        crate::tests_lock::set_var("RAGEWARDEN_MOCK_HARDWARE", "1");
        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                crate::tests_lock::remove_var("RAGEWARDEN_MOCK_HARDWARE");
            }
        }
        let _cleanup = Cleanup;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            commands::cmd_enroll_fido2("ragewarden", Some("mock key"), false)
                .await
                .expect("enroll fido2 (mock)");
        });
        let recipients = rt
            .block_on(crate::recipients::load())
            .expect("recipients")
            .recipients();
        let enrolled_salt = recipients
            .iter()
            .find_map(|r| match r {
                ragewarden_core::Recipient::Fido2HmacSecret { salt, .. } => Some(*salt),
                _ => None,
            })
            .expect("a fido2 recipient");
        let a = commands::build_prf_outputs_for(&recipients).expect("first write");
        let b = commands::build_prf_outputs_for(&recipients).expect("second write");
        assert_eq!((a.len(), b.len()), (1, 1));
        assert_ne!(a[0].2, b[0].2, "two writes reused a PRF salt");
        assert_ne!(a[0].2, enrolled_salt, "a write reused the enrollment salt");
        assert_ne!(a[0].3, b[0].3);
    });
}

#[test]
fn a_three_argument_prf_stanza_is_a_legacy_wrap_and_the_current_format_is_not() {
    use ragewarden_core::stanza_format as sf;
    let file_key = [3u8; 16];
    let salt = [4u8; 32];
    let prf = [5u8; 32];
    let current = sf::encrypt_fido2_hmac_with_prf(&file_key, b"cred", &salt, "ragewarden", &prf);
    assert!(!sf::is_legacy_prf_wrap(&current));
    let mut legacy = current.clone();
    legacy.args.truncate(3);
    assert!(sf::is_legacy_prf_wrap(&legacy));
}

#[test]
fn generate_and_set_generate_use_core_generator_policies() {
    let g = commands::Generate {
        length: 32,
        no_symbols: true,
        words: None,
    };
    let p = commands::generated_secret(&g).unwrap();
    assert_eq!(p.len(), 32);
    assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
    let w = commands::generated_secret(&commands::Generate {
        length: 0,
        no_symbols: false,
        words: Some(6),
    })
    .unwrap();
    assert_eq!(w.split('-').count(), 6);
}

fn field_map(
    pairs: &[(&str, &str)],
) -> std::collections::BTreeMap<String, zeroize::Zeroizing<Vec<u8>>> {
    pairs
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                zeroize::Zeroizing::new(v.as_bytes().to_vec()),
            )
        })
        .collect()
}

#[test]
fn set_field_replaces_one_field_and_keeps_the_others() {
    use ragewarden_core::protected::{self, TYPE_CARD, TYPE_LOGIN, TYPE_SECURE_NOTE};
    let card = protected::seal(
        TYPE_CARD,
        &field_map(&[("number", "4111"), ("code", "123")]),
    )
    .unwrap();
    let (sealed, fields) = commands::payload_with(
        Some((TYPE_CARD, &card)),
        TYPE_CARD,
        field_map(&[("code", "456")]),
    )
    .unwrap();
    assert_eq!(fields, ["code", "number"]);
    assert_eq!(
        &protected::field(TYPE_CARD, &sealed, "code").unwrap()[..],
        b"456"
    );
    assert_eq!(
        &protected::field(TYPE_CARD, &sealed, "").unwrap()[..],
        b"4111"
    );

    let (sealed, fields) =
        commands::payload_with(None, TYPE_LOGIN, field_map(&[("password", "pw2")])).unwrap();
    assert_eq!(
        (&sealed[..], fields),
        (&b"pw2"[..], vec!["password".to_string()])
    );

    let (sealed, fields) = commands::payload_with(
        Some((TYPE_LOGIN, b"pw")),
        TYPE_LOGIN,
        field_map(&[("totp", "seed")]),
    )
    .unwrap();
    assert_eq!(fields, ["password", "totp"]);
    assert_eq!(
        &protected::field(TYPE_LOGIN, &sealed, "").unwrap()[..],
        b"pw"
    );

    let (sealed, fields) = commands::payload_with(
        Some((TYPE_SECURE_NOTE, b"old body")),
        TYPE_LOGIN,
        field_map(&[("password", "new")]),
    )
    .unwrap();
    assert_eq!(
        fields,
        ["notes", "password"],
        "a type change keeps the note body"
    );
    assert_eq!(
        &protected::field(TYPE_LOGIN, &sealed, "notes").unwrap()[..],
        b"old body"
    );
}

#[test]
fn protectable_fields_follow_the_item_type() {
    use ragewarden_core::sync;
    let card = commands::protectable_fields(sync::CIPHER_TYPE_CARD);
    assert!(card.contains(&"number") && card.contains(&"code") && card.contains(&"notes"));
    assert!(commands::protectable_fields(sync::CIPHER_TYPE_SSH_KEY).contains(&"passphrase"));
    assert!(!commands::protectable_fields(sync::CIPHER_TYPE_LOGIN).contains(&"username"));
    assert_eq!(
        commands::protectable_fields(sync::CIPHER_TYPE_SECURE_NOTE),
        ["notes"]
    );
}

fn test_session() -> ragewarden_core::sync::Session {
    ragewarden_core::sync::Session {
        access_token: ragewarden_core::BearerToken::from_trusted("t".into()),
        refresh_token: ragewarden_core::RefreshToken::from_trusted("r".into()),
        user_id: "u".into(),
        email: "e@x".into(),
        user_enc_key: vec![7u8; 32].into(),
        user_mac_key: vec![8u8; 32].into(),
        kdf: Default::default(),
        device_id: "d".into(),
    }
}

#[test]
fn a_new_card_keeps_its_protected_number_and_cvv_out_of_the_type2_block() {
    use ragewarden_core::sync::{self, decrypt_string};
    let session = test_session();
    let with = vec![
        ("brand".to_string(), "Visa".to_string()),
        ("expMonth".to_string(), "12".to_string()),
    ];
    let draft = commands::new_item_draft(
        "visa",
        Some(commands::SetCipherType::Card),
        None,
        vec!["code".into(), "number".into()],
        &with,
    );
    let c = sync::build_cipher(&session, &draft, Some("age blob")).unwrap();
    assert_eq!(c.cipher_type, sync::CIPHER_TYPE_CARD);
    let card = c.card.as_ref().expect("a card block");
    assert!(card.number.is_none() && card.code.is_none(), "{card:?}");
    assert_eq!(
        decrypt_string(&session, card.brand.as_ref().unwrap()).unwrap(),
        "Visa"
    );
    let fields: std::collections::BTreeMap<String, String> = c
        .fields
        .iter()
        .flatten()
        .map(|f| {
            (
                decrypt_string(&session, &f.name).unwrap(),
                decrypt_string(&session, f.value.as_ref().unwrap()).unwrap(),
            )
        })
        .collect();
    assert_eq!(fields["rage:v1"], "age blob");
    let listed: Vec<String> = serde_json::from_str(&fields["rage:fields"]).unwrap();
    assert_eq!(listed, ["code", "number"]);
}

fn set_payload_via_api(name: &str, payload: &[u8]) {
    let id = crate::idfile::read(&crate::config::identity_path().unwrap()).unwrap();
    let recipient = ragewarden_core::Recipient::SoftwarePassphrase {
        armored_pubkey: ragewarden_core::ArmoredAgeRecipient::from_trusted(
            id.to_public().to_string(),
        ),
    };
    let blob = ragewarden_core::encrypt(payload, &[recipient]).unwrap();
    let store_path = crate::config::store_path().unwrap();
    crate::config::ensure_config_dir().unwrap();
    let mut store = crate::store::Store::load(&store_path).unwrap();
    store.upsert(name, String::from_utf8(blob.0).unwrap(), chrono::Utc::now());
    store.save(&store_path).unwrap();
}

#[test]
fn reencrypt_and_restrict_carry_every_protected_field() {
    use ragewarden_core::protected::{self, TYPE_CARD};
    with_isolated_config(|_cfg| {
        crate::tests_lock::set_var("RAGEWARDEN_MOCK_HARDWARE", "1");
        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                crate::tests_lock::remove_var("RAGEWARDEN_MOCK_HARDWARE");
            }
        }
        let _cleanup = Cleanup;
        commands::cmd_enroll_software_identity(true).expect("enroll");
        let payload = protected::seal(
            TYPE_CARD,
            &field_map(&[("number", "4111"), ("code", "123")]),
        )
        .unwrap();
        set_payload_via_api("visa", &payload);
        let read = |field: &str| {
            commands::decrypt_named_field("visa", field, &yes_guard("Print", "visa"))
                .expect("decrypt")
                .to_vec()
        };
        let before = crate::store::Store::load(&crate::config::store_path().unwrap())
            .unwrap()
            .get("visa")
            .unwrap()
            .rage_blob
            .clone();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(commands::cmd_enroll_yubikey(
            0x95,
            Some("mock yk"),
            None,
            true,
            false,
            false,
            false,
        ))
        .expect("enroll yubikey (mock)");
        rt.block_on(commands::cmd_reencrypt(
            Some("visa"),
            false,
            false,
            None,
            None,
            false,
            true,
            false,
        ))
        .expect("reencrypt");
        let after = crate::store::Store::load(&crate::config::store_path().unwrap())
            .unwrap()
            .get("visa")
            .unwrap()
            .rage_blob
            .clone();
        assert_ne!(before, after, "reencrypt wrote a new blob");
        assert_eq!(read("*"), payload.to_vec());
        assert_eq!(
            (read("number"), read("code")),
            (b"4111".to_vec(), b"123".to_vec())
        );

        let list = rt.block_on(crate::recipients::load()).unwrap();
        let yk = list
            .entries
            .iter()
            .find(|(_, e)| {
                matches!(
                    e.recipient,
                    ragewarden_core::Recipient::YubiKeyPivP256 { .. }
                )
            })
            .map(|(id, _)| id.clone())
            .expect("the mock YubiKey is a recipient");
        rt.block_on(commands::cmd_restrict("visa", &yk, true, false))
            .expect("restrict");
        assert_eq!(read("*"), payload.to_vec());
        assert_eq!(
            (read("number"), read("code")),
            (b"4111".to_vec(), b"123".to_vec())
        );
    });
}

#[test]
fn set_parses_typed_items_protected_fields_and_with_values() {
    use clap::Parser;
    let cli = crate::Cli::try_parse_from([
        "rageterm",
        "set",
        "visa",
        "--type",
        "card",
        "--protect",
        "number,code",
        "--with",
        "brand=Visa",
        "--with",
        "expMonth=12",
    ])
    .unwrap();
    let crate::Command::Set {
        r#type,
        protect,
        with,
        field,
        ..
    } = cli.command.unwrap()
    else {
        panic!("not a set command");
    };
    assert_eq!(r#type, Some(crate::SetType::Card));
    assert_eq!(protect, ["number", "code"]);
    assert_eq!(
        with,
        [
            ("brand".to_string(), "Visa".to_string()),
            ("expMonth".to_string(), "12".to_string())
        ]
    );
    assert_eq!(field, None);
    assert!(crate::Cli::try_parse_from(["rageterm", "set", "x", "--with", "novalue"]).is_err());
    let cli = crate::Cli::try_parse_from(["rageterm", "set", "visa", "--field", "code"]).unwrap();
    assert!(matches!(cli.command, Some(crate::Command::Set { field: Some(f), .. }) if f == "code"));
}

struct MockHardware;

impl MockHardware {
    fn on() -> Self {
        crate::tests_lock::set_var("RAGEWARDEN_MOCK_HARDWARE", "1");
        MockHardware
    }
}

impl Drop for MockHardware {
    fn drop(&mut self) {
        crate::tests_lock::remove_var("RAGEWARDEN_MOCK_HARDWARE");
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn fido_public_keys() -> Vec<Option<String>> {
    crate::identities::Identities::load()
        .unwrap()
        .items
        .values()
        .filter_map(|e| match &e.kind {
            crate::identities::IdentityKind::Fido2HmacSecret { public_key_hex, .. } => {
                Some(public_key_hex.clone())
            }
            _ => None,
        })
        .collect()
}

#[test]
fn attest_fido2_recovers_the_key_an_older_enrollment_did_not_keep() {
    with_isolated_config(|_cfg| {
        let _mock = MockHardware::on();
        let rt = runtime();
        rt.block_on(commands::cmd_enroll_fido2(
            "ragewarden",
            Some("mock key"),
            false,
        ))
        .expect("enroll fido2 (mock)");
        let keys = fido_public_keys();
        let [Some(original)] = keys.as_slice() else {
            panic!("enrollment should store the credential key: {keys:?}");
        };

        let mut ids = crate::identities::Identities::load().unwrap();
        for e in ids.items.values_mut() {
            if let crate::identities::IdentityKind::Fido2HmacSecret { public_key_hex, .. } =
                &mut e.kind
            {
                *public_key_hex = None;
            }
        }
        ids.save().unwrap();
        let list = rt.block_on(crate::recipients::load()).unwrap();
        let flags: Vec<&str> = list
            .entries
            .values()
            .map(|e| commands::attestation_flag(&ids, &e.recipient))
            .collect();
        assert!(
            flags.iter().any(|f| f.contains("attest-fido2")),
            "{flags:?}"
        );

        rt.block_on(commands::cmd_attest_fido2(None, false))
            .expect("attest");
        assert_eq!(fido_public_keys(), [Some(original.clone())]);
    });
}

#[test]
fn migrate_piv_moves_every_item_to_a_p256_slot_and_retires_the_x25519_one() {
    use ragewarden_core::Recipient;
    with_isolated_config(|_cfg| {
        let _mock = MockHardware::on();
        let rt = runtime();
        commands::cmd_enroll_software_identity(true).expect("enroll software");
        rt.block_on(commands::cmd_enroll_yubikey(
            0x82,
            Some("old slot"),
            None,
            true,
            false,
            false,
            true,
        ))
        .expect("enroll x25519 (mock)");
        let list = rt.block_on(crate::recipients::load()).unwrap();
        let (x25519_id, x25519) = list
            .entries
            .iter()
            .find(|(_, e)| matches!(e.recipient, Recipient::YubiKeyPiv { .. }))
            .map(|(id, e)| (id.clone(), e.recipient.clone()))
            .expect("an X25519 recipient");
        let ids = crate::identities::Identities::load().unwrap();
        assert!(commands::attestation_flag(&ids, &x25519).contains("migrate-piv"));
        let payload = b"migrate me".to_vec();
        let blob = ragewarden_core::encrypt(&payload, &[x25519]).unwrap();
        let store_path = crate::config::store_path().unwrap();
        let mut store = crate::store::Store::load(&store_path).unwrap();
        store.upsert(
            "on-the-old-slot",
            String::from_utf8(blob.0).unwrap(),
            chrono::Utc::now(),
        );
        store.save(&store_path).unwrap();

        rt.block_on(commands::cmd_migrate_piv(
            Some(0x9d),
            None,
            Some("new slot"),
            None,
            false,
            true,
            false,
        ))
        .expect("migrate");

        let list = rt.block_on(crate::recipients::load()).unwrap();
        assert!(
            !list.entries.contains_key(&x25519_id),
            "the X25519 slot is retired"
        );
        assert!(
            list.entries
                .values()
                .any(|e| matches!(e.recipient, Recipient::YubiKeyPivP256 { slot: 0x9d, .. }))
        );
        let blob = commands::load_item_blob("on-the-old-slot").unwrap();
        let stanzas = ragewarden_core::parse_header_stanzas(&blob).unwrap();
        let is_x25519 = |s: &ragewarden_core::Stanza| s.tag == "piv-p256" && s.args[0].len() == 43;
        let is_p256 = |s: &ragewarden_core::Stanza| s.tag == "piv-p256" && s.args[0].len() == 6;
        assert!(
            !stanzas.iter().any(is_x25519),
            "the item still names the X25519 slot"
        );
        assert!(stanzas.iter().any(is_p256), "the item names the P-256 slot");
        let pt = commands::decrypt_named("on-the-old-slot", &yes_guard("Print", "on-the-old-slot"))
            .expect("opens after the migration");
        assert_eq!(pt.as_slice(), payload.as_slice());
        let ids = crate::identities::Identities::load().unwrap();
        assert!(ids.items.values().all(|e| !matches!(
            &e.kind,
            crate::identities::IdentityKind::YubiKeyPiv { public_key_hex, .. } if public_key_hex.len() == 64
        )));
    });
}

#[test]
fn enroll_yubikey_takes_an_x25519_slot_only_with_x25519() {
    with_isolated_config(|_cfg| {
        let err = runtime()
            .block_on(commands::cmd_enroll_yubikey(
                0x95,
                None,
                Some(&"11".repeat(32)),
                true,
                false,
                false,
                false,
            ))
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("X25519") && msg.contains("--x25519"), "{msg}");
        assert!(msg.contains("ECCP256"), "{msg}");
    });
}

#[cfg(unix)]
/// The newest audit event, as `audit` would print it.
fn last_audit() -> ragewarden_core::audit::AuditEvent {
    crate::audit_helper::tail(1)
        .expect("audit log")
        .events
        .into_iter()
        .next()
        .expect("an event was recorded")
}

#[cfg(unix)]
fn assert_audited(
    kind: ragewarden_core::audit::AuditKind,
    result: ragewarden_core::audit::AuditResult,
    target: &str,
    detail: &str,
) {
    let e = last_audit();
    assert_eq!((e.kind, e.result), (kind, Some(result)), "{e:?}");
    assert_eq!(e.target.as_deref(), Some(target), "{e:?}");
    assert!(
        e.detail.as_deref().unwrap_or("").contains(detail),
        "{detail:?} not in {e:?}"
    );
}

#[cfg(unix)]
#[test]
fn every_delivery_verb_records_its_own_kind_and_outcome() {
    use ragewarden_core::audit::{AuditKind, AuditResult};
    with_isolated_config(|cfg| {
        let rt = runtime();
        commands::cmd_enroll_software_identity(true).expect("enroll");
        set_via_api("secret", b"hunter2");
        set_via_api("ssh", crate::tests_agent_add::ED25519_FIXTURE.as_bytes());
        set_via_api("otp", b"JBSWY3DPEHPK3PXP");

        rt.block_on(commands::cmd_get("secret", None, false, true, false))
            .unwrap();
        assert_audited(AuditKind::Reveal, AuditResult::Ok, "secret", "stdout");

        let code = rt
            .block_on(commands::cmd_exec(
                "secret",
                &["true".to_string()],
                false,
                &crate::output::ExecEnv::default(),
                true,
                false,
            ))
            .unwrap();
        assert_eq!(code, 0);
        assert_audited(AuditKind::Exec, AuditResult::Ok, "secret", "FD 3 of `true`");

        assert!(
            rt.block_on(commands::cmd_exec(
                "missing",
                &["true".to_string()],
                false,
                &crate::output::ExecEnv::default(),
                true,
                false,
            ))
            .is_err()
        );
        assert_audited(
            AuditKind::Exec,
            AuditResult::Failed,
            "missing",
            "FD 3 of `true`",
        );

        let socket = cfg.join("agent.sock");
        let received = crate::tests_agent_add::spawn_fake_agent(socket.clone());
        let prev = std::env::var_os("SSH_AUTH_SOCK");
        crate::tests_lock::set_var("SSH_AUTH_SOCK", &socket);
        rt.block_on(commands::cmd_agent_add("ssh", None, true, false))
            .unwrap();
        assert!(received.recv().is_ok());
        assert_audited(AuditKind::AgentAdd, AuditResult::Ok, "ssh", "ssh-agent");

        crate::tests_lock::set_var("SSH_AUTH_SOCK", cfg.join("no-agent-here.sock"));
        assert!(
            rt.block_on(commands::cmd_agent_add("ssh", None, true, false))
                .is_err()
        );
        assert_audited(AuditKind::AgentAdd, AuditResult::Failed, "ssh", "ssh-agent");
        match prev {
            Some(p) => crate::tests_lock::set_var("SSH_AUTH_SOCK", p),
            None => crate::tests_lock::remove_var("SSH_AUTH_SOCK"),
        }

        rt.block_on(commands::cmd_totp("otp", false, true, false))
            .unwrap();
        assert_audited(AuditKind::Totp, AuditResult::Ok, "otp", "stdout");
    });
}

#[test]
fn a_refusal_is_recorded_as_declined_and_a_breakage_as_failed() {
    use crate::audit_helper::result_of;
    use ragewarden_core::audit::AuditResult;
    let declined: Result<(), _> = Err(commands::CmdError::Cancelled);
    let failed: Result<(), _> = Err(commands::CmdError::NotFound("x".into()));
    assert_eq!(result_of(&declined), AuditResult::Declined);
    assert_eq!(result_of(&failed), AuditResult::Failed);
    assert_eq!(
        result_of(&Ok::<(), commands::CmdError>(())),
        AuditResult::Ok
    );
}

#[cfg(unix)]
#[test]
fn the_audit_log_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    with_isolated_config(|cfg| {
        crate::audit_helper::record_kind(ragewarden_core::audit::AuditKind::Sync);
        let mode = std::fs::metadata(cfg.join("audit.jsonl"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    });
}
