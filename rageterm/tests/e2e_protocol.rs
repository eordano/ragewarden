//! core's account and vault protocol against a real Vaultwarden: KDF
//! upgrades in both request shapes, Argon2id, the downgrade pin, token
//! refresh, field-preserving updates, folder moves, the unified history and
//! wrong-key detection.

use ragewarden_core::bitwarden::{encrypt_type2, master_password_hash, stretch_master_key};
use ragewarden_core::history::{self, HistoryEntry};
use ragewarden_core::sync::{
    self, CipherDraft, CipherEdit, KdfParams, LoginOptions, Server, Session, SyncError,
    build_cipher, build_meta_cipher, create_cipher, create_folder, extract_rage_blob, fetch_vault,
    login, login_with_options, register, register_with_kdf, upgrade_kdf,
};

mod support;

const PASSWORD: &str = "e2e-password-correct-horse-battery";

fn fresh_email() -> String {
    format!("proto-{}@ragewarden.test", support::random_suffix())
}

/// Moves an account to `kdf` with a raw request, as another client (or a
/// hostile server operator) could, bypassing the floors `upgrade_kdf` keeps.
async fn force_kdf(server_url: &str, session: &Session, kdf: KdfParams) {
    let old = session
        .kdf
        .derive_master_key(PASSWORD, &session.email)
        .unwrap();
    let new = kdf.derive_master_key(PASSWORD, &session.email).unwrap();
    let (e, m) = stretch_master_key(&new);
    let mut raw = session.user_enc_key.to_vec();
    raw.extend_from_slice(&session.user_mac_key);
    let key = encrypt_type2(&raw, &e, &m);
    let new_hash = master_password_hash(&new, PASSWORD);
    let wire = serde_json::json!({
        "kdfType": kdf.kdf, "iterations": kdf.iterations,
        "memory": kdf.memory_mib, "parallelism": kdf.parallelism,
    });
    let body = serde_json::json!({
        "masterPasswordHash": master_password_hash(&old, PASSWORD),
        "authenticationData": { "salt": session.email, "kdf": wire, "masterPasswordAuthenticationHash": new_hash },
        "unlockData": { "salt": session.email, "kdf": wire, "masterKeyWrappedUserKey": key },
        "kdf": kdf.kdf, "kdfIterations": kdf.iterations, "kdfMemory": kdf.memory_mib,
        "kdfParallelism": kdf.parallelism, "newMasterPasswordHash": new_hash, "key": key,
    });
    let res = reqwest::Client::new()
        .post(format!("{server_url}/api/accounts/kdf"))
        .header("Authorization", session.bearer())
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(
        res.status().is_success(),
        "force kdf: {}",
        res.text().await.unwrap()
    );
}

#[test]
fn kdf_upgrades_reach_the_server_and_argon2id_accounts_log_in() {
    support::runtime().block_on(async {
        let Some(vw) = support::start().await else {
            return;
        };
        let server = Server::self_hosted(&vw.url);
        let http = support::client();

        let email = fresh_email();
        register(&http, &server, &email, PASSWORD, "p", 600_000)
            .await
            .unwrap();
        let s = login(&http, &server, &email, PASSWORD, "dev")
            .await
            .unwrap();
        force_kdf(&vw.url, &s, KdfParams::pbkdf2(100_000)).await;

        let low = login(&http, &server, &email, PASSWORD, "dev")
            .await
            .expect("100k login");
        assert_eq!(low.kdf, KdfParams::pbkdf2(100_000));
        let up = upgrade_kdf(&http, &server, &low, PASSWORD, "dev", KdfParams::default())
            .await
            .expect("upgrade to 600k on the real server");
        assert_eq!(up.kdf, KdfParams::default());
        let again = login(&http, &server, &email, PASSWORD, "dev")
            .await
            .unwrap();
        assert_eq!(
            again.kdf,
            KdfParams::default(),
            "prelogin now reports the new count"
        );

        let argon = upgrade_kdf(
            &http,
            &server,
            &again,
            PASSWORD,
            "dev",
            KdfParams::argon2id_default(),
        )
        .await
        .expect("PBKDF2 -> Argon2id");
        assert_eq!(argon.kdf, KdfParams::argon2id_default());
        fetch_vault(&http, &server, &argon)
            .await
            .expect("the re-login's token works");

        let email2 = fresh_email();
        register_with_kdf(
            &http,
            &server,
            &email2,
            PASSWORD,
            "p",
            KdfParams::argon2id_default(),
        )
        .await
        .expect("register Argon2id");
        let s2 = login(&http, &server, &email2, PASSWORD, "dev")
            .await
            .expect("Argon2id login");
        assert!(s2.kdf.is_argon2id());
    });
}

#[test]
fn the_pin_refuses_a_server_side_downgrade_before_sending_the_hash() {
    support::runtime().block_on(async {
        let Some(vw) = support::start().await else {
            return;
        };
        let server = Server::self_hosted(&vw.url);
        let http = support::client();
        let email = fresh_email();
        register(&http, &server, &email, PASSWORD, "p", 600_000)
            .await
            .unwrap();
        let s = login(&http, &server, &email, PASSWORD, "dev")
            .await
            .unwrap();
        let pin = s.kdf;
        force_kdf(&vw.url, &s, KdfParams::pbkdf2(100_000)).await;

        let pinned = LoginOptions {
            kdf_pin: Some(pin),
            ..LoginOptions::default()
        };
        let err = login_with_options(&http, &server, &email, PASSWORD, "dev", &pinned)
            .await
            .unwrap_err();
        assert!(matches!(err, SyncError::KdfDowngraded { .. }), "{err:?}");
    });
}

#[test]
fn a_refreshed_token_works_and_the_old_one_is_replaced() {
    support::runtime().block_on(async {
        let Some(vw) = support::start().await else {
            return;
        };
        let server = Server::self_hosted(&vw.url);
        let http = support::client();
        let email = fresh_email();
        register(&http, &server, &email, PASSWORD, "p", 600_000)
            .await
            .unwrap();
        let mut s = login(&http, &server, &email, PASSWORD, "dev")
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let before = s.access_token.expose().to_string();
        sync::refresh_session(&http, &server, &mut s)
            .await
            .expect("refresh");
        assert_ne!(
            s.access_token.expose(),
            before,
            "a token minted a second later differs"
        );
        fetch_vault(&http, &server, &s)
            .await
            .expect("fetch with the refreshed token");
        assert!(!s.refresh_token.is_empty());
    });
}

#[test]
fn protecting_and_rotating_a_login_keeps_every_field_on_the_server() {
    support::runtime().block_on(async {
        let Some(vw) = support::start().await else {
            return;
        };
        let server = Server::self_hosted(&vw.url);
        let http = support::client();
        let email = fresh_email();
        register(&http, &server, &email, PASSWORD, "p", 600_000)
            .await
            .unwrap();
        let s = login(&http, &server, &email, PASSWORD, "dev")
            .await
            .unwrap();
        let folder = create_folder(&http, &server, &s, "Work").await.unwrap();

        let draft = CipherDraft {
            login: true,
            name: "Shop".into(),
            notes: Some("order history in the drawer".into()),
            username: Some("me@shop".into()),
            uris: vec![
                "https://shop.example/login".into(),
                "https://m.shop.example".into(),
            ],
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            password: Some("hunter2".into()),
            folder_id: Some(folder.id.clone()),
            favorite: true,
            ..CipherDraft::default()
        };
        let created = create_cipher(&http, &server, &s, &build_cipher(&s, &draft, None).unwrap())
            .await
            .unwrap();
        let id = created.id.clone().unwrap();

        for blob in ["FIRST-BLOB", "ROTATED-BLOB"] {
            sync::update_preserving(&http, &server, &s, &id, Some(blob), &CipherEdit::default())
                .await
                .expect("update_preserving");
        }

        let vault = fetch_vault(&http, &server, &s).await.unwrap();
        let c = vault
            .ciphers
            .iter()
            .find(|c| c.id.as_deref() == Some(&id))
            .unwrap();
        let d =
            |ct: &ragewarden_core::Type2EncString| sync::decrypt_cipher_string(&s, c, ct).unwrap();
        assert_eq!(c.cipher_type, 1);
        assert_eq!(c.folder_id.as_deref(), Some(folder.id.as_str()));
        assert!(c.favorite);
        assert_eq!(d(c.notes.as_ref().unwrap()), "order history in the drawer");
        let l = c.login.as_ref().unwrap();
        assert_eq!(d(l.username.as_ref().unwrap()), "me@shop");
        assert_eq!(d(l.totp.as_ref().unwrap()), "JBSWY3DPEHPK3PXP");
        let uris: Vec<String> = l.uris.as_ref().unwrap().iter().map(|u| d(&u.uri)).collect();
        assert_eq!(
            uris,
            ["https://shop.example/login", "https://m.shop.example"]
        );
        assert!(
            l.password.is_none(),
            "the protected password left the Type-2 field"
        );
        assert_eq!(
            extract_rage_blob(&s, c).unwrap().as_deref(),
            Some("ROTATED-BLOB")
        );
        let rage_fields = c
            .fields
            .iter()
            .flatten()
            .filter(|f| d(&f.name) == sync::RAGE_FIELD_NAME)
            .count();
        assert_eq!(rage_fields, 1);
    });
}

#[test]
fn a_folder_move_rewrites_nothing_else() {
    support::runtime().block_on(async {
        let Some(vw) = support::start().await else {
            return;
        };
        let server = Server::self_hosted(&vw.url);
        let http = support::client();
        let email = fresh_email();
        register(&http, &server, &email, PASSWORD, "p", 600_000)
            .await
            .unwrap();
        let s = login(&http, &server, &email, PASSWORD, "dev")
            .await
            .unwrap();
        let created = create_cipher(
            &http,
            &server,
            &s,
            &sync::build_rage_cipher(&s, "n", "B").unwrap(),
        )
        .await
        .unwrap();
        let folder = create_folder(&http, &server, &s, "Moved").await.unwrap();
        let id = created.id.as_deref().unwrap();
        let moved = sync::set_folder_on(&http, &server, &s, id, Some(&folder.id))
            .await
            .expect("set_folder_on");
        assert_eq!(moved.folder_id.as_deref(), Some(folder.id.as_str()));
        assert_eq!(moved.name, created.name, "the name was not re-encrypted");
        let cleared = sync::set_folder_on(&http, &server, &s, id, None)
            .await
            .expect("clear folder");
        assert!(cleared.folder_id.is_none());
    });
}

#[test]
fn history_lives_in_one_document_and_absorbs_the_browsers_legacy_ones() {
    support::runtime().block_on(async {
        let Some(vw) = support::start().await else {
            return;
        };
        let server = Server::self_hosted(&vw.url);
        let http = support::client();
        let email = fresh_email();
        register(&http, &server, &email, PASSWORD, "p", 600_000)
            .await
            .unwrap();
        let s = login(&http, &server, &email, PASSWORD, "dev")
            .await
            .unwrap();

        let legacy =
            serde_json::json!([{ "recordedAt": 1, "cipherId": "item-1", "priorPayload": "OLD" }]);
        let legacy_name = format!("{}:item-1", history::LEGACY_MARKER_NAME);
        create_cipher(
            &http,
            &server,
            &s,
            &build_meta_cipher(&s, &legacy_name, &legacy.to_string()).unwrap(),
        )
        .await
        .unwrap();

        let vault = fetch_vault(&http, &server, &s).await.unwrap();
        history::record_revision(
            &http,
            &server,
            &s,
            &vault,
            None,
            HistoryEntry::revision("item-1", "NEWER", vec![], 2),
        )
        .await
        .expect("record");
        let vault = fetch_vault(&http, &server, &s).await.unwrap();
        history::record_revision(
            &http,
            &server,
            &s,
            &vault,
            None,
            HistoryEntry::deletion("item-1", "LAST", vec![], 3),
        )
        .await
        .expect("record deletion");

        let vault = fetch_vault(&http, &server, &s).await.unwrap();
        let names: Vec<String> = vault
            .ciphers
            .iter()
            .filter_map(|c| sync::cipher_name(&s, c).ok())
            .collect();
        assert!(
            !names.contains(&legacy_name),
            "the browser's legacy document was deleted"
        );
        assert_eq!(
            names.iter().filter(|n| *n == history::MARKER_NAME).count(),
            1
        );
        let got = history::load_history(&s, &vault, "item-1").unwrap();
        let payloads: Vec<&str> = got
            .iter()
            .map(|e| e.prior_payload_armored.as_str())
            .collect();
        assert_eq!(payloads, ["LAST", "NEWER", "OLD"]);
        assert!(got[0].deleted);
    });
}

#[test]
fn another_accounts_key_is_an_error_not_an_empty_vault() {
    support::runtime().block_on(async {
        let Some(vw) = support::start().await else {
            return;
        };
        let server = Server::self_hosted(&vw.url);
        let http = support::client();
        let email = fresh_email();
        register(&http, &server, &email, PASSWORD, "p", 600_000)
            .await
            .unwrap();
        let s = login(&http, &server, &email, PASSWORD, "dev")
            .await
            .unwrap();
        create_cipher(
            &http,
            &server,
            &s,
            &sync::build_rage_cipher(&s, "n", "B").unwrap(),
        )
        .await
        .unwrap();
        let mut wrong = s.clone();
        wrong.user_enc_key = vec![0x5a; 32].into();
        let err = fetch_vault(&http, &server, &wrong).await.unwrap_err();
        assert!(matches!(err, SyncError::WrongUserKey { .. }), "{err:?}");
    });
}

fn sealed_blob(
    cipher_type: u8,
    fields: &[(&str, &str)],
) -> (String, Vec<Box<dyn ragewarden_core::Identity>>) {
    use age::secrecy::ExposeSecret;
    let generated = ragewarden_core::recovery::generate().unwrap();
    let recipients = vec![ragewarden_core::Recipient::SoftwarePassphrase {
        armored_pubkey: generated.armored_pubkey.clone(),
    }];
    let map = fields
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                zeroize::Zeroizing::new(v.as_bytes().to_vec()),
            )
        })
        .collect();
    let payload = ragewarden_core::protected::seal(cipher_type, &map).unwrap();
    let blob = ragewarden_core::encrypt(&payload, &recipients).unwrap();
    let id = ragewarden_core::recovery::from_mnemonic(&generated.mnemonic).unwrap();
    let secret =
        ragewarden_core::ArmoredAgeSecret::from_trusted(id.to_string().expose_secret().to_string());
    let identity = ragewarden_core::software_passphrase_identity(&secret).unwrap();
    (String::from_utf8(blob.0).unwrap(), vec![Box::new(identity)])
}

#[test]
fn cards_identities_and_ssh_keys_round_trip_with_several_protected_fields() {
    use std::collections::BTreeMap;
    support::runtime().block_on(async {
        let Some(vw) = support::start().await else {
            return;
        };
        let server = Server::self_hosted(&vw.url);
        let http = support::client();
        let email = fresh_email();
        register(&http, &server, &email, PASSWORD, "p", 600_000)
            .await
            .unwrap();
        let s = login(&http, &server, &email, PASSWORD, "dev")
            .await
            .unwrap();
        let block = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };

        type Case<'a> = (u8, CipherDraft, Vec<(&'a str, &'a str)>, (&'a str, &'a str));
        let cases: Vec<Case<'_>> = vec![
            (
                3,
                CipherDraft {
                    name: "Visa".into(),
                    card: Some(block(&[
                        ("cardholderName", "O C"),
                        ("brand", "Visa"),
                        ("expMonth", "12"),
                        ("expYear", "2030"),
                    ])),
                    ..CipherDraft::default()
                },
                vec![("number", "4111111111111111"), ("code", "123")],
                ("brand", "Visa"),
            ),
            (
                4,
                CipherDraft {
                    name: "Me".into(),
                    identity: Some(block(&[
                        ("title", "Dr"),
                        ("firstName", "Octo"),
                        ("company", "GitHub"),
                        ("email", "o@example.com"),
                    ])),
                    ..CipherDraft::default()
                },
                vec![
                    ("ssn", "000-00-0000"),
                    ("passportNumber", "P123"),
                    ("licenseNumber", "L456"),
                ],
                ("company", "GitHub"),
            ),
            (
                5,
                CipherDraft {
                    name: "deploy key".into(),
                    ssh_key: Some(block(&[
                        ("publicKey", "ssh-ed25519 AAAAtest"),
                        ("keyFingerprint", "SHA256:test"),
                    ])),
                    ..CipherDraft::default()
                },
                vec![
                    ("privateKey", "openssh-key-v1 test material"),
                    ("passphrase", "pp"),
                ],
                ("keyFingerprint", "SHA256:test"),
            ),
        ];

        for (ty, mut draft, secrets, (visible, visible_value)) in cases {
            let (blob, ids) = sealed_blob(ty, &secrets);
            draft.protected_fields = secrets.iter().map(|(k, _)| k.to_string()).collect();
            let created = create_cipher(
                &http,
                &server,
                &s,
                &build_cipher(&s, &draft, Some(&blob)).unwrap(),
            )
            .await
            .unwrap();
            let id = created.id.clone().unwrap();

            let edit = CipherEdit {
                name: Some(format!("{} (renamed)", draft.name)),
                ..CipherEdit::default()
            };
            sync::update_preserving(&http, &server, &s, &id, None, &edit)
                .await
                .unwrap();

            let vault = fetch_vault(&http, &server, &s).await.unwrap();
            let c = vault
                .ciphers
                .iter()
                .find(|c| c.id.as_deref() == Some(&id))
                .unwrap();
            assert_eq!(c.cipher_type, ty);
            assert_eq!(
                sync::outer_field(&s, c, visible).unwrap().as_deref(),
                Some(visible_value),
                "type {ty}"
            );
            let names = sync::protected_field_names(&s, c).unwrap();
            assert_eq!(
                names,
                secrets
                    .iter()
                    .map(|(k, _)| k.to_string())
                    .collect::<Vec<_>>()
            );
            let blob = extract_rage_blob(&s, c).unwrap().unwrap();
            let payload = ragewarden_core::decrypt(
                &ragewarden_core::AgeBlob::from_bytes(blob.into_bytes()),
                &ids,
            )
            .unwrap();
            for (name, value) in &secrets {
                assert_eq!(
                    &ragewarden_core::protected::field(ty, &payload, name).unwrap()[..],
                    value.as_bytes()
                );
                assert_eq!(
                    sync::outer_field(&s, c, name).unwrap(),
                    None,
                    "`{name}` leaked into Type-2"
                );
                assert!(sync::protects_field(&s, c, name).unwrap());
            }
        }
    });
}
