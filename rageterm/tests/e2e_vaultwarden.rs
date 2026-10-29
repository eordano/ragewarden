use std::time::{SystemTime, UNIX_EPOCH};

mod support;

#[test]
fn round_trip_via_real_vaultwarden() {
    let rt = support::runtime();

    rt.block_on(async {
        let Some(vw) = support::start().await else {
            return;
        };
        let server_url = vw.url.clone();

        let server = ragewarden_core::sync::Server::self_hosted(&server_url);

        server.require_secure().expect("loopback http allowed");
        let http = support::client();

        let suffix = support::random_suffix();
        let email = format!("e2e-{suffix}@ragewarden.test");
        let password = "e2e-password-correct-horse-battery";

        eprintln!("[e2e] registering {email} on {server_url}");
        ragewarden_core::sync::register(&http, &server, &email, password, "e2e", 600_000)
            .await
            .expect("register");

        eprintln!("[e2e] logging in");
        let session =
            ragewarden_core::sync::login(&http, &server, &email, password, "rageterm-e2e-device")
                .await
                .expect("login");

        eprintln!("[e2e] generating recovery identity + encrypting payload");
        let generated = ragewarden_core::recovery::generate().expect("generate recovery");
        let plaintext = format!(
            "e2e-payload-{}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            suffix,
        );
        let recipient = ragewarden_core::Recipient::SoftwarePassphrase {
            armored_pubkey: generated.armored_pubkey.clone(),
        };
        let blob = ragewarden_core::encrypt(plaintext.as_bytes(), &[recipient]).expect("encrypt");
        let armored = String::from_utf8(blob.0).unwrap();

        let item_name = format!("e2e-cipher-{suffix}");
        eprintln!("[e2e] building rage cipher `{item_name}` and POSTing");
        let cipher_in = ragewarden_core::sync::build_rage_cipher(&session, &item_name, &armored)
            .expect("build_rage_cipher");
        let saved = ragewarden_core::sync::create_cipher(&http, &server, &session, &cipher_in)
            .await
            .expect("create_cipher");
        let cipher_id = saved.id.clone().expect("server returned cipher id");
        eprintln!("[e2e] server stored cipher id={cipher_id}");

        eprintln!("[e2e] re-fetching vault");
        let vault = ragewarden_core::sync::fetch_vault(&http, &server, &session)
            .await
            .expect("fetch_vault");
        let our = vault
            .ciphers
            .iter()
            .find(|c| c.id.as_deref() == Some(cipher_id.as_str()))
            .expect("our cipher in vault");

        let blob_armored = ragewarden_core::sync::extract_rage_blob(&session, our)
            .expect("extract_rage_blob")
            .expect("rage:v1 field present");
        let blob = ragewarden_core::AgeBlob::from_bytes(blob_armored.into_bytes());

        eprintln!("[e2e] reconstructing identity from mnemonic + decrypting");
        use age::secrecy::ExposeSecret;
        let id =
            ragewarden_core::recovery::from_mnemonic(&generated.mnemonic).expect("from_mnemonic");
        let armored_secret = ragewarden_core::ArmoredAgeSecret::from_trusted(
            id.to_string().expose_secret().to_string(),
        );
        let sw = ragewarden_core::software_passphrase_identity(&armored_secret)
            .expect("software identity");
        let identities: Vec<Box<dyn ragewarden_core::Identity>> = vec![Box::new(sw)];
        let recovered = ragewarden_core::decrypt(&blob, &identities).expect("decrypt");
        assert_eq!(recovered.as_slice(), plaintext.as_bytes());

        eprintln!("[e2e] round-trip OK ({} bytes)", plaintext.len());
    });
}

#[test]
fn cross_frontend_interop_via_ragemanifest_snapshot() {
    let rt = support::runtime();

    rt.block_on(async {
        let Some(vw) = support::start().await else {
            return;
        };
        let server_url = vw.url.clone();

        let server = ragewarden_core::sync::Server::self_hosted(&server_url);
        let http = support::client();
        let suffix = support::random_suffix();
        let email = format!("e2e-interop-{suffix}@ragewarden.test");
        let password = "e2e-interop-correct-horse-battery";

        ragewarden_core::sync::register(&http, &server, &email, password, "e2e-interop", 600_000)
            .await
            .expect("register");
        let session = ragewarden_core::sync::login(
            &http,
            &server,
            &email,
            password,
            "rageterm-e2e-interop-device",
        )
        .await
        .expect("login");

        let generated = ragewarden_core::recovery::generate().expect("generate");
        let plaintext = format!("interop-{suffix}");
        let recipient = ragewarden_core::Recipient::SoftwarePassphrase {
            armored_pubkey: generated.armored_pubkey.clone(),
        };
        let blob = ragewarden_core::encrypt(plaintext.as_bytes(), &[recipient]).expect("encrypt");
        let armored = String::from_utf8(blob.0).unwrap();
        let cipher_in =
            ragewarden_core::sync::build_rage_cipher(&session, "interop-cipher", &armored)
                .expect("build");
        ragewarden_core::sync::create_cipher(&http, &server, &session, &cipher_in)
            .await
            .expect("create");

        let vault = ragewarden_core::sync::fetch_vault(&http, &server, &session)
            .await
            .expect("fetch");

        let snapshot = ragemanifest::snapshot::build_snapshot(&session, &vault);
        let interop = snapshot
            .ciphers
            .iter()
            .find(|c| c.name == "interop-cipher")
            .expect("ragemanifest snapshot sees the cipher");
        assert!(
            interop.rage,
            "ragemanifest snapshot must flag the cipher as rage-protected"
        );
        eprintln!("[e2e-interop] ragemanifest snapshot agrees with rageterm: {} cipher(s) total, our cipher rage={}", snapshot.ciphers.len(), interop.rage);
    });
}

#[test]
fn ragedroid_jni_wire_format_round_trip() {
    let rt = support::runtime();

    rt.block_on(async {
        let Some(vw) = support::start().await else {
            return;
        };
        let server_url = vw.url.clone();

        let server = ragewarden_core::sync::Server::self_hosted(&server_url);
        let http = support::client();
        let suffix = support::random_suffix();
        let email = format!("e2e-droid-{suffix}@ragewarden.test");
        let password = "e2e-droid-correct-horse-battery";

        ragewarden_core::sync::register(&http, &server, &email, password, "e2e-droid", 600_000)
            .await
            .expect("register");
        let session =
            ragewarden_core::sync::login(&http, &server, &email, password, "ragedroid-e2e-device")
                .await
                .expect("login");

        let credential_id = b"ragedroid-mock-credential";
        let salt = [0xab; 32];
        let prf_output = [0x77; 32];
        let recipient = ragewarden_core::Recipient::PasskeyPrf {
            credential_id: credential_id.to_vec(),
            salt,
            rp_id: "ragewarden".to_string(),
            label: "mock-passkey".to_string(),
        };
        let prf_table = vec![ragewarden_core::PrfEntry {
            rp_id: "ragewarden",
            credential_id: &[],
            salt: &salt,
            prf_output: &prf_output,
        }];
        let plaintext = format!("ragedroid-jni-wire-format-{suffix}");
        let blob =
            ragewarden_core::encrypt_with_prf(plaintext.as_bytes(), &[recipient], &prf_table)
                .expect("encrypt");
        let armored = String::from_utf8(blob.0).unwrap();

        let cipher_in =
            ragewarden_core::sync::build_rage_cipher(&session, "droid-cipher", &armored)
                .expect("build cipher");
        let saved = ragewarden_core::sync::create_cipher(&http, &server, &session, &cipher_in)
            .await
            .expect("create cipher");
        let cipher_id = saved.id.clone().expect("server returned cipher id");
        eprintln!("[droid-e2e] server stored cipher id={cipher_id}");

        let vault = ragewarden_core::sync::fetch_vault(&http, &server, &session)
            .await
            .expect("fetch vault");
        let our = vault
            .ciphers
            .iter()
            .find(|c| c.id.as_deref() == Some(cipher_id.as_str()))
            .expect("our cipher");
        let blob_armored = ragewarden_core::sync::extract_rage_blob(&session, our)
            .expect("extract")
            .expect("rage:v1 field present");
        let blob = ragewarden_core::AgeBlob::from_bytes(blob_armored.into_bytes());

        struct MockPrfIdentity {
            prf: [u8; 32],
        }
        impl ragewarden_core::Identity for MockPrfIdentity {
            fn try_unwrap_stanza(
                &self,
                stanza: &ragewarden_core::Stanza,
            ) -> Result<Option<ragewarden_core::FileKey>, ragewarden_core::IdentityError>
            {
                if stanza.tag != "webauthn-prf-v1" {
                    return Ok(None);
                }
                let fk = ragewarden_core::stanza_format::decrypt_webauthn_prf_with_prf(
                    stanza, &self.prf,
                )
                .map_err(|e| ragewarden_core::IdentityError::Crypto(e.to_string()))?;
                Ok(Some(fk))
            }
            fn display(&self) -> &str {
                "mock-passkey"
            }
        }
        let identities: Vec<Box<dyn ragewarden_core::Identity>> =
            vec![Box::new(MockPrfIdentity { prf: prf_output })];
        let recovered = ragewarden_core::decrypt(&blob, &identities).expect("decrypt");
        assert_eq!(recovered.as_slice(), plaintext.as_bytes());
        eprintln!(
            "[droid-e2e] webauthn-prf wire format round-trip OK ({} bytes)",
            plaintext.len()
        );
    });
}
