use std::time::{SystemTime, UNIX_EPOCH};

fn opted_in() -> bool {
    matches!(std::env::var("RAGEWARDEN_LIVE_TEST").as_deref(), Ok("1"))
}

fn server() -> String {
    std::env::var("RAGEWARDEN_LIVE_SERVER")
        .unwrap_or_else(|_| "https://vault.example.com".into())
}

fn email() -> Option<String> {
    std::env::var("RAGEWARDEN_LIVE_EMAIL").ok()
}

fn password() -> Option<String> {
    std::env::var("RAGEWARDEN_LIVE_PASSWORD").ok()
}

#[test]
#[ignore = "live test against a real Vaultwarden server; set RAGEWARDEN_LIVE_SERVER and opt in with RAGEWARDEN_LIVE_TEST=1"]
fn live_recovery_round_trip() {
    if !opted_in() {
        eprintln!("RAGEWARDEN_LIVE_TEST not set; skipping live test.");
        return;
    }
    let (email, password) = match (email(), password()) {
        (Some(e), Some(p)) => (e, p),
        _ => {
            eprintln!("RAGEWARDEN_LIVE_EMAIL / RAGEWARDEN_LIVE_PASSWORD not set; skipping.");
            return;
        }
    };
    let server = server();

    let tmp = tempfile::TempDir::new().unwrap();
    std::env::set_var("RAGEWARDEN_CONFIG_DIR", tmp.path());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let client = ragewarden_core::sync::Server::self_hosted(&server);
        let http = make_client();
        let session =
            ragewarden_core::sync::login(&http, &client, &email, &password, "rageterm-live-test")
                .await
                .expect("login");

        let gen = ragewarden_core::recovery::generate().expect("generate");
        let plaintext = format!(
            "live-recovery-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );
        let recipient = ragewarden_core::Recipient::SoftwarePassphrase {
            armored_pubkey: gen.armored_pubkey.clone(),
        };
        let blob = ragewarden_core::encrypt(plaintext.as_bytes(), &[recipient])
            .expect("encrypt to recovery");
        let armored = String::from_utf8(blob.0).unwrap();

        let name = format!("live-recovery-test-{}", random_suffix());
        let cipher_in =
            ragewarden_core::sync::build_rage_cipher(&session, &name, &armored).expect("build");
        let saved = ragewarden_core::sync::create_cipher(&http, &client, &session, &cipher_in)
            .await
            .expect("create cipher");
        let cipher_id = saved.id.clone().expect("cipher id");
        eprintln!("Created cipher `{name}` id={cipher_id}");

        let vault = ragewarden_core::sync::fetch_vault(&http, &client, &session)
            .await
            .expect("fetch vault");
        let our = vault
            .ciphers
            .iter()
            .find(|c| c.id.as_deref() == Some(cipher_id.as_str()))
            .expect("our cipher in vault");
        let blob_armored = ragewarden_core::sync::extract_rage_blob(&session, our)
            .expect("extract")
            .expect("rage blob present");
        let blob = ragewarden_core::AgeBlob::from_bytes(blob_armored.into_bytes());

        let id = ragewarden_core::recovery::from_mnemonic(&gen.mnemonic).expect("recover");
        use age::secrecy::ExposeSecret;
        let armored_secret = ragewarden_core::ArmoredAgeSecret::from_trusted(
            id.to_string().expose_secret().to_string(),
        );
        let sw = ragewarden_core::software_passphrase_identity(&armored_secret)
            .expect("software identity");
        let identities: Vec<Box<dyn ragewarden_core::Identity>> = vec![Box::new(sw)];
        let recovered = ragewarden_core::decrypt(&blob, &identities).expect("decrypt");
        assert_eq!(recovered.as_slice(), plaintext.as_bytes());

        eprintln!("Live test passed. Manual cleanup of `{name}` recommended.");

        std::env::remove_var("RAGEWARDEN_CONFIG_DIR");
    });

    drop(tmp);
}

fn random_suffix() -> String {
    use rand::Rng;
    let mut b = [0u8; 4];
    rand::rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn make_client() -> impl ragewarden_core::sync::HttpClient {
    ragewarden_core::http_reqwest::ReqwestClient::new("rageterm-live-test/0.1")
        .expect("rustls client should always build")
}
