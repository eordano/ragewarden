use std::time::{Duration, SystemTime, UNIX_EPOCH};

use testcontainers::{
    core::{ContainerPort, IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    GenericImage, ImageExt,
};

const VAULTWARDEN_IMAGE: &str = "vaultwarden/server";
const VAULTWARDEN_TAG: &str = "1.32.7";
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(60);

fn opted_in() -> bool {
    matches!(std::env::var("RAGEWARDEN_E2E").as_deref(), Ok("1"))
}

const RELAXED_LOGIN_RATELIMIT_MAX_BURST: &str = "1000";
const RELAXED_LOGIN_RATELIMIT_SECONDS: &str = "1";
const RELAXED_ADMIN_RATELIMIT_MAX_BURST: &str = "1000";
const RELAXED_ADMIN_RATELIMIT_SECONDS: &str = "1";

#[test]
#[ignore = "requires Docker; opt in with RAGEWARDEN_E2E=1"]
fn round_trip_via_real_vaultwarden() {
    if !opted_in() {
        eprintln!("RAGEWARDEN_E2E not set; skipping. Run with: RAGEWARDEN_E2E=1 cargo test ... -- --ignored");
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let container = GenericImage::new(VAULTWARDEN_IMAGE, VAULTWARDEN_TAG)
            .with_exposed_port(ContainerPort::Tcp(80))
            .with_wait_for(WaitFor::message_on_stdout("Rocket has launched"))
            .with_env_var("SIGNUPS_ALLOWED", "true")
            .with_env_var("WEB_VAULT_ENABLED", "false")
            .with_env_var("ROCKET_PORT", "80")
            .with_env_var("DOMAIN", "http://localhost")
            .with_env_var("LOGIN_RATELIMIT_MAX_BURST", RELAXED_LOGIN_RATELIMIT_MAX_BURST)
            .with_env_var("LOGIN_RATELIMIT_SECONDS", RELAXED_LOGIN_RATELIMIT_SECONDS)
            .with_env_var("ADMIN_RATELIMIT_MAX_BURST", RELAXED_ADMIN_RATELIMIT_MAX_BURST)
            .with_env_var("ADMIN_RATELIMIT_SECONDS", RELAXED_ADMIN_RATELIMIT_SECONDS)
            .start()
            .await
            .expect("start vaultwarden");
        let host_port = container
            .get_host_port_ipv4(80.tcp())
            .await
            .expect("vaultwarden host port");

        let server_url = format!("http://localhost:{host_port}");
        wait_for_alive(&server_url).await;

        let server = ragewarden_core::sync::Server::self_hosted(&server_url);

        server.require_secure().expect("loopback http allowed");
        let http = make_client();

        let suffix = random_suffix();
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
        let gen = ragewarden_core::recovery::generate().expect("generate recovery");
        let plaintext = format!(
            "e2e-payload-{}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            suffix,
        );
        let recipient = ragewarden_core::Recipient::SoftwarePassphrase {
            armored_pubkey: gen.armored_pubkey.clone(),
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
        let id = ragewarden_core::recovery::from_mnemonic(&gen.mnemonic).expect("from_mnemonic");
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
#[ignore = "requires Docker; opt in with RAGEWARDEN_E2E=1"]
fn cross_frontend_interop_via_ragemanifest_snapshot() {
    if !opted_in() {
        eprintln!("RAGEWARDEN_E2E not set; skipping.");
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let container = GenericImage::new(VAULTWARDEN_IMAGE, VAULTWARDEN_TAG)
            .with_exposed_port(ContainerPort::Tcp(80))
            .with_wait_for(WaitFor::message_on_stdout("Rocket has launched"))
            .with_env_var("SIGNUPS_ALLOWED", "true")
            .with_env_var("WEB_VAULT_ENABLED", "false")
            .with_env_var("ROCKET_PORT", "80")
            .with_env_var("DOMAIN", "http://localhost")
            .with_env_var("LOGIN_RATELIMIT_MAX_BURST", RELAXED_LOGIN_RATELIMIT_MAX_BURST)
            .with_env_var("LOGIN_RATELIMIT_SECONDS", RELAXED_LOGIN_RATELIMIT_SECONDS)
            .with_env_var("ADMIN_RATELIMIT_MAX_BURST", RELAXED_ADMIN_RATELIMIT_MAX_BURST)
            .with_env_var("ADMIN_RATELIMIT_SECONDS", RELAXED_ADMIN_RATELIMIT_SECONDS)
            .start()
            .await
            .expect("start vaultwarden");
        let host_port = container
            .get_host_port_ipv4(80.tcp())
            .await
            .expect("port");
        let server_url = format!("http://localhost:{host_port}");
        wait_for_alive(&server_url).await;

        let server = ragewarden_core::sync::Server::self_hosted(&server_url);
        let http = make_client();
        let suffix = random_suffix();
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

        let gen = ragewarden_core::recovery::generate().expect("generate");
        let plaintext = format!("interop-{suffix}");
        let recipient = ragewarden_core::Recipient::SoftwarePassphrase {
            armored_pubkey: gen.armored_pubkey.clone(),
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
#[ignore = "requires Docker; opt in with RAGEWARDEN_E2E=1"]
fn ragedroid_jni_wire_format_round_trip() {
    if !opted_in() {
        eprintln!("RAGEWARDEN_E2E not set; skipping.");
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let container = GenericImage::new(VAULTWARDEN_IMAGE, VAULTWARDEN_TAG)
            .with_exposed_port(ContainerPort::Tcp(80))
            .with_wait_for(WaitFor::message_on_stdout("Rocket has launched"))
            .with_env_var("SIGNUPS_ALLOWED", "true")
            .with_env_var("WEB_VAULT_ENABLED", "false")
            .with_env_var("ROCKET_PORT", "80")
            .with_env_var("DOMAIN", "http://localhost")
            .with_env_var("LOGIN_RATELIMIT_MAX_BURST", RELAXED_LOGIN_RATELIMIT_MAX_BURST)
            .with_env_var("LOGIN_RATELIMIT_SECONDS", RELAXED_LOGIN_RATELIMIT_SECONDS)
            .with_env_var("ADMIN_RATELIMIT_MAX_BURST", RELAXED_ADMIN_RATELIMIT_MAX_BURST)
            .with_env_var("ADMIN_RATELIMIT_SECONDS", RELAXED_ADMIN_RATELIMIT_SECONDS)
            .start()
            .await
            .expect("start vaultwarden");
        let host_port = container.get_host_port_ipv4(80.tcp()).await.expect("port");
        let server_url = format!("http://localhost:{host_port}");
        wait_for_alive(&server_url).await;

        let server = ragewarden_core::sync::Server::self_hosted(&server_url);
        let http = make_client();
        let suffix = random_suffix();
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

async fn wait_for_alive(server_url: &str) {
    let alive = format!("{server_url}/alive");
    let client = reqwest::Client::new();
    let deadline = std::time::Instant::now() + HEALTHCHECK_TIMEOUT;
    loop {
        match client.get(&alive).send().await {
            Ok(r) if r.status().is_success() => return,
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            panic!("vaultwarden /alive never returned 2xx within {HEALTHCHECK_TIMEOUT:?}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn random_suffix() -> String {
    use rand::Rng;
    let mut b = [0u8; 4];
    rand::rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn make_client() -> impl ragewarden_core::sync::HttpClient {
    ragewarden_core::http_reqwest::ReqwestClient::new("rageterm-e2e-test/0.1")
        .expect("rustls client should always build")
}
