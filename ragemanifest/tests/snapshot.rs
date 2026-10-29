use std::sync::Mutex;

use async_trait::async_trait;
use ragemanifest::snapshot::{
    LocalIdentityInventory, WireSession, build_snapshot, build_snapshot_with_identities,
};
use ragewarden_core::bitwarden::{encrypt_type2, make_user_key};
use ragewarden_core::sync::{
    self, Cipher, CipherLogin, CipherUri, Folder, HttpBody, HttpClient, HttpError, HttpResponse,
    Server, Session, Vault, build_rage_cipher, encrypt_string,
};
use ragewarden_core::{Recipient, Type2EncString, encrypt as core_encrypt};

struct RecordingClient {
    log: Mutex<Vec<String>>,
}

impl RecordingClient {
    fn new() -> Self {
        Self {
            log: Mutex::new(Vec::new()),
        }
    }
    fn calls(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

#[async_trait]
impl HttpClient for RecordingClient {
    async fn post(
        &self,
        url: &str,
        _body: HttpBody,
        _headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        self.log.lock().unwrap().push(format!("POST {url}"));
        Ok(HttpResponse {
            status: 200,
            body: b"{}".to_vec(),
        })
    }
    async fn put(
        &self,
        url: &str,
        _body: HttpBody,
        _headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        self.log.lock().unwrap().push(format!("PUT {url}"));
        Ok(HttpResponse {
            status: 200,
            body: b"{}".to_vec(),
        })
    }
    async fn get(
        &self,
        url: &str,
        _headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        self.log.lock().unwrap().push(format!("GET {url}"));
        Ok(HttpResponse {
            status: 200,
            body: b"{}".to_vec(),
        })
    }
    async fn delete(
        &self,
        url: &str,
        _headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        self.log.lock().unwrap().push(format!("DELETE {url}"));
        Ok(HttpResponse {
            status: 200,
            body: b"{}".to_vec(),
        })
    }
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    let mut cx = Context::from_waker(Waker::noop());
    let mut fut = Box::pin(fut);
    loop {
        match Pin::new(&mut fut).as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => continue,
        }
    }
}

fn make_session() -> Session {
    let master = ragewarden_core::bitwarden::derive_master_key("hunter2", "test@example.com", 100);
    let user_key = make_user_key(&master);
    Session {
        access_token: ragewarden_core::BearerToken::from_trusted("access-stub".into()),
        refresh_token: ragewarden_core::RefreshToken::from_trusted("refresh-stub".into()),
        user_id: "00000000-0000-0000-0000-000000000000".into(),
        email: "test@example.com".into(),
        user_enc_key: user_key.enc_key.to_vec().into(),
        user_mac_key: user_key.mac_key.to_vec().into(),
        kdf: ragewarden_core::sync::KdfParams::pbkdf2(100),
        device_id: "test-device".into(),
    }
}

fn type2(s: &str, session: &Session) -> Type2EncString {
    let enc: [u8; 32] = session.user_enc_key[..].try_into().unwrap();
    let mac: [u8; 32] = session.user_mac_key[..].try_into().unwrap();
    Type2EncString::from_trusted(encrypt_type2(s.as_bytes(), &enc, &mac))
}

#[test]
fn http_client_trait_impl_is_usable_with_core_sync() {
    let client = RecordingClient::new();
    let server = Server::self_hosted("https://bitwarden.example.test");
    let session = make_session();

    let _ = block_on(sync::fetch_vault(&client, &server, &session));

    let calls = client.calls();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].starts_with("GET https://bitwarden.example.test/api/sync"),
        "got: {}",
        calls[0]
    );
}

#[test]
fn build_snapshot_decrypts_metadata_and_flags_rage() {
    let session = make_session();

    let mut rage_cipher: Cipher = {
        let cipher_in = build_rage_cipher(&session, "GitHub", "armored age blob ----")
            .expect("build_rage_cipher");
        Cipher {
            id: Some("rage-1".into()),
            cipher_type: cipher_in.cipher_type,
            name: cipher_in.name,
            notes: cipher_in.notes,
            fields: cipher_in.fields.map(|fs| {
                fs.into_iter()
                    .map(|f| sync::CipherField {
                        name: f.name,
                        value: f.value,
                        field_type: f.field_type,
                        extra: f.extra,
                    })
                    .collect()
            }),
            secure_note: cipher_in.secure_note,
            ..Default::default()
        }
    };

    let plain_cipher = Cipher {
        id: Some("plain-1".into()),
        cipher_type: 1,
        name: type2("Spotify", &session),
        login: Some(CipherLogin {
            username: Some(type2("listener@example.com", &session)),
            password: Some(type2("not-rage-protected", &session)),
            totp: None,
            uris: Some(vec![CipherUri {
                uri: type2("https://spotify.com", &session),
                match_type: None,
                extra: Default::default(),
            }]),
            extra: Default::default(),
        }),
        ..Default::default()
    };

    let folder = Folder {
        id: "folder-work".into(),
        name: type2("Work", &session),
    };

    rage_cipher.folder_id = Some("folder-work".into());

    let vault = Vault {
        ciphers: vec![rage_cipher.clone(), plain_cipher.clone()],
        folders: vec![folder],
        organizations: Vec::new(),
    };

    let snap = build_snapshot(&session, &vault);

    assert_eq!(snap.folders.len(), 1);
    assert_eq!(snap.folders[0].name, "Work");
    assert_eq!(snap.ciphers.len(), 2);

    let by_id: std::collections::HashMap<&str, _> =
        snap.ciphers.iter().map(|c| (c.id.as_str(), c)).collect();

    let github = by_id.get("rage-1").expect("rage cipher present");
    assert_eq!(github.name, "GitHub");
    assert!(github.rage, "rage flag should be set");
    assert_eq!(github.kind, "note");
    assert_eq!(github.folder_id.as_deref(), Some("folder-work"));
    assert!(!github.internal);
    assert!(
        !github.decryptable,
        "an unparseable blob with no inventory must fail closed"
    );
    assert_eq!(github.recipient_count, 0);

    let spotify = by_id.get("plain-1").expect("plain cipher present");
    assert_eq!(spotify.name, "Spotify");
    assert!(!spotify.rage);
    assert_eq!(spotify.kind, "login");
    assert_eq!(spotify.username.as_deref(), Some("listener@example.com"));
    assert_eq!(spotify.site.as_deref(), Some("https://spotify.com"));
    assert_eq!(spotify.raw.id.as_deref(), Some("plain-1"));
    assert!(spotify.decryptable, "session-key items are always openable");
    assert!(!spotify.internal);
    assert_eq!(spotify.recipient_count, 0);
}

fn cipher_from_in(id: &str, cipher_in: sync::CipherIn) -> Cipher {
    Cipher {
        id: Some(id.into()),
        cipher_type: cipher_in.cipher_type,
        name: cipher_in.name,
        notes: cipher_in.notes,
        fields: cipher_in.fields.map(|fs| {
            fs.into_iter()
                .map(|f| sync::CipherField {
                    name: f.name,
                    value: f.value,
                    field_type: f.field_type,
                    extra: f.extra,
                })
                .collect()
        }),
        secure_note: cipher_in.secure_note,
        ..Default::default()
    }
}

#[test]
fn snapshot_flags_decryptability_and_hides_internal_items() {
    let session = make_session();

    let identity = age::x25519::Identity::generate();
    let local_pubkey = identity.to_public().to_string();
    let armored_pubkey = ragewarden_core::ArmoredAgeRecipient::from_trusted(local_pubkey.clone());
    let blob = core_encrypt(
        b"payload",
        &[Recipient::SoftwarePassphrase { armored_pubkey }],
    )
    .expect("encrypt");
    let armored = String::from_utf8(blob.0).expect("utf-8");

    let hardware_only = core_encrypt(
        b"payload",
        &[Recipient::YubiKeyPiv {
            public_key: [9u8; 32],
            serial: 1,
            slot: 0x9a,
            stanza_version: 1,
        }],
    )
    .expect("encrypt");
    let hardware_armored = String::from_utf8(hardware_only.0).expect("utf-8");

    let vault = Vault {
        ciphers: vec![
            cipher_from_in(
                "soft-1",
                build_rage_cipher(&session, "Reachable", &armored).expect("build"),
            ),
            cipher_from_in(
                "hard-1",
                build_rage_cipher(&session, "Elsewhere", &hardware_armored).expect("build"),
            ),
            cipher_from_in(
                "reg-1",
                sync::build_meta_cipher(&session, "__ragedroid_recipients_v1__", "{}")
                    .expect("meta"),
            ),
            cipher_from_in(
                "hist-1",
                sync::build_meta_cipher(&session, "__ragewarden_history_v1__:soft-1", "[]")
                    .expect("meta"),
            ),
        ],
        folders: Vec::new(),
        organizations: Vec::new(),
    };

    let inventory = LocalIdentityInventory {
        software_armored_pubkeys: vec![local_pubkey],
        ..Default::default()
    };
    let snap = build_snapshot_with_identities(&session, &vault, &inventory);
    let by_id: std::collections::HashMap<&str, _> =
        snap.ciphers.iter().map(|c| (c.id.as_str(), c)).collect();

    let soft = by_id.get("soft-1").expect("present");
    assert!(soft.rage && soft.decryptable && !soft.internal);
    assert_eq!(soft.recipient_count, 1);

    let hard = by_id.get("hard-1").expect("present");
    assert!(hard.rage && !hard.decryptable && !hard.internal);
    assert_eq!(hard.recipient_count, 1);

    let registry = by_id.get("reg-1").expect("present");
    assert!(
        registry.internal,
        "registry marker must be flagged internal"
    );
    let history = by_id.get("hist-1").expect("present");
    assert!(history.internal, "history marker must be flagged internal");

    let bare = build_snapshot(&session, &vault);
    for c in bare.ciphers.iter().filter(|c| c.rage) {
        assert!(!c.decryptable, "{} should be undecryptable", c.id);
    }
}

#[test]
fn wire_session_round_trips_through_json() {
    let session = make_session();
    let server = Server::self_hosted("https://vault.example.test");
    let wire = WireSession::from_runtime(&server, &session);

    let json = serde_json::to_string(&wire).expect("serialize");
    let back: WireSession = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(wire, back);

    let (server2, session2) = back.into_runtime().expect("into_runtime");
    assert_eq!(server2.api_url, server.api_url);
    assert_eq!(server2.identity_url, server.identity_url);
    assert_eq!(session2.email, session.email);
    assert_eq!(session2.user_enc_key, session.user_enc_key);
    assert_eq!(session2.user_mac_key, session.user_mac_key);
    assert_eq!(session2.kdf, session.kdf);
}

#[test]
fn snapshot_carries_raw_cipher_for_round_trip_to_decrypt() {
    let session = make_session();

    let plaintext = b"correct-horse-battery-staple";
    let identity = age::x25519::Identity::generate();
    let armored_pubkey =
        ragewarden_core::ArmoredAgeRecipient::from_trusted(identity.to_public().to_string());
    let blob = core_encrypt(
        plaintext,
        &[Recipient::SoftwarePassphrase { armored_pubkey }],
    )
    .expect("encrypt");
    let armored = String::from_utf8(blob.0).expect("utf-8 blob");

    let cipher_in = build_rage_cipher(&session, "secret", &armored).expect("build");
    let cipher = Cipher {
        id: Some("c1".into()),
        cipher_type: cipher_in.cipher_type,
        name: cipher_in.name,
        notes: cipher_in.notes,
        fields: cipher_in.fields.map(|fs| {
            fs.into_iter()
                .map(|f| sync::CipherField {
                    name: f.name,
                    value: f.value,
                    field_type: f.field_type,
                    extra: f.extra,
                })
                .collect()
        }),
        secure_note: cipher_in.secure_note,
        ..Default::default()
    };

    let vault = Vault {
        ciphers: vec![cipher.clone()],
        folders: Vec::new(),
        organizations: Vec::new(),
    };
    let snap = build_snapshot(&session, &vault);
    assert_eq!(snap.ciphers.len(), 1);
    let display = &snap.ciphers[0];
    assert!(display.rage);

    let extracted = sync::extract_rage_blob(&session, &display.raw)
        .expect("extract")
        .expect("present");
    assert_eq!(extracted, armored);
}

#[allow(dead_code)]
fn _encrypt_string_signature_check() {
    let _: fn(&Session, &str) -> Result<Type2EncString, sync::SyncError> = encrypt_string;
}
