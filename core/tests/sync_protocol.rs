use std::sync::Mutex;

use async_trait::async_trait;
use base64::{
    engine::general_purpose::STANDARD as B64, engine::general_purpose::URL_SAFE_NO_PAD as B64URL,
    Engine,
};
use ragewarden_core::bitwarden::{
    derive_master_key, encrypt_type2, make_user_key, master_password_hash, stretch_master_key,
};
use ragewarden_core::sync::{
    self, build_rage_cipher, create_cipher, create_folder, delete_cipher, delete_folder,
    encrypt_string, extract_rage_blob, fetch_vault, login, login_pinned, name_index, register,
    set_folder, set_folder_on, update_cipher, update_folder, Cipher, CipherIn, HttpBody, HttpClient,
    HttpError, HttpResponse, SecureUrl, Server, Session,
};

#[derive(Debug, Clone)]
struct RecordedRequest {
    method: &'static str,
    url: String,
    body: Option<HttpBody>,
    headers: Vec<(String, String)>,
}

struct MockClient {
    routes: Mutex<Vec<(&'static str, String, u16, Vec<u8>)>>,
    log: Mutex<Vec<RecordedRequest>>,
}

impl MockClient {
    fn new(routes: Vec<(&'static str, &str, u16, Vec<u8>)>) -> Self {
        Self {
            routes: Mutex::new(
                routes
                    .into_iter()
                    .map(|(m, u, s, b)| (m, u.to_string(), s, b))
                    .collect(),
            ),
            log: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.log.lock().unwrap().clone()
    }

    fn dispatch(
        &self,
        method: &'static str,
        url: &str,
        body: Option<HttpBody>,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        self.log.lock().unwrap().push(RecordedRequest {
            method,
            url: url.to_string(),
            body: body.clone(),
            headers: headers.to_vec(),
        });
        let routes = self.routes.lock().unwrap();
        for (m, fragment, status, body) in routes.iter() {
            if *m == method && url.contains(fragment.as_str()) {
                return Ok(HttpResponse {
                    status: *status,
                    body: body.clone(),
                });
            }
        }
        Err(HttpError::Transport(format!(
            "no mock route for {method} {url}"
        )))
    }
}

#[async_trait]
impl HttpClient for MockClient {
    async fn post(
        &self,
        url: &str,
        body: HttpBody,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        self.dispatch("POST", url, Some(body), headers)
    }
    async fn put(
        &self,
        url: &str,
        body: HttpBody,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        self.dispatch("PUT", url, Some(body), headers)
    }
    async fn get(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        self.dispatch("GET", url, None, headers)
    }
    async fn delete(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        self.dispatch("DELETE", url, None, headers)
    }
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake};

    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    let waker = Arc::new(Noop).into();
    let mut cx = Context::from_waker(&waker);
    let mut fut = Box::pin(fut);
    loop {
        match Pin::new(&mut fut).as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => continue,
        }
    }
}

const TEST_ITERS: u32 = ragewarden_core::bitwarden::KDF_ITERATIONS_MIN;

const REGISTER_ITERS: u32 = ragewarden_core::bitwarden::KDF_ITERATIONS_MIN_NEW_ACCOUNT;

fn server() -> Server {
    Server::self_hosted("https://bitwarden.example.test")
}

fn fake_token_response(
    email: &str,
    password: &str,
    iters: u32,
    user_key_raw: &[u8; 64],
    user_id: &str,
) -> Vec<u8> {
    let master_key = derive_master_key(password, email, iters);
    let (stretch_enc, stretch_mac) = stretch_master_key(&master_key);
    let protected = encrypt_type2(user_key_raw, &stretch_enc, &stretch_mac);

    let header = B64URL.encode(b"{\"alg\":\"none\"}");
    let payload_json = format!("{{\"sub\":\"{user_id}\",\"email\":\"{email}\"}}");
    let payload = B64URL.encode(payload_json.as_bytes());
    let access_token = format!("{header}.{payload}.sig");
    let json = serde_json::json!({
        "access_token": access_token,
        "refresh_token": "refresh-stub",
        "Key": protected,
        "expires_in": 3600,
    });
    serde_json::to_vec(&json).unwrap()
}

fn make_session(user_enc: [u8; 32], user_mac: [u8; 32]) -> Session {
    Session {
        access_token: ragewarden_core::BearerToken::from_trusted("stub".into()),
        refresh_token: ragewarden_core::RefreshToken::from_trusted("refresh".into()),
        user_id: "00000000-0000-0000-0000-000000000000".into(),
        email: "test@example.com".into(),
        user_enc_key: user_enc.to_vec().into(),
        user_mac_key: user_mac.to_vec().into(),
        kdf_iterations: 100,
        device_id: "test-device".into(),
    }
}

#[test]
fn register_posts_to_identity_accounts_register() {
    let mock = MockClient::new(vec![(
        "POST",
        "/identity/accounts/register",
        200,
        b"".to_vec(),
    )]);
    let out = block_on(register(
        &mock,
        &server(),
        "Test@Example.Com",
        "hunter2",
        "Test User",
        REGISTER_ITERS,
    ))
    .expect("register ok");
    assert_eq!(out.email, "test@example.com");
    assert_eq!(out.kdf_iterations, REGISTER_ITERS);
    assert_eq!(out.user_enc_key.len(), 32);
    assert_eq!(out.user_mac_key.len(), 32);

    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(
        reqs[0].url,
        "https://bitwarden.example.test/identity/accounts/register"
    );

    let body = match &reqs[0].body {
        Some(HttpBody::Json(b)) => b.clone(),
        other => panic!("expected JSON body, got {other:?}"),
    };
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["email"], "test@example.com");
    assert_eq!(v["name"], "Test User");
    assert_eq!(v["kdf"], 0);
    assert_eq!(v["kdfIterations"], REGISTER_ITERS);

    assert_eq!(v["masterPasswordHash"].as_str().unwrap().len(), 44);

    assert!(v["key"].as_str().unwrap().starts_with("2."));

    assert!(!v["keys"]["publicKey"].as_str().unwrap().is_empty());
    assert!(v["keys"]["encryptedPrivateKey"]
        .as_str()
        .unwrap()
        .starts_with("2."));

    assert!(v["referenceData"].is_null());
}

#[test]
fn login_form_encodes_and_decrypts_user_key() {
    let email = "login@example.com";
    let password = "hunter2";
    let iters = TEST_ITERS;

    let mut user_key_raw = [0u8; 64];
    for (i, b) in user_key_raw.iter_mut().enumerate() {
        *b = i as u8;
    }
    let user_id = "11111111-2222-3333-4444-555555555555";
    let token_body = fake_token_response(email, password, iters, &user_key_raw, user_id);

    let prelogin_body = serde_json::to_vec(&serde_json::json!({
        "Kdf": 0,
        "KdfIterations": iters,
    }))
    .unwrap();

    let mock = MockClient::new(vec![
        ("POST", "/identity/accounts/prelogin", 200, prelogin_body),
        ("POST", "/identity/connect/token", 200, token_body),
    ]);

    let session =
        block_on(login(&mock, &server(), email, password, "rageterm-test")).expect("login ok");

    assert_eq!(session.user_id, user_id);
    assert_eq!(session.email, email);
    assert_eq!(session.kdf_iterations, iters);
    assert_eq!(session.user_enc_key.as_slice(), &user_key_raw[..32]);
    assert_eq!(session.user_mac_key.as_slice(), &user_key_raw[32..]);

    let reqs = mock.requests();

    assert_eq!(reqs.len(), 2);
    let token_req = reqs
        .iter()
        .find(|r| r.url.contains("/identity/connect/token"))
        .expect("token request recorded");

    let expected_auth_email = B64URL.encode(email.as_bytes());
    let auth_email_value = token_req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("auth-email"))
        .map(|(_, v)| v.as_str())
        .expect("Auth-Email header present");
    assert_eq!(auth_email_value, expected_auth_email);

    let form = match &token_req.body {
        Some(HttpBody::Form(b)) => std::str::from_utf8(b).unwrap().to_string(),
        other => panic!("expected Form body, got {other:?}"),
    };
    assert!(form.contains("grant_type=password"));
    assert!(form.contains("scope=api+offline_access"));
    assert!(form.contains("client_id=cli"));
    assert!(form.contains("deviceType=8"));

    assert!(form.contains("username=login%40example.com"));
}

#[test]
fn fetch_vault_handles_pascalcase_and_camelcase() {
    let body = serde_json::to_vec(&serde_json::json!({
        "Profile": {
            "Organizations": [{"Id": "org-1", "Name": "2.aaaa|bbbb|cccc"}],
        },
        "Folders": [{"Id": "f-1", "Name": "2.x|y|z"}],
        "Ciphers": [
            {
                "Id": "c-1",
                "Type": 2,
                "Name": "2.name-iv|name-ct|name-mac",
                "Notes": "2.notes-iv|notes-ct|notes-mac",
                "Fields": [
                    {"Name": "2.fn-iv|fn-ct|fn-mac", "Value": "2.fv-iv|fv-ct|fv-mac", "Type": 1}
                ],
                "Favorite": false,
                "Reprompt": 0,
                "SecureNote": {"Type": 0}
            }
        ]
    }))
    .unwrap();

    let mock = MockClient::new(vec![("GET", "/api/sync", 200, body)]);
    let session = make_session([0xAA; 32], [0xBB; 32]);
    let vault = block_on(fetch_vault(&mock, &server(), &session)).expect("vault");

    assert_eq!(vault.organizations.len(), 1);
    assert_eq!(vault.organizations[0].id, "org-1");
    assert_eq!(vault.folders.len(), 1);
    assert_eq!(vault.folders[0].id, "f-1");
    assert_eq!(vault.ciphers.len(), 1);
    assert_eq!(vault.ciphers[0].cipher_type, 2);
    assert_eq!(
        vault.ciphers[0].fields.as_ref().unwrap()[0].field_type,
        1,
        "field type should be HIDDEN (1)"
    );

    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "GET");
    assert!(reqs[0].url.contains("/api/sync"));
    let auth = reqs[0]
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.as_str())
        .expect("Authorization header");
    assert_eq!(auth, "Bearer stub");
}

#[test]
fn create_cipher_posts_to_api_ciphers_with_bearer() {
    let response_body = serde_json::to_vec(&serde_json::json!({
        "Id": "abc-123",
        "Type": 2,
        "Name": "2.iv|ct|mac",
        "Favorite": false,
        "Reprompt": 0,
    }))
    .unwrap();

    let mock = MockClient::new(vec![("POST", "/api/ciphers", 201, response_body)]);
    let session = make_session([0xCC; 32], [0xDD; 32]);

    let cipher = build_rage_cipher(&session, "github", "-----BEGIN AGE...END AGE-----")
        .expect("build cipher");
    let out: Cipher =
        block_on(create_cipher(&mock, &server(), &session, &cipher)).expect("create cipher");
    assert_eq!(out.id.as_deref(), Some("abc-123"));

    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert!(reqs[0].url.ends_with("/api/ciphers"));
    let body = match &reqs[0].body {
        Some(HttpBody::Json(b)) => b.clone(),
        other => panic!("body was {other:?}"),
    };
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["type"], 2);

    assert!(v["name"].as_str().unwrap().starts_with("2."));

    let fields = v["fields"].as_array().unwrap();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0]["type"], 1);

    assert!(fields[0]["name"].as_str().unwrap().starts_with("2."));
    assert!(fields[0]["value"].as_str().unwrap().starts_with("2."));
}

#[test]
fn end_to_end_build_post_fetch_extract_round_trip() {
    let session = make_session([0x11; 32], [0x22; 32]);
    let original_blob = "-----BEGIN AGE ENCRYPTED FILE-----\nsome-armored-payload-here\n-----END AGE ENCRYPTED FILE-----\n";

    let cipher_in = build_rage_cipher(&session, "round-trip", original_blob).expect("build cipher");

    let mut as_cipher: Cipher = serde_json::from_slice(&serde_json::to_vec(&cipher_in).unwrap())
        .expect("cipher_in -> Cipher via JSON should round-trip");
    as_cipher.id = Some("server-uuid".into());

    let sync_body = serde_json::to_vec(&serde_json::json!({
        "Profile": {"Organizations": []},
        "Folders": [],
        "Ciphers": [as_cipher],
    }))
    .unwrap();
    let cipher_create_body = serde_json::to_vec(&as_cipher).unwrap();
    let mock = MockClient::new(vec![
        ("POST", "/api/ciphers", 201, cipher_create_body),
        ("GET", "/api/sync", 200, sync_body),
    ]);

    let _created = block_on(create_cipher(&mock, &server(), &session, &cipher_in)).expect("create");
    let vault = block_on(fetch_vault(&mock, &server(), &session)).expect("vault");
    assert_eq!(vault.ciphers.len(), 1);

    let recovered = vault.ciphers[0].fields.as_ref().unwrap()[0].clone();
    assert_eq!(recovered.field_type, 1, "should be HIDDEN");

    let blob = extract_rage_blob(&session, &vault.ciphers[0])
        .expect("extract")
        .expect("rage:v1 field present");
    assert_eq!(blob, original_blob);

    let names = name_index(&session, &vault);
    assert!(names.contains_key("round-trip"));
}

#[test]
fn extract_rage_blob_none_for_plain_login() {
    let session = make_session([0x33; 32], [0x44; 32]);
    let other_field_name = encrypt_string(&session, "other").unwrap();
    let other_field_value = encrypt_string(&session, "value").unwrap();
    let cipher = Cipher {
        cipher_type: 1,
        name: encrypt_string(&session, "github").unwrap(),
        fields: Some(vec![sync::CipherField {
            name: other_field_name,
            value: Some(other_field_value),
            field_type: 0,
        }]),
        ..Cipher::default()
    };
    assert!(extract_rage_blob(&session, &cipher).unwrap().is_none());
}

#[test]
fn server_error_includes_status_and_body() {
    let mock = MockClient::new(vec![(
        "POST",
        "/identity/accounts/register",
        400,
        br#"{"error":"email already taken"}"#.to_vec(),
    )]);
    let err = block_on(register(
        &mock,
        &server(),
        "test@example.com",
        "pw",
        "Name",
        REGISTER_ITERS,
    ))
    .unwrap_err();
    match err {
        sync::SyncError::Server { status, body } => {
            assert_eq!(status, 400);
            assert!(body.contains("email already taken"));
        }
        other => panic!("expected SyncError::Server, got {other:?}"),
    }
}

#[test]
fn make_user_key_round_trip_under_master_key() {
    let mk = derive_master_key("hunter2", "test@example.com", 100);
    let uk = make_user_key(&mk);
    let (se, sm) = stretch_master_key(&mk);
    let raw = ragewarden_core::bitwarden::decrypt_type2(&uk.protected, &se, &sm)
        .expect("decrypt user key");
    assert_eq!(raw.len(), 64);
    assert_eq!(&raw[..32], uk.enc_key.as_slice());
    assert_eq!(&raw[32..], uk.mac_key.as_slice());

    let h1 = master_password_hash(&mk, "hunter2");
    let h2 = master_password_hash(&mk, "hunter2");
    assert_eq!(h1, h2);

    assert_eq!(h1.len(), 44);

    let decoded = B64.decode(&h1).unwrap();
    assert_eq!(decoded.len(), 32);
}

fn folder_response(id: &str, folder_id: Option<&str>) -> Vec<u8> {
    let folder_value = match folder_id {
        Some(f) => serde_json::Value::String(f.to_string()),
        None => serde_json::Value::Null,
    };
    serde_json::to_vec(&serde_json::json!({
        "Id": id,
        "FolderId": folder_value,
        "Type": 2,
        "Name": "2.iv|ct|mac",
        "Favorite": false,
        "Reprompt": 0,
    }))
    .unwrap()
}

#[test]
fn set_folder_puts_folder_id_to_cipher_folder_endpoint() {
    let mock = MockClient::new(vec![(
        "PUT",
        "/api/ciphers/cipher-1/folder",
        200,
        folder_response("cipher-1", Some("folder-42")),
    )]);
    let session = make_session([0xEE; 32], [0xFF; 32]);

    let updated = block_on(set_folder(
        &mock,
        &server().api_url,
        &session,
        "cipher-1",
        Some("folder-42"),
    ))
    .expect("set_folder ok");
    assert_eq!(updated.id.as_deref(), Some("cipher-1"));
    assert_eq!(updated.folder_id.as_deref(), Some("folder-42"));

    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "PUT");
    assert!(reqs[0].url.ends_with("/api/ciphers/cipher-1/folder"));

    let body = match &reqs[0].body {
        Some(HttpBody::Json(b)) => b.clone(),
        other => panic!("expected JSON body, got {other:?}"),
    };
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["folderId"], serde_json::json!("folder-42"));

    let auth = reqs[0]
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.as_str())
        .expect("Authorization header");
    assert_eq!(auth, "Bearer stub");
}

#[test]
fn set_folder_clears_folder_when_id_is_none() {
    let mock = MockClient::new(vec![(
        "PUT",
        "/api/ciphers/cipher-7/folder",
        200,
        folder_response("cipher-7", None),
    )]);
    let session = make_session([0x01; 32], [0x02; 32]);

    let updated = block_on(set_folder(
        &mock,
        &server().api_url,
        &session,
        "cipher-7",
        None,
    ))
    .expect("set_folder None ok");
    assert!(updated.folder_id.is_none());

    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    let body = match &reqs[0].body {
        Some(HttpBody::Json(b)) => b.clone(),
        other => panic!("expected JSON body, got {other:?}"),
    };
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        v["folderId"].is_null(),
        "None must serialize as null, got {v}"
    );
}

#[test]
fn set_folder_surfaces_http_error_as_server_variant() {
    let mock = MockClient::new(vec![(
        "PUT",
        "/api/ciphers/missing/folder",
        404,
        br#"{"error":"cipher not found"}"#.to_vec(),
    )]);
    let session = make_session([0xAB; 32], [0xCD; 32]);

    let err = block_on(set_folder(
        &mock,
        &server().api_url,
        &session,
        "missing",
        Some("folder-42"),
    ))
    .expect_err("404 must surface as SyncError::Server");

    match err {
        sync::SyncError::Server { status, body } => {
            assert_eq!(status, 404);
            assert!(body.contains("cipher not found"));
        }
        other => panic!("expected SyncError::Server, got {other:?}"),
    }
}

#[test]
fn require_secure_accepts_https_and_loopback() {
    assert!(Server::self_hosted("https://vault.example.test")
        .require_secure()
        .is_ok());

    assert!(Server::self_hosted("http://vault.example.test")
        .require_secure()
        .is_err());

    assert!(Server::self_hosted("http://localhost:8080")
        .require_secure()
        .is_ok());
    assert!(Server::self_hosted("http://127.0.0.1")
        .require_secure()
        .is_ok());

    assert!(Server::self_hosted("http://localhost.evil.example")
        .require_secure()
        .is_err());
}

#[test]
fn require_secure_rejects_hosts_that_merely_look_like_loopback() {
    let hostile = [
        "http://127.evil.example",
        "http://127.0.0.1.evil.example",
        "http://127.0.0.1evil.example",
        "http://localhost.evil.example",
        "http://127.0.0.1@evil.example",
        "http://localhost@evil.example",
        "http://127.0.0.1:8080@evil.example",
        "http://user:127.0.0.1@evil.example",
        "http://evil.example/127.0.0.1",
        "http://evil.example?h=127.0.0.1",
        "http://evil.example#127.0.0.1",
        "HTTP://127.EVIL.EXAMPLE",
        "http://[::1].evil.example",
        "http://127.0.0.1.",
        "ftp://127.0.0.1",
        "//127.0.0.1",
        "127.0.0.1",
        "",
    ];
    for url in hostile {
        let err = Server::self_hosted(url).require_secure();
        assert!(
            err.is_err(),
            "require_secure() accepted a non-loopback plaintext URL: {url}"
        );
    }
}

#[test]
fn require_secure_still_accepts_real_loopback_forms() {
    for url in [
        "http://127.0.0.1",
        "http://127.0.0.1:8080",
        "http://127.1.2.3:8080",
        "http://localhost",
        "http://localhost:8080",
        "http://[::1]",
        "http://[::1]:8080",
        "https://vault.example.test",
        "HTTPS://VAULT.EXAMPLE.TEST",
    ] {
        assert!(
            Server::self_hosted(url).require_secure().is_ok(),
            "require_secure() rejected a legitimate URL: {url}"
        );
    }
}

#[test]
fn register_refuses_to_transmit_over_a_lookalike_loopback_host() {
    let mock = MockClient::new(vec![(
        "POST",
        "/identity/accounts/register",
        200,
        b"".to_vec(),
    )]);
    let evil = Server::self_hosted("http://127.evil.example");
    let err = block_on(register(
        &mock,
        &evil,
        "test@example.com",
        "hunter2",
        "Test User",
        REGISTER_ITERS,
    ))
    .unwrap_err();
    assert!(
        matches!(err, sync::SyncError::Insecure(_)),
        "expected Insecure, got {err:?}"
    );
    assert!(
        mock.requests().is_empty(),
        "the master-password hash was put on the wire anyway: {:?}",
        mock.requests()
    );
}

#[test]
fn login_refuses_to_transmit_over_a_lookalike_loopback_host() {
    let mock = MockClient::new(vec![
        ("POST", "/identity/accounts/prelogin", 200, b"{}".to_vec()),
        ("POST", "/identity/connect/token", 200, b"{}".to_vec()),
    ]);
    let evil = Server::self_hosted("http://127.evil.example");
    let err = block_on(login(&mock, &evil, "a@b.test", "hunter2", "dev")).unwrap_err();
    assert!(
        matches!(err, sync::SyncError::Insecure(_)),
        "expected Insecure, got {err:?}"
    );
    assert!(mock.requests().is_empty(), "prelogin still went out");
}

#[test]
fn vault_operations_refuse_an_insecure_server() {
    let mock = MockClient::new(vec![("GET", "/sync", 200, b"{}".to_vec())]);
    let evil = Server::self_hosted("http://127.evil.example");
    let session = make_session([1u8; 32], [2u8; 32]);
    let err = block_on(fetch_vault(&mock, &evil, &session)).unwrap_err();
    assert!(
        matches!(err, sync::SyncError::Insecure(_)),
        "expected Insecure, got {err:?}"
    );
    assert!(mock.requests().is_empty(), "bearer token still went out");
}

#[test]
fn login_rejects_a_server_supplied_kdf_iteration_count_below_the_floor() {
    let email = "low@example.com";
    let password = "hunter2";
    let mut user_key_raw = [0u8; 64];
    for (i, b) in user_key_raw.iter_mut().enumerate() {
        *b = i as u8;
    }

    for hostile_iters in [0u32, 1, 2, 100, ragewarden_core::bitwarden::KDF_ITERATIONS_MIN - 1] {
        let prelogin_body = serde_json::to_vec(&serde_json::json!({
            "Kdf": 0,
            "KdfIterations": hostile_iters,
        }))
        .unwrap();
        let token_body =
            fake_token_response(email, password, hostile_iters.max(1), &user_key_raw, "u");
        let mock = MockClient::new(vec![
            ("POST", "/identity/accounts/prelogin", 200, prelogin_body),
            ("POST", "/identity/connect/token", 200, token_body),
        ]);

        let err = block_on(login(&mock, &server(), email, password, "dev")).unwrap_err();
        match err {
            sync::SyncError::KdfIterationsTooLow { got, min } => {
                assert_eq!(got, hostile_iters);
                assert_eq!(min, ragewarden_core::bitwarden::KDF_ITERATIONS_MIN);
            }
            other => panic!("expected KdfIterationsTooLow for {hostile_iters}, got {other:?}"),
        }

        let hit_token = mock
            .requests()
            .iter()
            .any(|r| r.url.contains("/connect/token"));
        assert!(
            !hit_token,
            "a {hostile_iters}-iteration master-password hash was sent to the server"
        );
    }
}

#[test]
fn register_rejects_a_kdf_iteration_count_below_the_floor() {
    let mock = MockClient::new(vec![(
        "POST",
        "/identity/accounts/register",
        200,
        b"".to_vec(),
    )]);
    let err = block_on(register(
        &mock,
        &server(),
        "test@example.com",
        "hunter2",
        "Test User",
        1,
    ))
    .unwrap_err();
    assert!(
        matches!(err, sync::SyncError::KdfIterationsTooLow { got: 1, .. }),
        "got {err:?}"
    );
    assert!(mock.requests().is_empty());
}

#[test]
fn login_fails_loudly_on_argon2id_rather_than_silently_misderiving() {
    let email = "argon@example.com";
    let password = "hunter2";
    let mut user_key_raw = [0u8; 64];
    for (i, b) in user_key_raw.iter_mut().enumerate() {
        *b = i as u8;
    }
    let token_body = fake_token_response(email, password, TEST_ITERS, &user_key_raw, "u");
    let prelogin_body = serde_json::to_vec(&serde_json::json!({
        "Kdf": 1,
        "KdfIterations": 3,
        "KdfMemory": 64,
        "KdfParallelism": 4,
    }))
    .unwrap();
    let mock = MockClient::new(vec![
        ("POST", "/identity/accounts/prelogin", 200, prelogin_body),
        ("POST", "/identity/connect/token", 200, token_body),
    ]);

    let err = block_on(login(&mock, &server(), email, password, "dev")).unwrap_err();
    match err {
        sync::SyncError::UnsupportedKdfType { got, supported } => {
            assert_eq!(got, ragewarden_core::bitwarden::KDF_ARGON2ID);
            assert_eq!(supported, ragewarden_core::bitwarden::KDF_PBKDF2);
        }
        other => panic!("expected UnsupportedKdfType, got {other:?}"),
    }
    assert!(
        !mock
            .requests()
            .iter()
            .any(|r| r.url.contains("/connect/token")),
        "a PBKDF2 hash was sent to an Argon2id account"
    );
}

#[test]
fn login_accepts_an_explicit_pbkdf2_kdf_discriminator() {
    let email = "pbkdf2@example.com";
    let password = "hunter2";
    let mut user_key_raw = [0u8; 64];
    for (i, b) in user_key_raw.iter_mut().enumerate() {
        *b = i as u8;
    }
    let token_body = fake_token_response(email, password, TEST_ITERS, &user_key_raw, "u");
    let prelogin_body = serde_json::to_vec(&serde_json::json!({
        "kdf": 0,
        "kdfIterations": TEST_ITERS,
    }))
    .unwrap();
    let mock = MockClient::new(vec![
        ("POST", "/identity/accounts/prelogin", 200, prelogin_body),
        ("POST", "/identity/connect/token", 200, token_body),
    ]);
    let session = block_on(login(&mock, &server(), email, password, "dev")).expect("login ok");
    assert_eq!(session.kdf_iterations, TEST_ITERS);
}

#[test]
fn session_debug_does_not_dump_the_vault_keys() {
    let mut session = make_session([0xab; 32], [0xcd; 32]);
    session.access_token = ragewarden_core::BearerToken::from_trusted("jwt-aaaa".into());
    session.refresh_token = ragewarden_core::RefreshToken::from_trusted("rt-bbbb".into());
    let rendered = format!("{session:?}");
    assert!(
        !rendered.contains("171") && !rendered.contains("205"),
        "vault key bytes leaked into Debug: {rendered}"
    );
    assert!(
        rendered.contains("VaultKey(<redacted>)"),
        "expected redacted vault keys, got: {rendered}"
    );
    assert!(
        !rendered.contains("jwt-aaaa") && !rendered.contains("rt-bbbb"),
        "tokens leaked into Debug: {rendered}"
    );
    assert_eq!(session.user_enc_key.expose(), &[0xab; 32]);
}

#[test]
fn register_output_debug_does_not_dump_the_vault_keys() {
    let mock = MockClient::new(vec![(
        "POST",
        "/identity/accounts/register",
        200,
        b"".to_vec(),
    )]);
    let out = block_on(register(
        &mock,
        &server(),
        "dbg@example.com",
        "hunter2",
        "Name",
        REGISTER_ITERS,
    ))
    .expect("register ok");

    let rendered = format!("{out:?}");
    assert!(
        rendered.matches("VaultKey(<redacted>)").count() == 2,
        "expected both key halves redacted, got: {rendered}"
    );
    let key_bytes: Vec<String> = out
        .user_enc_key
        .expose()
        .iter()
        .map(|b| b.to_string())
        .collect();
    assert!(
        !rendered.contains(&key_bytes.join(", ")),
        "key bytes leaked: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// Transport: the defect this round fixes, plus the whole-surface audit.
// ---------------------------------------------------------------------------

const HOSTILE_URLS: [&str; 12] = [
    "http://127.evil.example",
    "http://127.0.0.1.evil.example",
    "http://127.0.0.1evil.example",
    "http://localhost.evil.example",
    "http://127.0.0.1@evil.example",
    "http://127.0.0.1:8080@evil.example",
    "http://evil.example/127.0.0.1",
    "http://evil.example?h=127.0.0.1",
    "HTTP://127.EVIL.EXAMPLE",
    "http://[::1].evil.example",
    "ftp://127.0.0.1",
    "//127.0.0.1",
];

#[test]
fn set_folder_refuses_to_send_the_bearer_token_over_a_plaintext_url() {
    let session = make_session([0x11; 32], [0x22; 32]);
    for base in HOSTILE_URLS {
        let mock = MockClient::new(vec![(
            "PUT",
            "/ciphers/cipher-1/folder",
            200,
            folder_response("cipher-1", Some("folder-42")),
        )]);
        let api = format!("{base}/api");
        let err = match block_on(set_folder(&mock, &api, &session, "cipher-1", Some("folder-42"))) {
            Ok(c) => panic!("set_folder accepted plaintext base {base}, returned {c:?}"),
            Err(e) => e,
        };
        assert!(
            matches!(err, sync::SyncError::Insecure(_)),
            "expected Insecure for {base}, got {err:?}"
        );
        assert!(
            mock.requests().is_empty(),
            "set_folder put the bearer token on the wire for {base}: {:?}",
            mock.requests()
        );
    }
}

#[test]
fn set_folder_still_works_over_https_and_loopback_http() {
    let session = make_session([0x11; 32], [0x22; 32]);
    for base in [
        "https://vault.example.test/api",
        "http://localhost:8080/api",
        "http://127.0.0.1:8080/api",
        "http://[::1]:8080/api",
    ] {
        let mock = MockClient::new(vec![(
            "PUT",
            "/ciphers/c/folder",
            200,
            folder_response("c", Some("f")),
        )]);
        block_on(set_folder(&mock, base, &session, "c", Some("f")))
            .unwrap_or_else(|e| panic!("set_folder rejected legitimate base {base}: {e:?}"));
        assert_eq!(mock.requests().len(), 1);
    }
}

#[test]
fn set_folder_on_validates_the_whole_server_not_just_the_api_url() {
    let session = make_session([0x11; 32], [0x22; 32]);
    let mock = MockClient::new(vec![(
        "PUT",
        "/ciphers/c/folder",
        200,
        folder_response("c", None),
    )]);
    // api side is https, identity side is not: the full-Server entry point
    // must still refuse, exactly like every other &Server function.
    let half = Server::new("https://vault.example.test/api", "http://evil.example/identity");
    let err = block_on(set_folder_on(&mock, &half, &session, "c", None))
        .expect_err("half-plaintext server must be refused");
    assert!(
        matches!(err, sync::SyncError::Insecure(_)),
        "expected Insecure, got {err:?}"
    );
    assert!(mock.requests().is_empty());
}

/// Every `&Server` entry point in `sync.rs` that talks to the network, checked
/// in one place so a newly added one is obvious by its absence.
#[test]
fn every_network_entry_point_refuses_an_insecure_server() {
    let session = make_session([1u8; 32], [2u8; 32]);
    let cipher_in: CipherIn = build_rage_cipher(&session, "n", "blob").unwrap();
    let evil = Server::self_hosted("http://127.evil.example");

    fn routes() -> MockClient {
        MockClient::new(vec![
            ("POST", "/", 200, b"{}".to_vec()),
            ("PUT", "/", 200, b"{}".to_vec()),
            ("GET", "/", 200, b"{}".to_vec()),
            ("DELETE", "/", 200, b"{}".to_vec()),
        ])
    }

    macro_rules! refuses {
        ($label:expr, $mock:ident, $fut:expr) => {{
            let $mock = routes();
            let err = block_on($fut).expect_err(concat!($label, " must refuse"));
            assert!(
                matches!(err, sync::SyncError::Insecure(_)),
                "{} returned {:?} instead of Insecure",
                $label,
                err
            );
            assert!(
                $mock.requests().is_empty(),
                "{} still hit the network: {:?}",
                $label,
                $mock.requests()
            );
        }};
    }

    refuses!(
        "register",
        mock,
        register(&mock, &evil, "a@b.test", "pw", "n", REGISTER_ITERS)
    );
    refuses!("login", mock, login(&mock, &evil, "a@b.test", "pw", "dev"));
    refuses!(
        "login_pinned",
        mock,
        login_pinned(&mock, &evil, "a@b.test", "pw", "dev", "test-device", Some(600_000))
    );
    refuses!("fetch_vault", mock, fetch_vault(&mock, &evil, &session));
    refuses!(
        "create_cipher",
        mock,
        create_cipher(&mock, &evil, &session, &cipher_in)
    );
    refuses!(
        "update_cipher",
        mock,
        update_cipher(&mock, &evil, &session, "c-1", &cipher_in)
    );
    refuses!(
        "delete_cipher",
        mock,
        delete_cipher(&mock, &evil, &session, "c-1")
    );
    refuses!(
        "create_folder",
        mock,
        create_folder(&mock, &evil, &session, "f")
    );
    refuses!(
        "update_folder",
        mock,
        update_folder(&mock, &evil, &session, "f-1", "f")
    );
    refuses!(
        "delete_folder",
        mock,
        delete_folder(&mock, &evil, &session, "f-1")
    );
    refuses!(
        "set_folder_on",
        mock,
        set_folder_on(&mock, &evil, &session, "c-1", None)
    );
}

/// Structural guard for the chokepoint. `sync.rs` reaches the network in
/// exactly one function, which only accepts an already-validated
/// [`SecureUrl`]; if a future endpoint calls the `HttpClient` trait directly
/// it bypasses the check, and this fails.
#[test]
fn every_http_call_in_sync_rs_goes_through_the_chokepoint() {
    let src = include_str!("../src/sync.rs");
    let flat: String = src.chars().filter(|c| !c.is_whitespace()).collect();
    for method in [
        "client.get(",
        "client.post(",
        "client.put(",
        "client.delete(",
    ] {
        let n = flat.matches(method).count();
        assert_eq!(
            n, 1,
            "`{method}` appears {n} times in sync.rs; it must appear exactly once, \
             inside the `send()` chokepoint that takes a validated SecureUrl"
        );
    }
}

#[test]
fn secure_url_parse_agrees_with_require_secure() {
    for url in HOSTILE_URLS {
        assert!(
            SecureUrl::parse(url).is_err(),
            "SecureUrl::parse accepted {url}"
        );
    }
    for url in [
        "https://vault.example.test",
        "HTTPS://VAULT.EXAMPLE.TEST",
        "http://127.0.0.1",
        "http://127.0.0.1:8080",
        "http://localhost",
        "http://[::1]:8080",
    ] {
        assert!(SecureUrl::parse(url).is_ok(), "SecureUrl::parse rejected {url}");
    }
}

#[test]
fn try_constructors_reject_a_plaintext_base_at_configuration_time() {
    assert!(Server::try_self_hosted("http://vault.example.test").is_err());
    assert!(Server::try_self_hosted("https://vault.example.test").is_ok());
    assert!(Server::try_new("https://a.test/api", "http://evil.test/identity").is_err());
    assert!(Server::try_new("https://a.test/api", "https://a.test/identity").is_ok());
}

// ---------------------------------------------------------------------------
// KDF
// ---------------------------------------------------------------------------

#[test]
fn register_rejects_a_count_that_clears_the_login_floor_but_not_the_new_account_floor() {
    let mock = MockClient::new(vec![(
        "POST",
        "/identity/accounts/register",
        200,
        b"".to_vec(),
    )]);
    let below = ragewarden_core::bitwarden::KDF_ITERATIONS_MIN;
    assert!(
        below < REGISTER_ITERS,
        "the new-account floor must be stricter than the login floor"
    );
    let err = block_on(register(
        &mock,
        &server(),
        "test@example.com",
        "hunter2",
        "Test User",
        below,
    ))
    .unwrap_err();
    match err {
        sync::SyncError::KdfIterationsTooLow { got, min } => {
            assert_eq!(got, below);
            assert_eq!(min, REGISTER_ITERS);
        }
        other => panic!("expected KdfIterationsTooLow, got {other:?}"),
    }
    assert!(mock.requests().is_empty());
}

#[test]
fn login_rejects_a_downgrade_that_stays_above_the_floor() {
    let email = "pinned@example.com";
    let password = "hunter2";
    let mut user_key_raw = [0u8; 64];
    for (i, b) in user_key_raw.iter_mut().enumerate() {
        *b = i as u8;
    }

    // Above the hard floor, so only the pin can catch it.
    let offered = ragewarden_core::bitwarden::KDF_ITERATIONS_MIN;
    let pinned = ragewarden_core::bitwarden::KDF_ITERATIONS_DEFAULT;
    assert!(offered >= ragewarden_core::bitwarden::KDF_ITERATIONS_MIN);

    let prelogin_body = serde_json::to_vec(&serde_json::json!({
        "Kdf": 0,
        "KdfIterations": offered,
    }))
    .unwrap();
    let token_body = fake_token_response(email, password, offered, &user_key_raw, "u");
    let mock = MockClient::new(vec![
        ("POST", "/identity/accounts/prelogin", 200, prelogin_body),
        ("POST", "/identity/connect/token", 200, token_body),
    ]);

    let err = block_on(login_pinned(
        &mock,
        &server(),
        email,
        password,
        "dev",
        "test-device",
        Some(pinned),
    ))
    .expect_err("a 600k -> 100k downgrade must be refused");
    match err {
        sync::SyncError::KdfIterationsDowngraded { got, pinned: p } => {
            assert_eq!(got, offered);
            assert_eq!(p, pinned);
        }
        other => panic!("expected KdfIterationsDowngraded, got {other:?}"),
    }
    assert!(
        !mock
            .requests()
            .iter()
            .any(|r| r.url.contains("/connect/token")),
        "a downgraded master-password hash was sent to the server"
    );

    // Plain `login` has no pin and therefore cannot see this.
    assert!(
        sync::check_kdf_iterations(offered).is_ok(),
        "the floor alone does not catch this downgrade, which is the point of the pin"
    );
}

#[test]
fn login_accepts_an_unchanged_or_raised_count_against_the_pin() {
    let email = "raise@example.com";
    let password = "hunter2";
    let mut user_key_raw = [0u8; 64];
    for (i, b) in user_key_raw.iter_mut().enumerate() {
        *b = i as u8;
    }
    for (pinned, offered) in [(TEST_ITERS, TEST_ITERS), (TEST_ITERS, TEST_ITERS * 2)] {
        let prelogin_body = serde_json::to_vec(&serde_json::json!({
            "Kdf": 0,
            "KdfIterations": offered,
        }))
        .unwrap();
        let token_body = fake_token_response(email, password, offered, &user_key_raw, "u");
        let mock = MockClient::new(vec![
            ("POST", "/identity/accounts/prelogin", 200, prelogin_body),
            ("POST", "/identity/connect/token", 200, token_body),
        ]);
        let session = block_on(login_pinned(
            &mock,
            &server(),
            email,
            password,
            "dev",
            "test-device",
            Some(pinned),
        ))
        .unwrap_or_else(|e| panic!("pin {pinned} vs offered {offered} should pass: {e:?}"));
        assert_eq!(session.kdf_iterations, offered);
    }
}

#[test]
fn check_kdf_not_downgraded_is_trust_on_first_use_when_unpinned() {
    assert!(sync::check_kdf_not_downgraded(1, None).is_ok());
    assert!(sync::check_kdf_not_downgraded(600_000, Some(600_000)).is_ok());
    assert!(sync::check_kdf_not_downgraded(600_001, Some(600_000)).is_ok());
    assert!(sync::check_kdf_not_downgraded(599_999, Some(600_000)).is_err());
}

#[test]
fn the_login_floor_rejects_the_2013_era_default() {
    // The value the 2023 disclosure found still live on real accounts.
    assert!(
        sync::check_kdf_iterations(5_000).is_err(),
        "5000 PBKDF2 iterations must not be accepted"
    );
    assert!(sync::check_kdf_iterations(99_999).is_err());
    assert!(sync::check_kdf_iterations(100_000).is_ok());
}
