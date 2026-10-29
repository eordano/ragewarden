use std::sync::Mutex;

use async_trait::async_trait;
use base64::{
    Engine, engine::general_purpose::STANDARD as B64,
    engine::general_purpose::URL_SAFE_NO_PAD as B64URL,
};
use ragewarden_core::bitwarden::{
    derive_master_key, encrypt_type2, make_user_key, master_password_hash, stretch_master_key,
};
use ragewarden_core::sync::{
    self, Cipher, CipherIn, HttpBody, HttpClient, HttpError, HttpResponse, SecureUrl, Server,
    Session, build_rage_cipher, create_cipher, create_folder, delete_cipher, delete_folder,
    encrypt_string, extract_rage_blob, fetch_vault, login, login_with_options, name_index,
    register, set_folder, set_folder_on, update_cipher, update_folder,
};

#[derive(Debug, Clone)]
struct RecordedRequest {
    method: &'static str,
    url: String,
    body: Option<HttpBody>,
    headers: Vec<(String, String)>,
}

type Route = (&'static str, String, u16, Vec<u8>);

struct MockClient {
    routes: Mutex<Vec<Route>>,
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
    use std::task::{Context, Poll, Waker};

    let mut cx = Context::from_waker(Waker::noop());
    let mut fut = Box::pin(fut);
    match Pin::new(&mut fut).as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!(
            "block_on drives only futures that never wait: the mock HttpClient answers synchronously"
        ),
    }
}

#[test]
#[should_panic(expected = "never wait")]
fn block_on_refuses_a_future_that_would_wait_instead_of_spinning() {
    block_on(std::future::pending::<()>());
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
    fake_token_response_kdf(
        email,
        password,
        &sync::KdfParams::pbkdf2(iters),
        user_key_raw,
        user_id,
    )
}

fn fake_token_response_kdf(
    email: &str,
    password: &str,
    kdf: &sync::KdfParams,
    user_key_raw: &[u8; 64],
    user_id: &str,
) -> Vec<u8> {
    let master_key = kdf.derive_master_key(password, email).unwrap();
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
        kdf: ragewarden_core::sync::KdfParams::pbkdf2(100),
        device_id: "test-device".into(),
    }
}

/// The two-step registration a current Bitwarden or Vaultwarden (1.37+)
/// server expects: the first call returns the token the second one carries.
fn register_mock() -> MockClient {
    MockClient::new(vec![
        (
            "POST",
            "/identity/accounts/register/send-verification-email",
            200,
            br#""verify-token""#.to_vec(),
        ),
        (
            "POST",
            "/identity/accounts/register/finish",
            200,
            b"".to_vec(),
        ),
    ])
}

fn json_body(req: &RecordedRequest) -> serde_json::Value {
    match &req.body {
        Some(HttpBody::Json(b)) => serde_json::from_slice(b).unwrap(),
        other => panic!("expected JSON body, got {other:?}"),
    }
}

#[test]
fn register_asks_for_a_verification_token_then_finishes_with_it() {
    let mock = register_mock();
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
    assert_eq!(out.kdf.iterations, REGISTER_ITERS);
    assert_eq!(out.user_enc_key.len(), 32);
    assert_eq!(out.user_mac_key.len(), 32);

    let reqs = mock.requests();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(
        reqs[0].url,
        "https://bitwarden.example.test/identity/accounts/register/send-verification-email"
    );
    assert!(
        reqs[0]
            .headers
            .contains(&("Accept".to_string(), "application/json".to_string()))
    );
    let verify = json_body(&reqs[0]);
    assert_eq!(verify["email"], "test@example.com");
    assert_eq!(verify["name"], "Test User");

    assert_eq!(reqs[1].method, "POST");
    assert_eq!(
        reqs[1].url,
        "https://bitwarden.example.test/identity/accounts/register/finish"
    );
    let v = json_body(&reqs[1]);
    assert_eq!(v["emailVerificationToken"], "verify-token");
    assert_eq!(v["email"], "test@example.com");
    assert_eq!(v["name"], "Test User");
    assert_eq!(v["kdf"], 0);
    assert_eq!(v["kdfIterations"], REGISTER_ITERS);

    assert_eq!(v["masterPasswordHash"].as_str().unwrap().len(), 44);

    assert!(v["key"].as_str().unwrap().starts_with("2."));

    assert!(!v["keys"]["publicKey"].as_str().unwrap().is_empty());
    assert!(
        v["keys"]["encryptedPrivateKey"]
            .as_str()
            .unwrap()
            .starts_with("2.")
    );

    assert!(v["referenceData"].is_null());
}

#[test]
fn register_falls_back_to_the_single_step_endpoint_on_an_older_server() {
    let mock = MockClient::new(vec![
        (
            "POST",
            "/identity/accounts/register/send-verification-email",
            404,
            b"<!DOCTYPE html>".to_vec(),
        ),
        ("POST", "/identity/accounts/register", 200, b"".to_vec()),
    ]);
    block_on(register(
        &mock,
        &server(),
        "old@example.com",
        "hunter2",
        "Old Server",
        REGISTER_ITERS,
    ))
    .expect("register ok");

    let reqs = mock.requests();
    assert_eq!(reqs.len(), 2);
    assert_eq!(
        reqs[1].url,
        "https://bitwarden.example.test/identity/accounts/register"
    );
    let v = json_body(&reqs[1]);
    assert!(v.get("emailVerificationToken").is_none(), "{v}");
    assert_eq!(v["name"], "Old Server");
}

#[test]
fn register_explains_a_server_that_emails_the_verification_link() {
    let mock = MockClient::new(vec![(
        "POST",
        "/identity/accounts/register/send-verification-email",
        204,
        b"".to_vec(),
    )]);
    let err = block_on(register(
        &mock,
        &server(),
        "mail@example.com",
        "hunter2",
        "Mail",
        REGISTER_ITERS,
    ))
    .unwrap_err();
    assert!(
        matches!(&err, sync::SyncError::State(m) if m.contains("verification link")),
        "{err:?}"
    );
    assert_eq!(mock.requests().len(), 1, "must not post the keys anywhere");
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
    assert_eq!(session.kdf.iterations, iters);
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
    let session = make_session([0xAA; 32], [0xBB; 32]);
    let folder_name = encrypt_string(&session, "Work").unwrap();
    let body = serde_json::to_vec(&serde_json::json!({
        "Profile": {
            "Organizations": [{"Id": "org-1", "Name": "2.aaaa|bbbb|cccc"}],
        },
        "Folders": [{"Id": "f-1", "Name": folder_name}],
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
    assert_eq!(v["encryptedFor"], session.user_id.as_str());

    assert!(v["name"].as_str().unwrap().starts_with("2."));

    let fields = v["fields"].as_array().unwrap();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0]["type"], 1);

    assert!(fields[0]["name"].as_str().unwrap().starts_with("2."));
    assert!(fields[0]["value"].as_str().unwrap().starts_with("2."));
}

#[test]
fn update_cipher_names_the_user_it_is_encrypted_for() {
    let response_body = serde_json::to_vec(&serde_json::json!({
        "Id": "c-1",
        "Type": 2,
        "Name": "2.iv|ct|mac",
        "Favorite": false,
        "Reprompt": 0,
    }))
    .unwrap();
    let mock = MockClient::new(vec![("PUT", "/api/ciphers/c-1", 200, response_body)]);
    let session = make_session([0xCC; 32], [0xDD; 32]);
    let cipher = build_rage_cipher(&session, "github", "-----BEGIN AGE...END AGE-----")
        .expect("build cipher");
    block_on(update_cipher(&mock, &server(), &session, "c-1", &cipher)).expect("update cipher");

    let v = json_body(&mock.requests()[0]);
    assert_eq!(v["encryptedFor"], session.user_id.as_str());
    assert_eq!(v["type"], 2);
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
            extra: Default::default(),
        }]),
        ..Cipher::default()
    };
    assert!(extract_rage_blob(&session, &cipher).unwrap().is_none());
}

fn sync_body(ciphers: serde_json::Value, folders: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "ciphers": ciphers, "folders": folders })).unwrap()
}

#[test]
fn a_vault_under_another_key_is_an_error_not_an_empty_vault() {
    let owner = make_session([0x10; 32], [0x11; 32]);
    let stranger = make_session([0x20; 32], [0x21; 32]);
    let body = sync_body(
        serde_json::json!([
            {"id": "c-1", "type": 2, "name": encrypt_string(&owner, "a").unwrap()},
            {"id": "c-2", "type": 2, "name": encrypt_string(&owner, "b").unwrap()}
        ]),
        serde_json::json!([{"id": "f-1", "name": encrypt_string(&owner, "Work").unwrap()}]),
    );
    let mock = MockClient::new(vec![("GET", "/api/sync", 200, body)]);
    match block_on(fetch_vault(&mock, &server(), &stranger)) {
        Err(sync::SyncError::WrongUserKey { items }) => assert_eq!(items, 3),
        other => panic!("expected WrongUserKey, got {other:?}"),
    }
    let vault = block_on(fetch_vault(&mock, &server(), &owner)).expect("owner's key works");
    assert_eq!(name_index(&owner, &vault).len(), 2);
}

#[test]
fn organization_ciphers_and_an_empty_vault_are_not_key_evidence() {
    let session = make_session([0x10; 32], [0x11; 32]);
    let org_only = sync_body(
        serde_json::json!([{"id": "c-1", "type": 2, "organizationId": "o-1", "name": "2.aaaa|bbbb|cccc"}]),
        serde_json::json!([]),
    );
    let mock = MockClient::new(vec![("GET", "/api/sync", 200, org_only)]);
    block_on(fetch_vault(&mock, &server(), &session)).expect("org-only vault");

    let empty = sync_body(serde_json::json!([]), serde_json::json!([]));
    let mock = MockClient::new(vec![("GET", "/api/sync", 200, empty)]);
    block_on(fetch_vault(&mock, &server(), &session)).expect("empty vault");

    let one_good = sync_body(
        serde_json::json!([
            {"id": "c-1", "type": 2, "name": "2.aaaa|bbbb|cccc"},
            {"id": "c-2", "type": 2, "name": encrypt_string(&session, "ok").unwrap()}
        ]),
        serde_json::json!([]),
    );
    let mock = MockClient::new(vec![("GET", "/api/sync", 200, one_good)]);
    block_on(fetch_vault(&mock, &server(), &session)).expect("one corrupt item is not a wrong key");
}

#[test]
fn a_rage_field_name_that_does_not_decrypt_is_an_error() {
    let owner = make_session([0x10; 32], [0x11; 32]);
    let other = make_session([0x20; 32], [0x21; 32]);
    let cipher = Cipher {
        cipher_type: 2,
        name: encrypt_string(&owner, "n").unwrap(),
        fields: Some(vec![sync::CipherField {
            name: encrypt_string(&other, "rage:v1").unwrap(),
            value: Some(encrypt_string(&other, "blob").unwrap()),
            field_type: 1,
            extra: Default::default(),
        }]),
        ..Cipher::default()
    };
    assert!(extract_rage_blob(&owner, &cipher).is_err());
}

#[test]
fn refresh_presents_the_sessions_device_and_keeps_the_rotated_refresh_token() {
    let mut session = make_session([1; 32], [2; 32]);
    let mock = MockClient::new(vec![(
        "POST",
        "/identity/connect/token",
        200,
        br#"{"access_token":"fresh","refresh_token":"rotated"}"#.to_vec(),
    )]);
    block_on(sync::refresh_session(&mock, &server(), &mut session)).expect("refresh");
    assert_eq!(session.access_token.expose(), "fresh");
    assert_eq!(session.refresh_token.expose(), "rotated");

    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1);
    let Some(HttpBody::Form(form)) = &reqs[0].body else {
        panic!("form body")
    };
    let form: std::collections::HashMap<String, String> =
        serde_urlencoded::from_bytes(form).unwrap();
    assert_eq!(form["grant_type"], "refresh_token");
    assert_eq!(form["refresh_token"], "refresh");
    assert_eq!(form["client_id"], "cli");
    assert_eq!(form["deviceIdentifier"], "test-device");
    assert!(
        !reqs[0].headers.iter().any(|(k, _)| k == "Authorization"),
        "the expired bearer is not sent"
    );

    let mock = MockClient::new(vec![(
        "POST",
        "/identity/connect/token",
        200,
        br#"{"access_token":"fresher"}"#.to_vec(),
    )]);
    block_on(sync::refresh_session(&mock, &server(), &mut session)).expect("refresh");
    assert_eq!(session.access_token.expose(), "fresher");
    assert_eq!(
        session.refresh_token.expose(),
        "rotated",
        "a response without one keeps the old refresh token"
    );
}

#[test]
fn an_expired_token_is_recognisable_and_a_retry_after_refresh_succeeds() {
    let mut session = make_session([1; 32], [2; 32]);
    let empty = sync_body(serde_json::json!([]), serde_json::json!([]));
    let expired = MockClient::new(vec![("GET", "/api/sync", 401, b"{}".to_vec())]);
    let err = block_on(fetch_vault(&expired, &server(), &session)).unwrap_err();
    assert!(sync::is_unauthorized(&err), "{err:?}");
    assert!(!sync::is_unauthorized(&sync::SyncError::Server {
        status: 500,
        body: String::new()
    }));

    let mock = MockClient::new(vec![
        (
            "POST",
            "/identity/connect/token",
            200,
            br#"{"access_token":"fresh"}"#.to_vec(),
        ),
        ("GET", "/api/sync", 200, empty),
    ]);
    block_on(sync::refresh_session(&mock, &server(), &mut session)).unwrap();
    block_on(fetch_vault(&mock, &server(), &session)).expect("retry with the fresh token");
    let get = mock
        .requests()
        .into_iter()
        .find(|r| r.method == "GET")
        .unwrap();
    assert!(
        get.headers
            .contains(&("Authorization".to_string(), "Bearer fresh".to_string()))
    );
}

#[test]
fn a_long_error_body_cut_inside_a_multibyte_character_does_not_panic() {
    let mut body = vec![b'x'; 4095];
    body.extend("\u{e9}".repeat(10).as_bytes());
    let mock = MockClient::new(vec![("GET", "/api/sync", 500, body)]);
    let err = block_on(fetch_vault(
        &mock,
        &server(),
        &make_session([1; 32], [2; 32]),
    ))
    .expect_err("500 must fail");
    match err {
        sync::SyncError::Server { status, body } => {
            assert_eq!(status, 500);
            assert!(body.ends_with("... <truncated>"), "{body}");
            assert!(body.starts_with("xxxx"));
        }
        other => panic!("expected Server error, got {other:?}"),
    }
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

fn folder_routes(
    id: &str,
    before: Option<&str>,
    after: Option<&str>,
) -> Vec<(&'static str, String, u16, Vec<u8>)> {
    vec![
        (
            "PUT",
            format!("/ciphers/{id}/partial"),
            200,
            folder_response(id, after),
        ),
        (
            "GET",
            format!("/ciphers/{id}"),
            200,
            folder_response(id, before),
        ),
    ]
}

fn mock_from(routes: Vec<(&'static str, String, u16, Vec<u8>)>) -> MockClient {
    MockClient {
        routes: Mutex::new(routes),
        log: Mutex::new(Vec::new()),
    }
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
        "Favorite": true,
        "Reprompt": 0,
    }))
    .unwrap()
}

#[test]
fn set_folder_puts_folder_id_and_the_current_favourite_to_the_partial_endpoint() {
    let mock = mock_from(folder_routes("cipher-1", None, Some("folder-42")));
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
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].method, "GET");
    assert!(reqs[0].url.ends_with("/api/ciphers/cipher-1"));
    assert_eq!(reqs[1].method, "PUT");
    assert!(reqs[1].url.ends_with("/api/ciphers/cipher-1/partial"));

    let body = match &reqs[1].body {
        Some(HttpBody::Json(b)) => b.clone(),
        other => panic!("expected JSON body, got {other:?}"),
    };
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["folderId"], serde_json::json!("folder-42"));
    assert_eq!(v["favorite"], serde_json::json!(true), "favourite is kept");

    let auth = reqs[1]
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.as_str())
        .expect("Authorization header");
    assert_eq!(auth, "Bearer stub");
}

#[test]
fn set_folder_clears_folder_when_id_is_none() {
    let mock = mock_from(folder_routes("cipher-7", Some("folder-1"), None));
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
    assert_eq!(reqs.len(), 2);
    let body = match &reqs[1].body {
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
        "GET",
        "/api/ciphers/missing",
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
    assert!(
        Server::self_hosted("https://vault.example.test")
            .require_secure()
            .is_ok()
    );

    assert!(
        Server::self_hosted("http://vault.example.test")
            .require_secure()
            .is_err()
    );

    assert!(
        Server::self_hosted("http://localhost:8080")
            .require_secure()
            .is_ok()
    );
    assert!(
        Server::self_hosted("http://127.0.0.1")
            .require_secure()
            .is_ok()
    );

    assert!(
        Server::self_hosted("http://localhost.evil.example")
            .require_secure()
            .is_err()
    );
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

    for hostile_iters in [
        0u32,
        1,
        2,
        100,
        ragewarden_core::bitwarden::KDF_ITERATIONS_MIN - 1,
    ] {
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
                assert_eq!(min, ragewarden_core::kdf::KDF_ITERATIONS_LEGACY_MIN);
            }
            sync::SyncError::LegacyKdfNeedsConsent { got, min } => {
                assert_eq!(got, hostile_iters);
                assert!(got >= ragewarden_core::kdf::KDF_ITERATIONS_LEGACY_MIN);
                assert_eq!(min, ragewarden_core::bitwarden::KDF_ITERATIONS_MIN);
            }
            other => panic!("expected a KDF floor refusal for {hostile_iters}, got {other:?}"),
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
fn login_derives_an_argon2id_master_key() {
    let email = "argon@example.com";
    let password = "hunter2";
    let mut user_key_raw = [0u8; 64];
    for (i, b) in user_key_raw.iter_mut().enumerate() {
        *b = i as u8;
    }
    let kdf = sync::KdfParams::argon2id(3, 16, 2);
    let token_body = fake_token_response_kdf(email, password, &kdf, &user_key_raw, "u");
    let prelogin_body = serde_json::to_vec(&serde_json::json!({
        "kdf": 1,
        "kdfIterations": 3,
        "kdfMemory": 16,
        "kdfParallelism": 2,
    }))
    .unwrap();
    let mock = MockClient::new(vec![
        ("POST", "/identity/accounts/prelogin", 200, prelogin_body),
        ("POST", "/identity/connect/token", 200, token_body),
    ]);

    let session =
        block_on(login(&mock, &server(), email, password, "dev")).expect("argon2id login");
    assert_eq!(session.kdf, kdf);
    assert_eq!(session.user_enc_key.as_slice(), &user_key_raw[..32]);

    let expected_hash =
        master_password_hash(&kdf.derive_master_key(password, email).unwrap(), password);
    let token = mock
        .requests()
        .into_iter()
        .find(|r| r.url.contains("/connect/token"))
        .unwrap();
    let Some(HttpBody::Form(form)) = token.body else {
        panic!("token body")
    };
    let form: std::collections::HashMap<String, String> =
        serde_urlencoded::from_bytes(&form).unwrap();
    assert_eq!(form["password"], expected_hash);
}

#[test]
fn argon2id_parameters_out_of_range_are_refused_before_the_token_request() {
    for (memory, parallelism, iterations) in [
        (Some(2048), Some(4), 3),
        (None, Some(4), 3),
        (Some(64), Some(4), 1),
        (Some(64), Some(64), 3),
    ] {
        let prelogin_body = serde_json::to_vec(&serde_json::json!({
            "kdf": 1,
            "kdfIterations": iterations,
            "kdfMemory": memory,
            "kdfParallelism": parallelism,
        }))
        .unwrap();
        let mock = MockClient::new(vec![(
            "POST",
            "/identity/accounts/prelogin",
            200,
            prelogin_body,
        )]);
        let err = block_on(login(&mock, &server(), "a@example.com", "pw", "dev")).unwrap_err();
        assert!(
            matches!(
                err,
                sync::SyncError::KdfOutOfRange { .. } | sync::SyncError::Kdf(_)
            ),
            "{memory:?}/{parallelism:?}/{iterations}: {err:?}"
        );
        assert!(
            !mock
                .requests()
                .iter()
                .any(|r| r.url.contains("/connect/token"))
        );
    }
}

#[test]
fn an_unknown_kdf_type_is_refused() {
    let prelogin_body =
        serde_json::to_vec(&serde_json::json!({ "kdf": 7, "kdfIterations": 3 })).unwrap();
    let mock = MockClient::new(vec![(
        "POST",
        "/identity/accounts/prelogin",
        200,
        prelogin_body,
    )]);
    let err = block_on(login(&mock, &server(), "a@example.com", "pw", "dev")).unwrap_err();
    assert!(
        matches!(err, sync::SyncError::UnsupportedKdfType { got: 7 }),
        "{err:?}"
    );
}

#[test]
fn a_legacy_account_logs_in_once_the_user_consents() {
    let email = "legacy@example.com";
    let password = "hunter2";
    let user_key_raw = [7u8; 64];
    let prelogin_body =
        serde_json::to_vec(&serde_json::json!({ "Kdf": 0, "KdfIterations": 5_000 })).unwrap();
    let token_body = fake_token_response(email, password, 5_000, &user_key_raw, "u");
    let mock = MockClient::new(vec![
        ("POST", "/identity/accounts/prelogin", 200, prelogin_body),
        ("POST", "/identity/connect/token", 200, token_body),
    ]);
    let err = block_on(login(&mock, &server(), email, password, "dev")).unwrap_err();
    assert!(
        matches!(
            err,
            sync::SyncError::LegacyKdfNeedsConsent { got: 5_000, .. }
        ),
        "{err:?}"
    );

    let session = block_on(login_with_options(
        &mock,
        &server(),
        email,
        password,
        "dev",
        &sync::LoginOptions {
            allow_legacy_kdf: true,
            ..Default::default()
        },
    ))
    .expect("consented legacy login");
    assert_eq!(session.kdf, sync::KdfParams::pbkdf2(5_000));
    assert!(session.kdf.below_recommended());
}

#[test]
fn register_with_argon2id_sends_its_memory_and_parallelism() {
    let mock = register_mock();
    let out = block_on(sync::register_with_kdf(
        &mock,
        &server(),
        "a@example.com",
        "pw",
        "n",
        sync::KdfParams::argon2id_default(),
    ))
    .expect("register");
    assert_eq!(out.kdf, sync::KdfParams::argon2id_default());
    let v = json_body(&mock.requests()[1]);
    assert_eq!(v["kdf"], 1);
    assert_eq!(v["kdfMemory"], 64);
    assert_eq!(v["kdfParallelism"], 4);

    let weak = block_on(sync::register_with_kdf(
        &mock,
        &server(),
        "a@example.com",
        "pw",
        "n",
        sync::KdfParams::argon2id(2, 16, 1),
    ));
    assert!(
        matches!(weak, Err(sync::SyncError::KdfOutOfRange { .. })),
        "{weak:?}"
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
    assert_eq!(session.kdf.iterations, TEST_ITERS);
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
    let mock = register_mock();
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
        let err = match block_on(set_folder(
            &mock,
            &api,
            &session,
            "cipher-1",
            Some("folder-42"),
        )) {
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
        let mock = mock_from(folder_routes("c", None, Some("f")));
        block_on(set_folder(&mock, base, &session, "c", Some("f")))
            .unwrap_or_else(|e| panic!("set_folder rejected legitimate base {base}: {e:?}"));
        assert_eq!(mock.requests().len(), 2);
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
    let half = Server::new(
        "https://vault.example.test/api",
        "http://evil.example/identity",
    );
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
        "login_with_options",
        mock,
        login_with_options(
            &mock,
            &evil,
            "a@b.test",
            "pw",
            "dev",
            &sync::LoginOptions {
                device_id: Some("test-device".into()),
                kdf_pin: Some(sync::KdfParams::default()),
                allow_legacy_kdf: false,
            }
        )
    );
    refuses!(
        "upgrade_kdf",
        mock,
        sync::upgrade_kdf(
            &mock,
            &evil,
            &session,
            "pw",
            "dev",
            sync::KdfParams::default()
        )
    );
    refuses!(
        "refresh_session",
        mock,
        sync::refresh_session(&mock, &evil, &mut session.clone())
    );
    refuses!(
        "get_cipher",
        mock,
        sync::get_cipher(&mock, &evil, &session, "c-1")
    );
    refuses!(
        "update_preserving",
        mock,
        sync::update_preserving(
            &mock,
            &evil,
            &session,
            "c-1",
            None,
            &sync::CipherEdit::default()
        )
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
        assert!(
            SecureUrl::parse(url).is_ok(),
            "SecureUrl::parse rejected {url}"
        );
    }
}

#[test]
fn try_constructors_reject_a_plaintext_base_at_configuration_time() {
    assert!(Server::try_self_hosted("http://vault.example.test").is_err());
    assert!(Server::try_self_hosted("https://vault.example.test").is_ok());
    assert!(Server::try_new("https://a.test/api", "http://evil.test/identity").is_err());
    assert!(Server::try_new("https://a.test/api", "https://a.test/identity").is_ok());
}

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

    let err = block_on(login_with_options(
        &mock,
        &server(),
        email,
        password,
        "dev",
        &sync::LoginOptions {
            kdf_pin: Some(sync::KdfParams::pbkdf2(pinned)),
            ..Default::default()
        },
    ))
    .expect_err("a 600k -> 100k downgrade must be refused");
    match err {
        sync::SyncError::KdfDowngraded { got, pinned: p } => {
            assert_eq!(got, sync::KdfParams::pbkdf2(offered).describe());
            assert_eq!(p, sync::KdfParams::pbkdf2(pinned).describe());
        }
        other => panic!("expected KdfDowngraded, got {other:?}"),
    }
    assert!(
        !mock
            .requests()
            .iter()
            .any(|r| r.url.contains("/connect/token")),
        "a downgraded master-password hash was sent to the server"
    );

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
        let session = block_on(login_with_options(
            &mock,
            &server(),
            email,
            password,
            "dev",
            &sync::LoginOptions {
                device_id: Some("test-device".into()),
                kdf_pin: Some(sync::KdfParams::pbkdf2(pinned)),
                ..Default::default()
            },
        ))
        .unwrap_or_else(|e| panic!("pin {pinned} vs offered {offered} should pass: {e:?}"));
        assert_eq!(session.kdf.iterations, offered);
        assert_eq!(session.device_id, "test-device");
    }
}

#[test]
fn the_pin_is_trust_on_first_use_and_only_blocks_a_decrease() {
    let p = |n| sync::KdfParams::pbkdf2(n);
    assert!(sync::check_server_kdf(&p(100_000), None, false).is_ok());
    assert!(sync::check_server_kdf(&p(600_000), Some(&p(600_000)), false).is_ok());
    assert!(sync::check_server_kdf(&p(600_001), Some(&p(600_000)), false).is_ok());
    assert!(sync::check_server_kdf(&p(599_999), Some(&p(600_000)), false).is_err());
    assert!(
        sync::check_server_kdf(&p(2_000_001), None, false).is_err(),
        "a stalling count"
    );
    assert!(
        sync::check_server_kdf(
            &p(600_000),
            Some(&sync::KdfParams::argon2id_default()),
            false
        )
        .is_err(),
        "Argon2id -> PBKDF2 is a downgrade"
    );
}

#[test]
fn the_login_floor_rejects_the_2013_era_default() {
    assert!(
        sync::check_kdf_iterations(5_000).is_err(),
        "5000 PBKDF2 iterations must not be accepted"
    );
    assert!(sync::check_kdf_iterations(99_999).is_err());
    assert!(sync::check_kdf_iterations(100_000).is_ok());
}
