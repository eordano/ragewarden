use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use ragewarden_core::bitwarden::{
    decrypt_type2, encrypt_type2, master_password_hash, stretch_master_key,
};
use ragewarden_core::sync::{
    HttpBody, HttpClient, HttpError, HttpResponse, KdfParams, LoginOptions, Server, SyncError,
    login, login_with_options, upgrade_kdf,
};
use serde_json::{Value, json};

const EMAIL: &str = "legacy@example.com";
const PASSWORD: &str = "correct horse";
const USER_KEY: [u8; 64] = [0x42; 64];

/// A Bitwarden account server that checks the master-password hash on every
/// token and KDF request, and re-wraps the account when its KDF changes.
struct Account {
    state: Mutex<(KdfParams, String, String)>,
}

impl Account {
    fn new(kdf: KdfParams) -> Self {
        let (hash, protected) = Self::credentials(&kdf);
        Self {
            state: Mutex::new((kdf, hash, protected)),
        }
    }

    fn credentials(kdf: &KdfParams) -> (String, String) {
        let mk = kdf.derive_master_key(PASSWORD, EMAIL).unwrap();
        let (e, m) = stretch_master_key(&mk);
        (
            master_password_hash(&mk, PASSWORD),
            encrypt_type2(&USER_KEY, &e, &m),
        )
    }

    fn ok(v: Value) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: 200,
            body: serde_json::to_vec(&v).unwrap(),
        })
    }

    fn reject() -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: 400,
            body: b"{\"message\":\"invalid password\"}".to_vec(),
        })
    }
}

#[async_trait]
impl HttpClient for Account {
    async fn post(
        &self,
        url: &str,
        body: HttpBody,
        _: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        let mut st = self.state.lock().unwrap();
        if url.ends_with("/identity/accounts/prelogin") {
            let k = st.0;
            return Self::ok(
                json!({ "kdf": k.kdf, "kdfIterations": k.iterations, "kdfMemory": k.memory_mib, "kdfParallelism": k.parallelism }),
            );
        }
        if url.ends_with("/identity/connect/token") {
            let HttpBody::Form(f) = body else {
                panic!("token form")
            };
            let form: HashMap<String, String> = serde_urlencoded::from_bytes(&f).unwrap();
            if form["password"] != st.1 {
                return Self::reject();
            }
            let jwt = format!(
                "{}.{}.sig",
                B64URL.encode(b"{}"),
                B64URL.encode(b"{\"sub\":\"u\"}")
            );
            return Self::ok(json!({ "access_token": jwt, "refresh_token": "r", "Key": st.2 }));
        }
        if url.ends_with("/api/accounts/kdf") {
            let HttpBody::Json(b) = body else {
                panic!("kdf json")
            };
            let v: Value = serde_json::from_slice(&b).unwrap();
            if v["masterPasswordHash"] != json!(st.1) {
                return Self::reject();
            }
            let new = KdfParams::from_parts(
                v["kdf"].as_u64().map(|x| x as u32),
                v["kdfIterations"].as_u64().unwrap() as u32,
                v["kdfMemory"].as_u64().map(|x| x as u32),
                v["kdfParallelism"].as_u64().map(|x| x as u32),
            );
            let mk = new.derive_master_key(PASSWORD, EMAIL).unwrap();
            let (e, m) = stretch_master_key(&mk);
            let key = v["key"].as_str().unwrap().to_string();
            assert_eq!(
                decrypt_type2(&key, &e, &m).unwrap().as_slice(),
                USER_KEY.as_slice(),
                "the user key must survive the re-wrap"
            );
            assert_eq!(
                v["newMasterPasswordHash"],
                json!(master_password_hash(&mk, PASSWORD))
            );
            let auth = &v["authenticationData"];
            let unlock = &v["unlockData"];
            assert_eq!(auth["salt"], json!(EMAIL));
            assert_eq!(unlock["salt"], json!(EMAIL));
            assert_eq!(auth["kdf"], unlock["kdf"]);
            assert_eq!(auth["kdf"]["kdfType"], v["kdf"]);
            assert_eq!(auth["kdf"]["iterations"], v["kdfIterations"]);
            assert_eq!(
                auth["masterPasswordAuthenticationHash"],
                v["newMasterPasswordHash"]
            );
            assert_eq!(unlock["masterKeyWrappedUserKey"], v["key"]);
            *st = (new, master_password_hash(&mk, PASSWORD), key);
            return Ok(HttpResponse {
                status: 200,
                body: Vec::new(),
            });
        }
        Err(HttpError::Transport(format!("unexpected POST {url}")))
    }
    async fn put(
        &self,
        url: &str,
        _: HttpBody,
        _: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        Err(HttpError::Transport(format!("unexpected PUT {url}")))
    }
    async fn get(&self, url: &str, _: &[(String, String)]) -> Result<HttpResponse, HttpError> {
        Err(HttpError::Transport(format!("unexpected GET {url}")))
    }
    async fn delete(&self, url: &str, _: &[(String, String)]) -> Result<HttpResponse, HttpError> {
        Err(HttpError::Transport(format!("unexpected DELETE {url}")))
    }
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut fut = Box::pin(fut);
    match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("the mock HttpClient is always ready"),
    }
}

fn server() -> Server {
    Server::self_hosted("https://vault.example.test")
}

#[test]
fn a_legacy_account_is_raised_to_the_default_and_then_logs_in_without_consent() {
    let account = Account::new(KdfParams::pbkdf2(5_000));

    assert!(matches!(
        block_on(login(&account, &server(), EMAIL, PASSWORD, "dev")),
        Err(SyncError::LegacyKdfNeedsConsent { got: 5_000, .. })
    ));

    let legacy = block_on(login_with_options(
        &account,
        &server(),
        EMAIL,
        PASSWORD,
        "dev",
        &LoginOptions {
            allow_legacy_kdf: true,
            ..Default::default()
        },
    ))
    .expect("consented login");
    assert!(legacy.kdf.below_recommended());

    let upgraded = block_on(upgrade_kdf(
        &account,
        &server(),
        &legacy,
        PASSWORD,
        "dev",
        KdfParams::default(),
    ))
    .expect("upgrade");
    assert_eq!(upgraded.kdf, KdfParams::default());
    assert_eq!(upgraded.device_id, legacy.device_id);
    assert_eq!(upgraded.user_enc_key.as_slice(), &USER_KEY[..32]);

    let later = block_on(login(&account, &server(), EMAIL, PASSWORD, "dev"))
        .expect("plain login after upgrade");
    assert_eq!(later.kdf, KdfParams::default());
}

#[test]
fn an_account_can_move_from_pbkdf2_to_argon2id() {
    let account = Account::new(KdfParams::pbkdf2(600_000));
    let s = block_on(login(&account, &server(), EMAIL, PASSWORD, "dev")).unwrap();
    let up = block_on(upgrade_kdf(
        &account,
        &server(),
        &s,
        PASSWORD,
        "dev",
        KdfParams::argon2id_default(),
    ))
    .unwrap();
    assert_eq!(up.kdf, KdfParams::argon2id_default());
    let pinned = LoginOptions {
        kdf_pin: Some(up.kdf),
        ..Default::default()
    };
    block_on(login_with_options(
        &account,
        &server(),
        EMAIL,
        PASSWORD,
        "dev",
        &pinned,
    ))
    .expect("pinned Argon2id login");
}

#[test]
fn upgrade_refuses_a_target_below_the_new_account_floor_without_calling_the_server() {
    let account = Account::new(KdfParams::pbkdf2(600_000));
    let s = block_on(login(&account, &server(), EMAIL, PASSWORD, "dev")).unwrap();
    let err = block_on(upgrade_kdf(
        &account,
        &server(),
        &s,
        PASSWORD,
        "dev",
        KdfParams::pbkdf2(100_000),
    ))
    .unwrap_err();
    assert!(
        matches!(err, SyncError::KdfIterationsTooLow { .. }),
        "{err:?}"
    );
    assert_eq!(account.state.lock().unwrap().0, KdfParams::pbkdf2(600_000));
}
