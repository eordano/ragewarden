use std::collections::BTreeMap;
use std::fmt;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::bitwarden::{
    self, KDF_ARGON2ID, KDF_ITERATIONS_DEFAULT, KDF_ITERATIONS_MIN, KDF_ITERATIONS_MIN_NEW_ACCOUNT,
    KDF_PBKDF2, decrypt_type2, make_rsa_keypair_for_registration, make_user_key,
    master_password_hash, stretch_master_key,
};
pub use crate::kdf::KdfParams;
use crate::kdf::{
    ARGON2_ITERATIONS_DEFAULT, ARGON2_ITERATIONS_MAX, ARGON2_ITERATIONS_MIN,
    ARGON2_MEMORY_MIB_DEFAULT, ARGON2_MEMORY_MIB_MAX, ARGON2_MEMORY_MIB_MIN,
    ARGON2_PARALLELISM_MAX, ARGON2_PARALLELISM_MIN, KDF_ITERATIONS_LEGACY_MIN, KDF_ITERATIONS_MAX,
    KdfError,
};
use crate::tokens::VaultKey;
use crate::type2::Type2EncString;

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("transport: {0}")]
    Transport(String),

    #[error("response decode: {0}")]
    Decode(String),
}

#[derive(Debug, Clone)]
pub enum HttpBody {
    Json(Vec<u8>),

    Form(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,

    pub body: Vec<u8>,
}

#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn post(
        &self,
        url: &str,
        body: HttpBody,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError>;

    async fn put(
        &self,
        url: &str,
        body: HttpBody,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError>;

    async fn get(&self, url: &str, headers: &[(String, String)])
    -> Result<HttpResponse, HttpError>;

    async fn delete(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<HttpResponse, HttpError>;
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("http: {0}")]
    Http(#[from] HttpError),

    #[error("server returned {status}: {body}")]
    Server { status: u16, body: String },

    #[error("parse: {0}")]
    Parse(String),

    #[error("crypto: {0}")]
    Crypto(String),

    #[error("{0}")]
    State(String),

    #[error("refusing to talk to an insecure server: {0}")]
    Insecure(#[from] ServerInsecureError),

    #[error(
        "server asked for {got} KDF iterations, which is below the {min} minimum this client \
         accepts; a server that lowers this is trying to weaken your master password"
    )]
    KdfIterationsTooLow { got: u32, min: u32 },

    #[error(
        "this account derives its master key with only {got} PBKDF2 iterations (below {min}); \
         log in once more confirming that this is expected, and the client will raise it to \
         the current default on the server"
    )]
    LegacyKdfNeedsConsent { got: u32, min: u32 },

    #[error("server requires KDF type {got}, which this client cannot derive")]
    UnsupportedKdfType { got: u32 },

    #[error("server asked for {param} = {got}; this client accepts {min}..={max}")]
    KdfOutOfRange {
        param: &'static str,
        got: u32,
        min: u32,
        max: u32,
    },

    #[error(
        "server asked for {got} but this account used {pinned} the last time it was seen; a \
         server that lowers this is trying to weaken your master password"
    )]
    KdfDowngraded { got: String, pinned: String },

    #[error("kdf: {0}")]
    Kdf(#[from] KdfError),

    #[error(
        "none of this vault's {items} personal items decrypt with this session's key; the \
         session belongs to another account or its key is corrupt -- log in again"
    )]
    WrongUserKey { items: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub api_url: String,

    pub identity_url: String,
}

impl Server {
    pub fn self_hosted(base_url: impl AsRef<str>) -> Self {
        let base = base_url.as_ref().trim_end_matches('/').to_string();
        Self {
            api_url: format!("{base}/api"),
            identity_url: format!("{base}/identity"),
        }
    }

    pub fn new(api_url: impl Into<String>, identity_url: impl Into<String>) -> Self {
        Self {
            api_url: api_url.into().trim_end_matches('/').to_string(),
            identity_url: identity_url.into().trim_end_matches('/').to_string(),
        }
    }

    /// Fail-fast variant of [`Server::self_hosted`]: rejects a plaintext
    /// non-loopback base URL at configuration time rather than at first
    /// request. Prefer this in new code.
    pub fn try_self_hosted(base_url: impl AsRef<str>) -> Result<Self, ServerInsecureError> {
        let s = Self::self_hosted(base_url);
        s.require_secure()?;
        Ok(s)
    }

    /// Fail-fast variant of [`Server::new`].
    pub fn try_new(
        api_url: impl Into<String>,
        identity_url: impl Into<String>,
    ) -> Result<Self, ServerInsecureError> {
        let s = Self::new(api_url, identity_url);
        s.require_secure()?;
        Ok(s)
    }

    pub fn require_secure(&self) -> Result<(), ServerInsecureError> {
        for url in [&self.api_url, &self.identity_url] {
            if !is_secure_url(url) {
                return Err(ServerInsecureError { url: url.clone() });
            }
        }
        Ok(())
    }

    /// Builds an api-side endpoint, validating the *whole* server first.
    ///
    /// This is the only way to turn a [`Server`] into something [`send`] will
    /// accept, which is what makes the transport check unforgettable: adding a
    /// new endpoint without validation does not compile.
    fn api(&self, path: fmt::Arguments<'_>) -> Result<SecureUrl, ServerInsecureError> {
        self.require_secure()?;
        SecureUrl::parse(format!("{}{}", self.api_url, path))
    }

    /// Identity-side counterpart of [`Server::api`].
    fn identity(&self, path: fmt::Arguments<'_>) -> Result<SecureUrl, ServerInsecureError> {
        self.require_secure()?;
        SecureUrl::parse(format!("{}{}", self.identity_url, path))
    }
}

/// Sealed so that not even the rest of `sync.rs` can reach the tuple
/// constructor: the only way to obtain a `SecureUrl` anywhere in the crate is
/// [`SecureUrl::parse`], which validates.
mod secure_url {
    use std::fmt;

    use super::{ServerInsecureError, is_secure_url};

    /// A URL that has been checked against [`is_secure_url`].
    ///
    /// The inner string is private to this module and the sole constructor
    /// validates, so a value of this type cannot name a plaintext non-loopback
    /// endpoint. All outbound requests in `sync.rs` take a `&SecureUrl`, which
    /// moves the transport check from "every author must remember to call
    /// `require_secure()`" to "the code does not compile without it".
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SecureUrl(String);

    impl SecureUrl {
        pub fn parse(url: impl Into<String>) -> Result<Self, ServerInsecureError> {
            let url = url.into();
            if is_secure_url(&url) {
                Ok(Self(url))
            } else {
                Err(ServerInsecureError { url })
            }
        }

        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    impl fmt::Display for SecureUrl {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }
}

pub use secure_url::SecureUrl;

enum Request {
    Get,
    Delete,
    Post(HttpBody),
    Put(HttpBody),
}

/// The single point at which this module touches the network.
///
/// Every `client.get/post/put/delete` call in `sync.rs` lives here; the
/// `&SecureUrl` parameter is the type-level proof that the URL was validated.
/// `sync_protocol.rs::every_http_call_in_sync_rs_goes_through_the_chokepoint`
/// guards against a future endpoint reaching around it.
async fn send<C: HttpClient + ?Sized>(
    client: &C,
    url: &SecureUrl,
    req: Request,
    headers: &[(String, String)],
) -> Result<HttpResponse, SyncError> {
    let u = url.as_str();
    let res = match req {
        Request::Get => client.get(u, headers).await?,
        Request::Delete => client.delete(u, headers).await?,
        Request::Post(body) => client.post(u, body, headers).await?,
        Request::Put(body) => client.put(u, body, headers).await?,
    };
    if res.status >= 400 {
        return Err(server_err(&res));
    }
    Ok(res)
}

/// `https://` anywhere, or `http://` only to a real loopback host.
pub fn is_secure_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    if lower.starts_with("https://") {
        return true;
    }
    match lower.strip_prefix("http://") {
        Some(rest) => host_is_loopback(authority_host(rest)),
        None => false,
    }
}

fn authority_host(after_scheme: &str) -> &str {
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);

    let hostport = match authority.rsplit_once('@') {
        Some((_userinfo, hostport)) => hostport,
        None => authority,
    };

    if let Some(rest) = hostport.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((inside, after)) if after.is_empty() || after.starts_with(':') => inside,
            _ => "",
        };
    }

    match hostport.split_once(':') {
        Some((host, _port)) => host,
        None => hostport,
    }
}

fn host_is_loopback(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return v4.is_loopback();
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return v6.is_loopback();
    }
    false
}

#[derive(Debug, Error)]
#[error("server URL is not https: {url}")]
pub struct ServerInsecureError {
    pub url: String,
}

#[derive(Debug)]
pub struct RegisterOutput {
    pub email: String,

    pub kdf: KdfParams,

    pub user_enc_key: VaultKey,

    pub user_mac_key: VaultKey,
}

/// Floor check for a count the *server* handed us (login).
pub fn check_kdf_iterations(got: u32) -> Result<(), SyncError> {
    check_kdf_iterations_at_least(got, KDF_ITERATIONS_MIN)
}

/// Floor check for a count *this client* chose (registration). Stricter than
/// [`check_kdf_iterations`] because no legacy account can exist yet.
pub fn check_kdf_iterations_for_new_account(got: u32) -> Result<(), SyncError> {
    check_kdf_iterations_at_least(got, KDF_ITERATIONS_MIN_NEW_ACCOUNT)
}

pub fn check_kdf_iterations_at_least(got: u32, min: u32) -> Result<(), SyncError> {
    if got < min {
        return Err(SyncError::KdfIterationsTooLow { got, min });
    }
    Ok(())
}

fn in_range(param: &'static str, got: u32, min: u32, max: u32) -> Result<(), SyncError> {
    if got < min || got > max {
        return Err(SyncError::KdfOutOfRange {
            param,
            got,
            min,
            max,
        });
    }
    Ok(())
}

/// Accepts derivation parameters a *server* handed us (prelogin).
///
/// PBKDF2 below [`KDF_ITERATIONS_MIN`] is a legacy account: refused unless
/// `allow_legacy` says the user confirmed it, and never below
/// [`KDF_ITERATIONS_LEGACY_MIN`]. Anything weaker than `pinned` -- the
/// parameters seen on this account's last successful login -- is refused, as
/// is anything above the maximum a hostile server could use to stall the
/// client.
pub fn check_server_kdf(
    got: &KdfParams,
    pinned: Option<&KdfParams>,
    allow_legacy: bool,
) -> Result<(), SyncError> {
    match got.kdf {
        KDF_PBKDF2 => {
            check_kdf_iterations_at_least(got.iterations, KDF_ITERATIONS_LEGACY_MIN)?;
            in_range(
                "PBKDF2 iterations",
                got.iterations,
                KDF_ITERATIONS_LEGACY_MIN,
                KDF_ITERATIONS_MAX,
            )?;
            if got.iterations < KDF_ITERATIONS_MIN && !allow_legacy {
                return Err(SyncError::LegacyKdfNeedsConsent {
                    got: got.iterations,
                    min: KDF_ITERATIONS_MIN,
                });
            }
        }
        KDF_ARGON2ID => check_argon2(got, ARGON2_ITERATIONS_MIN, ARGON2_MEMORY_MIB_MIN)?,
        other => return Err(SyncError::UnsupportedKdfType { got: other }),
    }
    if let Some(pinned) = pinned {
        if got.weaker_than(pinned) {
            return Err(SyncError::KdfDowngraded {
                got: got.describe(),
                pinned: pinned.describe(),
            });
        }
    }
    Ok(())
}

fn check_argon2(p: &KdfParams, min_iterations: u32, min_memory: u32) -> Result<(), SyncError> {
    let (Some(memory), Some(parallelism)) = (p.memory_mib, p.parallelism) else {
        return Err(KdfError::MissingArgon2Params.into());
    };
    in_range(
        "Argon2id iterations",
        p.iterations,
        min_iterations,
        ARGON2_ITERATIONS_MAX,
    )?;
    in_range(
        "Argon2id memory (MiB)",
        memory,
        min_memory,
        ARGON2_MEMORY_MIB_MAX,
    )?;
    in_range(
        "Argon2id parallelism",
        parallelism,
        ARGON2_PARALLELISM_MIN,
        ARGON2_PARALLELISM_MAX,
    )
}

/// Parameters *this client* chooses (registration, KDF upgrade): at least the
/// current recommendation, since nothing legacy can exist yet.
pub fn check_kdf_for_new_account(p: &KdfParams) -> Result<(), SyncError> {
    match p.kdf {
        KDF_PBKDF2 => {
            check_kdf_iterations_for_new_account(p.iterations)?;
            in_range(
                "PBKDF2 iterations",
                p.iterations,
                KDF_ITERATIONS_MIN_NEW_ACCOUNT,
                KDF_ITERATIONS_MAX,
            )
        }
        KDF_ARGON2ID => check_argon2(p, ARGON2_ITERATIONS_DEFAULT, ARGON2_MEMORY_MIB_DEFAULT),
        other => Err(SyncError::UnsupportedKdfType { got: other }),
    }
}

pub async fn register(
    client: &dyn HttpClient,
    server: &Server,
    email: &str,
    master_password: &str,
    name: &str,
    kdf_iterations: u32,
) -> Result<RegisterOutput, SyncError> {
    register_with_kdf(
        client,
        server,
        email,
        master_password,
        name,
        KdfParams::pbkdf2(kdf_iterations),
    )
    .await
}

/// [`register`] with any supported derivation, e.g.
/// [`KdfParams::argon2id_default`].
pub async fn register_with_kdf(
    client: &dyn HttpClient,
    server: &Server,
    email: &str,
    master_password: &str,
    name: &str,
    kdf: KdfParams,
) -> Result<RegisterOutput, SyncError> {
    let verify_url = server.identity(format_args!("/accounts/register/send-verification-email"))?;
    let finish_url = server.identity(format_args!("/accounts/register/finish"))?;
    let legacy_url = server.identity(format_args!("/accounts/register"))?;
    check_kdf_for_new_account(&kdf)?;
    let email_lc = email.trim().to_lowercase();
    let master_key = kdf.derive_master_key(master_password, &email_lc)?;
    let mphash = master_password_hash(&master_key, master_password);
    let user_key = make_user_key(&master_key);
    let rsa_keys = make_rsa_keypair_for_registration(&user_key.enc_key, &user_key.mac_key)
        .map_err(|e| SyncError::Crypto(e.to_string()))?;

    let body = RegisterRequest {
        email: email_lc.clone(),
        name: name.to_string(),
        master_password_hash: mphash,
        master_password_hint: None,
        key: user_key.protected.clone(),
        keys: RegisterKeys {
            public_key: rsa_keys.public_key_b64,
            encrypted_private_key: rsa_keys.encrypted_private_key,
        },
        kdf: kdf.kdf,
        kdf_iterations: kdf.iterations,
        kdf_memory: kdf.memory_mib,
        kdf_parallelism: kdf.parallelism,
        reference_data: None,
        email_verification_token: None,
    };

    let (url, body) = match registration_token(client, &verify_url, &email_lc, name).await? {
        Some(token) => (
            finish_url,
            RegisterRequest {
                email_verification_token: Some(token),
                ..body
            },
        ),
        None => (legacy_url, body),
    };
    let body_json = serde_json::to_vec(&body).map_err(|e| SyncError::Parse(e.to_string()))?;
    send(client, &url, Request::Post(HttpBody::Json(body_json)), &[]).await?;

    Ok(RegisterOutput {
        email: email_lc,
        kdf,
        user_enc_key: VaultKey::from_trusted(user_key.enc_key.to_vec()),
        user_mac_key: VaultKey::from_trusted(user_key.mac_key.to_vec()),
    })
}

/// First step of the two-step registration Bitwarden and Vaultwarden (since
/// 1.37) require: the server answers with the token `register/finish` wants.
/// `None` means a server that predates the flow (404), so the caller posts the
/// legacy single-step `/accounts/register` instead.
async fn registration_token(
    client: &dyn HttpClient,
    url: &SecureUrl,
    email: &str,
    name: &str,
) -> Result<Option<String>, SyncError> {
    let body = serde_json::to_vec(&RegisterVerificationRequest { email, name })
        .map_err(|e| SyncError::Parse(e.to_string()))?;
    let res = match send(
        client,
        url,
        Request::Post(HttpBody::Json(body)),
        &[("Accept".into(), "application/json".into())],
    )
    .await
    {
        Ok(res) => res,
        Err(SyncError::Server { status: 404, .. }) => return Ok(None),
        Err(e) => return Err(e),
    };
    let text = String::from_utf8_lossy(&res.body);
    let text = text.trim();
    if res.status == 204 || text.is_empty() {
        return Err(SyncError::State(
            "the server emailed a verification link instead of returning a registration token; \
             finish signing up from that link"
                .into(),
        ));
    }
    Ok(Some(
        serde_json::from_str::<String>(text).unwrap_or_else(|_| text.to_string()),
    ))
}

#[derive(Debug, Serialize)]
struct RegisterVerificationRequest<'a> {
    email: &'a str,
    name: &'a str,
}

#[derive(Debug, Serialize)]
struct RegisterRequest {
    email: String,
    name: String,
    #[serde(rename = "masterPasswordHash")]
    master_password_hash: String,
    #[serde(rename = "masterPasswordHint")]
    master_password_hint: Option<String>,
    key: String,
    keys: RegisterKeys,
    kdf: u32,
    #[serde(rename = "kdfIterations")]
    kdf_iterations: u32,
    #[serde(rename = "kdfMemory", skip_serializing_if = "Option::is_none")]
    kdf_memory: Option<u32>,
    #[serde(rename = "kdfParallelism", skip_serializing_if = "Option::is_none")]
    kdf_parallelism: Option<u32>,
    #[serde(rename = "referenceData")]
    reference_data: Option<serde_json::Value>,
    #[serde(
        rename = "emailVerificationToken",
        skip_serializing_if = "Option::is_none"
    )]
    email_verification_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegisterKeys {
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "encryptedPrivateKey")]
    encrypted_private_key: String,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub access_token: crate::BearerToken,

    pub refresh_token: crate::RefreshToken,

    pub user_id: String,

    pub email: String,

    pub user_enc_key: VaultKey,

    pub user_mac_key: VaultKey,

    /// How this account's master key is derived. Persist it and pass it back
    /// as [`LoginOptions::kdf_pin`] so a later login refuses weaker parameters.
    pub kdf: KdfParams,

    /// The device identifier this session registered with the server. Stable
    /// across a session so `refresh_session` re-presents the same device the
    /// access token was minted for; a fresh id per call bloats the server's
    /// device table and, on servers that bind tokens to devices, invalidates
    /// the token the moment a new device supersedes it.
    pub device_id: String,
}

impl Session {
    pub fn bearer(&self) -> String {
        self.access_token.header_value()
    }
}

#[derive(Debug, Clone, Default)]
pub struct LoginOptions {
    /// A stable device identifier; `None` mints a fresh one.
    pub device_id: Option<String>,

    /// The derivation parameters this account had on its last successful
    /// login ([`Session::kdf`]). A server offering weaker ones is refused
    /// before the master password is hashed or sent.
    pub kdf_pin: Option<KdfParams>,

    /// The user confirmed a legacy PBKDF2 count below
    /// [`bitwarden::KDF_ITERATIONS_MIN`]. Follow such a login with
    /// [`upgrade_kdf`].
    pub allow_legacy_kdf: bool,
}

pub async fn login(
    client: &dyn HttpClient,
    server: &Server,
    email: &str,
    master_password: &str,
    device_name: &str,
) -> Result<Session, SyncError> {
    login_with_options(
        client,
        server,
        email,
        master_password,
        device_name,
        &LoginOptions::default(),
    )
    .await
}

/// [`login`] with a caller-supplied stable device identifier.
pub async fn login_with_device(
    client: &dyn HttpClient,
    server: &Server,
    email: &str,
    master_password: &str,
    device_name: &str,
    device_id: &str,
) -> Result<Session, SyncError> {
    login_with_options(
        client,
        server,
        email,
        master_password,
        device_name,
        &LoginOptions {
            device_id: Some(device_id.to_string()),
            ..LoginOptions::default()
        },
    )
    .await
}

pub async fn login_with_options(
    client: &dyn HttpClient,
    server: &Server,
    email: &str,
    master_password: &str,
    device_name: &str,
    opts: &LoginOptions,
) -> Result<Session, SyncError> {
    let token_url = server.identity(format_args!("/connect/token"))?;
    let email_lc = email.trim().to_lowercase();
    let kdf = match prelogin(client, server, &email_lc).await {
        Ok(p) => {
            let got = p.params();
            check_server_kdf(&got, opts.kdf_pin.as_ref(), opts.allow_legacy_kdf)?;
            got
        }
        Err(_) => opts.kdf_pin.unwrap_or_default(),
    };
    let device_id = opts
        .device_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let master_key = kdf.derive_master_key(master_password, &email_lc)?;
    let mphash = master_password_hash(&master_key, master_password);

    let form = TokenForm {
        grant_type: "password".to_string(),
        username: email_lc.clone(),
        password: mphash,
        scope: "api offline_access".to_string(),
        client_id: "cli".to_string(),
        device_type: "8".to_string(),
        device_identifier: device_id.clone(),
        device_name: device_name.to_string(),
    };
    let body = serde_urlencoded::to_string(&form)
        .map_err(|e| SyncError::Parse(format!("urlencode: {e}")))?
        .into_bytes();

    let auth_email = B64URL.encode(email_lc.as_bytes());
    let res = send(
        client,
        &token_url,
        Request::Post(HttpBody::Form(body)),
        &[("Auth-Email".into(), auth_email)],
    )
    .await?;

    let parsed: TokenResponse =
        serde_json::from_slice(&res.body).map_err(|e| SyncError::Parse(format!("token: {e}")))?;

    let (stretch_enc, stretch_mac) = stretch_master_key(&master_key);
    let raw = decrypt_type2(&parsed.key, &stretch_enc, &stretch_mac)
        .map_err(|e| SyncError::Crypto(format!("unwrap user key: {e}")))?;
    if raw.len() != 64 {
        return Err(SyncError::Crypto(format!(
            "user key has wrong length {} (expected 64)",
            raw.len()
        )));
    }

    let user_id = jwt_sub(&parsed.access_token).unwrap_or_default();

    Ok(Session {
        access_token: crate::BearerToken::from_trusted(parsed.access_token),
        refresh_token: crate::RefreshToken::from_trusted(parsed.refresh_token.unwrap_or_default()),
        user_id,
        email: email_lc,
        user_enc_key: VaultKey::from_trusted(raw[..32].to_vec()),
        user_mac_key: VaultKey::from_trusted(raw[32..].to_vec()),
        kdf,
        device_id,
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct KdfWire {
    kdf_type: u32,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct KdfAuthenticationData {
    salt: String,
    kdf: KdfWire,
    master_password_authentication_hash: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct KdfUnlockData {
    salt: String,
    kdf: KdfWire,
    master_key_wrapped_user_key: String,
}

/// Both shapes of `POST /api/accounts/kdf`: the nested one current Bitwarden
/// and Vaultwarden (1.34+) read, and the flat one older servers read. Each
/// server ignores the other's fields.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct KdfChangeRequest {
    master_password_hash: String,
    authentication_data: KdfAuthenticationData,
    unlock_data: KdfUnlockData,
    kdf: u32,
    kdf_iterations: u32,
    kdf_memory: Option<u32>,
    kdf_parallelism: Option<u32>,
    new_master_password_hash: String,
    key: String,
}

/// Re-derives the account's master key with `new` on the server (the user
/// key and every cipher stay as they are; only the user key's wrapping
/// changes). The server then invalidates existing tokens, so this logs in
/// again with `new` pinned and returns that session. Other Bitwarden clients
/// of the account have to log in again, as after any KDF change.
pub async fn upgrade_kdf(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    master_password: &str,
    device_name: &str,
    new: KdfParams,
) -> Result<Session, SyncError> {
    let url = server.api(format_args!("/accounts/kdf"))?;
    check_kdf_for_new_account(&new)?;
    let old_master = session
        .kdf
        .derive_master_key(master_password, &session.email)?;
    let new_master = new.derive_master_key(master_password, &session.email)?;
    let (stretch_enc, stretch_mac) = stretch_master_key(&new_master);
    let user = ItemKeys::user(session)?;
    let mut raw = Zeroizing::new([0u8; 64]);
    raw[..32].copy_from_slice(user.enc.as_ref());
    raw[32..].copy_from_slice(user.mac.as_ref());
    let new_hash = master_password_hash(&new_master, master_password);
    let key = bitwarden::encrypt_type2(raw.as_ref(), &stretch_enc, &stretch_mac);
    let wire = KdfWire {
        kdf_type: new.kdf,
        iterations: new.iterations,
        memory: new.memory_mib,
        parallelism: new.parallelism,
    };
    let body = KdfChangeRequest {
        master_password_hash: master_password_hash(&old_master, master_password),
        authentication_data: KdfAuthenticationData {
            salt: session.email.clone(),
            kdf: wire.clone(),
            master_password_authentication_hash: new_hash.clone(),
        },
        unlock_data: KdfUnlockData {
            salt: session.email.clone(),
            kdf: wire,
            master_key_wrapped_user_key: key.clone(),
        },
        kdf: new.kdf,
        kdf_iterations: new.iterations,
        kdf_memory: new.memory_mib,
        kdf_parallelism: new.parallelism,
        new_master_password_hash: new_hash,
        key,
    };
    let body = serde_json::to_vec(&body).map_err(|e| SyncError::Parse(e.to_string()))?;
    send(
        client,
        &url,
        Request::Post(HttpBody::Json(body)),
        &[("Authorization".into(), session.bearer())],
    )
    .await?;
    login_with_options(
        client,
        server,
        &session.email,
        master_password,
        device_name,
        &LoginOptions {
            device_id: Some(session.device_id.clone()),
            kdf_pin: Some(new),
            allow_legacy_kdf: false,
        },
    )
    .await
}

/// Exchange the session's refresh token for a fresh access token in place.
///
/// Bitwarden access tokens are short-lived; a persisted session outlives them.
/// On a 401 the caller refreshes rather than forcing the user to re-enter their
/// master password. The same `device_id` is re-presented so the server keeps
/// binding the token to the one device this session owns.
pub async fn refresh_session(
    client: &dyn HttpClient,
    server: &Server,
    session: &mut Session,
) -> Result<(), SyncError> {
    let token_url = server.identity(format_args!("/connect/token"))?;
    let form = RefreshForm {
        grant_type: "refresh_token".to_string(),
        refresh_token: session.refresh_token.expose().to_string(),
        client_id: "cli".to_string(),
        device_type: "8".to_string(),
        device_identifier: session.device_id.clone(),
    };
    let body = serde_urlencoded::to_string(&form)
        .map_err(|e| SyncError::Parse(format!("urlencode: {e}")))?
        .into_bytes();
    let res = send(client, &token_url, Request::Post(HttpBody::Form(body)), &[]).await?;
    let parsed: RefreshResponse =
        serde_json::from_slice(&res.body).map_err(|e| SyncError::Parse(format!("refresh: {e}")))?;
    session.access_token = crate::BearerToken::from_trusted(parsed.access_token);
    if let Some(rt) = parsed.refresh_token {
        session.refresh_token = crate::RefreshToken::from_trusted(rt);
    }
    Ok(())
}

/// True for the error a request with an expired access token gets; answer it
/// with [`refresh_session`] and one retry rather than a fresh login.
pub fn is_unauthorized(e: &SyncError) -> bool {
    matches!(e, SyncError::Server { status: 401, .. })
}

#[derive(Debug, Deserialize)]
struct RefreshResponse {
    access_token: String,
    refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct RefreshForm {
    grant_type: String,
    refresh_token: String,
    client_id: String,
    #[serde(rename = "deviceType")]
    device_type: String,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: String,
}

#[derive(Debug, Serialize)]
struct TokenForm {
    grant_type: String,
    username: String,
    password: String,
    scope: String,
    client_id: String,
    #[serde(rename = "deviceType")]
    device_type: String,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: String,
    #[serde(rename = "deviceName")]
    device_name: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,

    #[serde(rename = "Key", alias = "key")]
    key: String,
}

#[derive(Debug, Deserialize)]
struct PreloginResponse {
    #[serde(rename = "KdfIterations", alias = "kdfIterations")]
    kdf_iterations: Option<u32>,

    #[serde(rename = "Kdf", alias = "kdf")]
    kdf: Option<u32>,

    #[serde(rename = "KdfMemory", alias = "kdfMemory", default)]
    kdf_memory: Option<u32>,

    #[serde(rename = "KdfParallelism", alias = "kdfParallelism", default)]
    kdf_parallelism: Option<u32>,
}

impl PreloginResponse {
    fn params(&self) -> KdfParams {
        let kdf = self.kdf.unwrap_or(KDF_PBKDF2);
        let default_iterations = if kdf == KDF_ARGON2ID {
            ARGON2_ITERATIONS_DEFAULT
        } else {
            KDF_ITERATIONS_DEFAULT
        };
        KdfParams::from_parts(
            Some(kdf),
            self.kdf_iterations.unwrap_or(default_iterations),
            self.kdf_memory,
            self.kdf_parallelism,
        )
    }
}

async fn prelogin(
    client: &dyn HttpClient,
    server: &Server,
    email: &str,
) -> Result<PreloginResponse, SyncError> {
    let url = server.identity(format_args!("/accounts/prelogin"))?;
    let body = serde_json::to_vec(&serde_json::json!({ "email": email }))
        .map_err(|e| SyncError::Parse(e.to_string()))?;
    let res = send(client, &url, Request::Post(HttpBody::Json(body)), &[]).await?;
    serde_json::from_slice(&res.body).map_err(|e| SyncError::Parse(format!("prelogin: {e}")))
}

fn jwt_sub(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let bytes = B64URL.decode(payload_b64).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("sub").and_then(|x| x.as_str()).map(|s| s.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherField {
    #[serde(rename = "Name", alias = "name")]
    pub name: Type2EncString,

    #[serde(rename = "Value", alias = "value")]
    pub value: Option<Type2EncString>,

    #[serde(rename = "Type", alias = "type")]
    pub field_type: u8,

    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CipherLogin {
    #[serde(
        rename = "Username",
        alias = "username",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub username: Option<Type2EncString>,

    #[serde(
        rename = "Password",
        alias = "password",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub password: Option<Type2EncString>,

    #[serde(
        rename = "Totp",
        alias = "totp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub totp: Option<Type2EncString>,

    #[serde(
        rename = "Uris",
        alias = "uris",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub uris: Option<Vec<CipherUri>>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherUri {
    #[serde(rename = "Uri", alias = "uri")]
    pub uri: Type2EncString,

    #[serde(
        rename = "Match",
        alias = "match",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub match_type: Option<u8>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Cipher {
    #[serde(
        rename = "Id",
        alias = "id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<String>,

    #[serde(
        rename = "OrganizationId",
        alias = "organizationId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub organization_id: Option<String>,

    #[serde(
        rename = "FolderId",
        alias = "folderId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub folder_id: Option<String>,

    #[serde(rename = "Type", alias = "type")]
    pub cipher_type: u8,

    #[serde(rename = "Name", alias = "name")]
    pub name: Type2EncString,

    #[serde(
        rename = "Notes",
        alias = "notes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub notes: Option<Type2EncString>,

    #[serde(
        rename = "Login",
        alias = "login",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub login: Option<CipherLogin>,

    #[serde(
        rename = "Fields",
        alias = "fields",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub fields: Option<Vec<CipherField>>,

    #[serde(rename = "Favorite", alias = "favorite", default)]
    pub favorite: bool,

    #[serde(rename = "Reprompt", alias = "reprompt", default)]
    pub reprompt: u8,

    #[serde(
        rename = "SecureNote",
        alias = "secureNote",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub secure_note: Option<SecureNote>,

    #[serde(
        rename = "Card",
        alias = "card",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub card: Option<CipherCard>,

    #[serde(
        rename = "Identity",
        alias = "identity",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity: Option<CipherIdentity>,

    #[serde(
        rename = "SshKey",
        alias = "sshKey",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ssh_key: Option<CipherSshKey>,

    #[serde(
        rename = "Key",
        alias = "key",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub key: Option<Type2EncString>,

    #[serde(
        rename = "PasswordHistory",
        alias = "passwordHistory",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub password_history: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureNote {
    #[serde(rename = "Type", alias = "type", default)]
    pub note_type: u8,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CipherCard {
    #[serde(
        rename = "CardholderName",
        alias = "cardholderName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cardholder_name: Option<Type2EncString>,

    #[serde(
        rename = "Brand",
        alias = "brand",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub brand: Option<Type2EncString>,

    #[serde(
        rename = "Number",
        alias = "number",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub number: Option<Type2EncString>,

    #[serde(
        rename = "ExpMonth",
        alias = "expMonth",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub exp_month: Option<Type2EncString>,

    #[serde(
        rename = "ExpYear",
        alias = "expYear",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub exp_year: Option<Type2EncString>,

    #[serde(
        rename = "Code",
        alias = "code",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub code: Option<Type2EncString>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CipherIdentity {
    #[serde(
        rename = "FirstName",
        alias = "firstName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub first_name: Option<Type2EncString>,

    #[serde(
        rename = "MiddleName",
        alias = "middleName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub middle_name: Option<Type2EncString>,

    #[serde(
        rename = "LastName",
        alias = "lastName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_name: Option<Type2EncString>,

    #[serde(
        rename = "Address1",
        alias = "address1",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub address1: Option<Type2EncString>,

    #[serde(
        rename = "Address2",
        alias = "address2",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub address2: Option<Type2EncString>,

    #[serde(
        rename = "Address3",
        alias = "address3",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub address3: Option<Type2EncString>,

    #[serde(
        rename = "City",
        alias = "city",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub city: Option<Type2EncString>,

    #[serde(
        rename = "State",
        alias = "state",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub state: Option<Type2EncString>,

    #[serde(
        rename = "PostalCode",
        alias = "postalCode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub postal_code: Option<Type2EncString>,

    #[serde(
        rename = "Country",
        alias = "country",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub country: Option<Type2EncString>,

    #[serde(
        rename = "Phone",
        alias = "phone",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub phone: Option<Type2EncString>,

    #[serde(
        rename = "Email",
        alias = "email",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub email: Option<Type2EncString>,

    #[serde(
        rename = "Ssn",
        alias = "ssn",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ssn: Option<Type2EncString>,

    #[serde(
        rename = "PassportNumber",
        alias = "passportNumber",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub passport_number: Option<Type2EncString>,

    #[serde(
        rename = "Dob",
        alias = "dob",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub dob: Option<Type2EncString>,
    #[serde(
        rename = "Title",
        alias = "title",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub title: Option<Type2EncString>,

    #[serde(
        rename = "Company",
        alias = "company",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub company: Option<Type2EncString>,

    #[serde(
        rename = "Username",
        alias = "username",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub username: Option<Type2EncString>,

    #[serde(
        rename = "LicenseNumber",
        alias = "licenseNumber",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub license_number: Option<Type2EncString>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CipherSshKey {
    #[serde(
        rename = "KeyType",
        alias = "keyType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub key_type: Option<Type2EncString>,

    #[serde(
        rename = "Fingerprint",
        alias = "fingerprint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub fingerprint: Option<Type2EncString>,

    #[serde(
        rename = "PublicKey",
        alias = "publicKey",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub public_key: Option<Type2EncString>,

    #[serde(
        rename = "PrivateKey",
        alias = "privateKey",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub private_key: Option<Type2EncString>,

    #[serde(
        rename = "Comment",
        alias = "comment",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub comment: Option<Type2EncString>,

    #[serde(
        rename = "Passphrase",
        alias = "passphrase",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub passphrase: Option<Type2EncString>,
    #[serde(
        rename = "KeyFingerprint",
        alias = "keyFingerprint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub key_fingerprint: Option<Type2EncString>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    #[serde(rename = "Id", alias = "id")]
    pub id: String,

    #[serde(rename = "Name", alias = "name")]
    pub name: Type2EncString,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    #[serde(rename = "Id", alias = "id")]
    pub id: String,

    #[serde(rename = "Name", alias = "name", default)]
    pub name: Option<Type2EncString>,
}

#[derive(Debug, Clone, Default)]
pub struct Vault {
    pub ciphers: Vec<Cipher>,

    pub folders: Vec<Folder>,

    pub organizations: Vec<Organization>,
}

impl Vault {
    /// Replaces any cached copy of `saved` (matched by id) and appends it.
    pub fn upsert_cipher(&mut self, saved: Cipher) {
        if let Some(id) = &saved.id {
            self.ciphers
                .retain(|c| c.id.as_deref() != Some(id.as_str()));
        }
        self.ciphers.push(saved);
    }
}

pub async fn fetch_vault(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
) -> Result<Vault, SyncError> {
    let url = server.api(format_args!("/sync?excludeDomains=true"))?;
    let res = send(
        client,
        &url,
        Request::Get,
        &[("Authorization".into(), session.bearer())],
    )
    .await?;

    let payload: SyncResponse =
        serde_json::from_slice(&res.body).map_err(|e| SyncError::Parse(format!("sync: {e}")))?;
    let vault = Vault {
        ciphers: payload.ciphers.unwrap_or_default(),
        folders: payload.folders.unwrap_or_default(),
        organizations: payload
            .profile
            .and_then(|p| p.organizations)
            .unwrap_or_default(),
    };
    check_user_key(session, &vault)?;
    Ok(vault)
}

/// Fails when the vault has personal items (ciphers or folders) and not one
/// of their names decrypts: with the wrong key every item would otherwise be
/// skipped and the vault would just look empty. Organization ciphers are
/// under organization keys and are not evidence either way.
pub fn check_user_key(session: &Session, vault: &Vault) -> Result<(), SyncError> {
    let personal: Vec<&Cipher> = vault
        .ciphers
        .iter()
        .filter(|c| c.organization_id.is_none())
        .collect();
    let items = personal.len() + vault.folders.len();
    if items == 0 {
        return Ok(());
    }
    let user = ItemKeys::user(session)?;
    let any_cipher = personal.iter().any(|c| cipher_name(session, c).is_ok());
    let any_folder = vault.folders.iter().any(|f| user.decrypt(&f.name).is_ok());
    if any_cipher || any_folder {
        Ok(())
    } else {
        Err(SyncError::WrongUserKey { items })
    }
}

#[derive(Debug, Deserialize)]
struct SyncResponse {
    #[serde(rename = "Ciphers", alias = "ciphers")]
    ciphers: Option<Vec<Cipher>>,
    #[serde(rename = "Folders", alias = "folders")]
    folders: Option<Vec<Folder>>,
    #[serde(rename = "Profile", alias = "profile")]
    profile: Option<SyncProfile>,
}

#[derive(Debug, Deserialize)]
struct SyncProfile {
    #[serde(rename = "Organizations", alias = "organizations")]
    organizations: Option<Vec<Organization>>,
}

/// The body of a cipher create/update. A PUT replaces the whole server cipher,
/// so every field the server holds must be carried here or it is lost; build
/// updates with [`CipherIn::from_existing`] / [`edit_preserving`], never from
/// scratch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CipherIn {
    #[serde(rename = "type")]
    pub cipher_type: u8,

    pub name: Type2EncString,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<Type2EncString>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<CipherLogin>,

    #[serde(
        rename = "secureNote",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub secure_note: Option<SecureNote>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<CipherCard>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<CipherIdentity>,

    #[serde(rename = "sshKey", default, skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<CipherSshKey>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<CipherFieldIn>>,

    #[serde(rename = "folderId", default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,

    #[serde(
        rename = "organizationId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub organization_id: Option<String>,

    #[serde(default)]
    pub favorite: bool,

    #[serde(default, skip_serializing_if = "is_zero")]
    pub reprompt: u8,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<Type2EncString>,

    #[serde(
        rename = "passwordHistory",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub password_history: Option<Vec<serde_json::Value>>,
}

fn is_zero(v: &u8) -> bool {
    *v == 0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CipherFieldIn {
    pub name: Type2EncString,

    #[serde(default)]
    pub value: Option<Type2EncString>,

    #[serde(rename = "type")]
    pub field_type: u8,

    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl CipherIn {
    /// Every editable field of a server cipher, verbatim: what a PUT must
    /// carry so that nothing the caller did not mean to change is lost.
    pub fn from_existing(c: &Cipher) -> Self {
        Self {
            cipher_type: c.cipher_type,
            name: c.name.clone(),
            notes: c.notes.clone(),
            login: c.login.clone(),
            secure_note: c.secure_note.clone(),
            card: c.card.clone(),
            identity: c.identity.clone(),
            ssh_key: c.ssh_key.clone(),
            fields: c.fields.as_ref().map(|fs| {
                fs.iter()
                    .map(|f| CipherFieldIn {
                        name: f.name.clone(),
                        value: f.value.clone(),
                        field_type: f.field_type,
                        extra: f.extra.clone(),
                    })
                    .collect()
            }),
            folder_id: c.folder_id.clone(),
            organization_id: c.organization_id.clone(),
            favorite: c.favorite,
            reprompt: c.reprompt,
            key: c.key.clone(),
            password_history: c.password_history.clone(),
        }
    }
}

pub type CipherOut = Cipher;

/// A cipher body as it goes on the wire. Vaultwarden 1.37 (after Bitwarden's
/// web-v2025.6.0) refuses a create or update that does not name the user the
/// cipher is encrypted for, and one that names anyone but the caller; older
/// servers ignore the field.
#[derive(Serialize)]
struct CipherBody<'a> {
    #[serde(flatten)]
    cipher: &'a CipherIn,
    #[serde(rename = "encryptedFor")]
    encrypted_for: &'a str,
}

impl<'a> CipherBody<'a> {
    fn new(session: &'a Session, cipher: &'a CipherIn) -> Self {
        Self {
            cipher,
            encrypted_for: &session.user_id,
        }
    }
}

pub async fn create_cipher(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    cipher: &CipherIn,
) -> Result<CipherOut, SyncError> {
    let url = server.api(format_args!("/ciphers"))?;
    send_json(
        client,
        session,
        &url,
        Request::Post,
        &CipherBody::new(session, cipher),
        "cipher create",
    )
    .await
}

pub async fn update_cipher(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    cipher_id: &str,
    cipher: &CipherIn,
) -> Result<CipherOut, SyncError> {
    let url = server.api(format_args!("/ciphers/{cipher_id}"))?;
    send_json(
        client,
        session,
        &url,
        Request::Put,
        &CipherBody::new(session, cipher),
        "cipher update",
    )
    .await
}

/// Updates `existing` in place when there is one, otherwise creates the cipher.
pub async fn save_cipher(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    existing: Option<&Cipher>,
    cipher: &CipherIn,
) -> Result<CipherOut, SyncError> {
    match existing {
        Some(existing) => {
            let id = existing.id.as_deref().unwrap_or("");
            update_cipher(client, server, session, id, cipher).await
        }
        None => create_cipher(client, server, session, cipher).await,
    }
}

fn key32(k: &[u8], what: &str) -> Result<Zeroizing<[u8; 32]>, SyncError> {
    let mut out = Zeroizing::new([0u8; 32]);
    if k.len() != 32 {
        return Err(SyncError::Crypto(format!("{what} wrong length")));
    }
    out.copy_from_slice(k);
    Ok(out)
}

struct ItemKeys {
    enc: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

impl ItemKeys {
    fn user(session: &Session) -> Result<Self, SyncError> {
        Ok(Self {
            enc: key32(&session.user_enc_key, "user_enc_key")?,
            mac: key32(&session.user_mac_key, "user_mac_key")?,
        })
    }

    /// The keys a cipher's strings are encrypted under: its own cipher key
    /// (Bitwarden's per-item `key`, itself wrapped by the user key) when it
    /// has one, the user key otherwise.
    fn for_cipher(
        session: &Session,
        cipher_key: Option<&Type2EncString>,
    ) -> Result<Self, SyncError> {
        let user = Self::user(session)?;
        let Some(wrapped) = cipher_key else {
            return Ok(user);
        };
        let raw = bitwarden::decrypt_type2(wrapped.as_str(), &user.enc, &user.mac)
            .map_err(|e| SyncError::Crypto(format!("unwrap cipher key: {e}")))?;
        if raw.len() != 64 {
            return Err(SyncError::Crypto(format!(
                "cipher key has wrong length {} (expected 64)",
                raw.len()
            )));
        }
        Ok(Self {
            enc: key32(&raw[..32], "cipher enc key")?,
            mac: key32(&raw[32..], "cipher mac key")?,
        })
    }

    fn encrypt(&self, s: &str) -> Type2EncString {
        Type2EncString::from_trusted(bitwarden::encrypt_type2(s.as_bytes(), &self.enc, &self.mac))
    }

    fn decrypt(&self, ct: &Type2EncString) -> Result<String, SyncError> {
        self.decrypt_secret(ct).map(|s| s.as_str().to_owned())
    }

    fn decrypt_secret(&self, ct: &Type2EncString) -> Result<Zeroizing<String>, SyncError> {
        let mut bytes = bitwarden::decrypt_type2(ct.as_str(), &self.enc, &self.mac)
            .map_err(|e| SyncError::Crypto(format!("decrypt: {e}")))?;
        std::str::from_utf8(&bytes).map_err(|e| SyncError::Crypto(format!("non-utf8: {e}")))?;
        let owned = std::mem::take(&mut *bytes);
        Ok(Zeroizing::new(
            String::from_utf8(owned).expect("validated as UTF-8 above"),
        ))
    }
}

pub fn encrypt_string(session: &Session, s: &str) -> Result<Type2EncString, SyncError> {
    Ok(ItemKeys::user(session)?.encrypt(s))
}

pub fn decrypt_string(session: &Session, ct: &Type2EncString) -> Result<String, SyncError> {
    ItemKeys::user(session)?.decrypt(ct)
}

/// [`decrypt_string`] for secret fields (login passwords, notes, TOTP seeds):
/// the plaintext never leaves zeroizing memory.
pub fn decrypt_string_secret(
    session: &Session,
    ct: &Type2EncString,
) -> Result<Zeroizing<String>, SyncError> {
    ItemKeys::user(session)?.decrypt_secret(ct)
}

/// [`decrypt_string`] for a string inside `cipher`: honours the cipher's own
/// key, which current Bitwarden clients set on every item they create.
pub fn decrypt_cipher_string(
    session: &Session,
    cipher: &Cipher,
    ct: &Type2EncString,
) -> Result<String, SyncError> {
    ItemKeys::for_cipher(session, cipher.key.as_ref())?.decrypt(ct)
}

pub const CIPHER_TYPE_LOGIN: u8 = crate::protected::TYPE_LOGIN;

pub const CIPHER_TYPE_SECURE_NOTE: u8 = crate::protected::TYPE_SECURE_NOTE;

pub const CIPHER_TYPE_CARD: u8 = crate::protected::TYPE_CARD;

pub const CIPHER_TYPE_IDENTITY: u8 = crate::protected::TYPE_IDENTITY;

pub const CIPHER_TYPE_SSH_KEY: u8 = crate::protected::TYPE_SSH_KEY;

/// The plaintext fields of a card block, by their Bitwarden names.
pub const CARD_FIELDS: &[&str] = &[
    "cardholderName",
    "brand",
    "number",
    "expMonth",
    "expYear",
    "code",
];

/// The plaintext fields of an identity block, by their Bitwarden names.
pub const IDENTITY_FIELDS: &[&str] = &[
    "title",
    "firstName",
    "middleName",
    "lastName",
    "address1",
    "address2",
    "address3",
    "city",
    "state",
    "postalCode",
    "country",
    "company",
    "email",
    "phone",
    "ssn",
    "username",
    "passportNumber",
    "licenseNumber",
];

/// The plaintext fields of an SSH key block, by their Bitwarden names.
pub const SSH_KEY_FIELDS: &[&str] = &["privateKey", "publicKey", "keyFingerprint"];

/// The custom field naming what a v2 rage blob protects (JSON array of
/// field names, under the user key). Absent: the item's primary field only.
pub const RAGE_FIELDS_NAME: &str = "rage:fields";

/// A new item: a login when `login` is set, a card, identity or SSH key when
/// that block is given (camelCase Bitwarden field names to plaintext), a
/// secure note otherwise. `protected_fields` names what the rage blob passed
/// alongside it holds; those fields are left out of the Type-2 layer.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CipherDraft {
    pub login: bool,
    pub name: String,
    pub notes: Option<String>,
    pub username: Option<String>,
    pub uris: Vec<String>,
    pub totp: Option<String>,
    /// Only for an item without a rage blob; a protected item's secret lives
    /// in the blob, never in the Type-2 password.
    pub password: Option<String>,
    pub card: Option<BTreeMap<String, String>>,
    pub identity: Option<BTreeMap<String, String>>,
    pub ssh_key: Option<BTreeMap<String, String>>,
    pub protected_fields: Vec<String>,
    pub folder_id: Option<String>,
    pub favorite: bool,
}

/// Changes to an existing item; `None` keeps the server's value and an empty
/// string clears an optional text field.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CipherEdit {
    pub name: Option<String>,
    pub notes: Option<String>,
    pub username: Option<String>,
    pub uris: Option<Vec<String>>,
    pub totp: Option<String>,
    /// A new Type-2 password for an unprotected login; the old one moves to
    /// the password history, as other Bitwarden clients do.
    pub password: Option<String>,
    /// Card, identity or SSH key fields to set (camelCase Bitwarden names); an
    /// empty value clears one. Giving a block to a secure note turns it into
    /// that type.
    pub card: Option<BTreeMap<String, String>>,
    pub identity: Option<BTreeMap<String, String>>,
    pub ssh_key: Option<BTreeMap<String, String>>,
    /// What the rage blob passed alongside holds, when it changes; `None`
    /// keeps the item's current list (a rotation re-wraps the same fields).
    pub protected_fields: Option<Vec<String>>,
    pub folder_id: Option<String>,
    pub clear_folder: bool,
    pub favorite: Option<bool>,
}

impl CipherDraft {
    /// The Bitwarden type this draft builds.
    pub fn cipher_type(&self) -> u8 {
        if self.card.is_some() {
            CIPHER_TYPE_CARD
        } else if self.identity.is_some() {
            CIPHER_TYPE_IDENTITY
        } else if self.ssh_key.is_some() {
            CIPHER_TYPE_SSH_KEY
        } else if self.login {
            CIPHER_TYPE_LOGIN
        } else {
            CIPHER_TYPE_SECURE_NOTE
        }
    }
}

const PASSWORD_HISTORY_MAX: usize = 5;

fn block_fields(cipher_type: u8) -> &'static [&'static str] {
    match cipher_type {
        CIPHER_TYPE_CARD => CARD_FIELDS,
        CIPHER_TYPE_IDENTITY => IDENTITY_FIELDS,
        CIPHER_TYPE_SSH_KEY => SSH_KEY_FIELDS,
        _ => &[],
    }
}

fn pascal(name: &str) -> String {
    let mut c = name.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

fn block_value(c: &CipherIn) -> Result<serde_json::Value, SyncError> {
    let v = match c.cipher_type {
        CIPHER_TYPE_CARD => serde_json::to_value(&c.card),
        CIPHER_TYPE_IDENTITY => serde_json::to_value(&c.identity),
        CIPHER_TYPE_SSH_KEY => serde_json::to_value(&c.ssh_key),
        _ => return Ok(serde_json::Value::Null),
    };
    let v = v.map_err(|e| SyncError::Parse(e.to_string()))?;
    Ok(if v.is_null() {
        serde_json::json!({})
    } else {
        v
    })
}

fn set_block_value(c: &mut CipherIn, v: serde_json::Value) -> Result<(), SyncError> {
    let parse = |e: serde_json::Error| SyncError::Parse(format!("cipher block: {e}"));
    match c.cipher_type {
        CIPHER_TYPE_CARD => c.card = Some(serde_json::from_value(v).map_err(parse)?),
        CIPHER_TYPE_IDENTITY => c.identity = Some(serde_json::from_value(v).map_err(parse)?),
        CIPHER_TYPE_SSH_KEY => c.ssh_key = Some(serde_json::from_value(v).map_err(parse)?),
        _ => {}
    }
    Ok(())
}

/// Sets (or, for an empty value, removes) `values` in `c`'s typed block.
fn apply_block(
    keys: &ItemKeys,
    c: &mut CipherIn,
    values: &BTreeMap<String, String>,
) -> Result<(), SyncError> {
    let allowed = block_fields(c.cipher_type);
    let mut block = block_value(c)?;
    let obj = block
        .as_object_mut()
        .ok_or_else(|| SyncError::Parse("cipher block is not an object".into()))?;
    for (name, value) in values {
        if !allowed.contains(&name.as_str()) {
            return Err(SyncError::State(format!(
                "`{name}` is not a field of a cipher of type {}",
                c.cipher_type
            )));
        }
        let key = pascal(name);
        obj.remove(name);
        if value.is_empty() {
            obj.remove(&key);
        } else {
            obj.insert(key, serde_json::json!(keys.encrypt(value)));
        }
    }
    set_block_value(c, block)
}

type BlockValues = BTreeMap<String, String>;

fn requested_block(
    card: &Option<BlockValues>,
    identity: &Option<BlockValues>,
    ssh_key: &Option<BlockValues>,
) -> Result<Option<(u8, BlockValues)>, SyncError> {
    let given: Vec<(u8, &BTreeMap<String, String>)> = [
        (CIPHER_TYPE_CARD, card),
        (CIPHER_TYPE_IDENTITY, identity),
        (CIPHER_TYPE_SSH_KEY, ssh_key),
    ]
    .into_iter()
    .filter_map(|(t, b)| b.as_ref().map(|b| (t, b)))
    .collect();
    match given.as_slice() {
        [] => Ok(None),
        [(t, b)] => Ok(Some((*t, (*b).clone()))),
        _ => Err(SyncError::State(
            "an item is one of login, card, identity or SSH key".into(),
        )),
    }
}

/// Records which fields the rage blob holds and takes them out of the Type-2
/// layer, so a protected value is never also readable without the tap. An SSH
/// key's private key, public key and fingerprint are mandatory to Bitwarden
/// (Vaultwarden drops the block, and mobile clients crash, without them), so
/// a protected one keeps the marker text in its place.
fn set_protected_fields(
    keys: &ItemKeys,
    c: &mut CipherIn,
    names: &[String],
) -> Result<(), SyncError> {
    let primary = crate::protected::primary_field(c.cipher_type);
    let canonical: Vec<String> = names
        .iter()
        .map(|n| crate::protected::canonical_field(c.cipher_type, n))
        .collect();
    let block_names = block_fields(c.cipher_type);
    let builtin = |n: &str| {
        n == "notes"
            || block_names.contains(&n)
            || (c.cipher_type == CIPHER_TYPE_LOGIN && ["password", "username", "totp"].contains(&n))
    };
    let custom_protected: Vec<&String> = canonical.iter().filter(|n| !builtin(n)).collect();
    let fields = c.fields.get_or_insert_with(Vec::new);
    let mut kept = Vec::with_capacity(fields.len());
    for f in fields.drain(..) {
        let name = keys.decrypt(&f.name)?;
        let is_marker = name == RAGE_FIELDS_NAME;
        let protected_custom = name != RAGE_FIELD_NAME && custom_protected.contains(&&name);
        if !is_marker && !protected_custom {
            kept.push(f);
        }
    }
    *fields = kept;
    if canonical.iter().any(|n| n != primary) {
        let list =
            serde_json::to_string(&canonical).map_err(|e| SyncError::Parse(e.to_string()))?;
        fields.push(CipherFieldIn {
            name: keys.encrypt(RAGE_FIELDS_NAME),
            value: Some(keys.encrypt(&list)),
            field_type: 1,
            extra: BTreeMap::new(),
        });
    }

    let mut block = block_value(c)?;
    for name in &canonical {
        match name.as_str() {
            "password" | "totp" if c.cipher_type == CIPHER_TYPE_LOGIN => {
                if let Some(login) = c.login.as_mut() {
                    if name == "password" {
                        login.password = None;
                    } else {
                        login.totp = None;
                    }
                }
            }
            "notes" => c.notes = Some(keys.encrypt(RAGE_MARKER_NOTE)),
            n if block_names.contains(&n) => {
                if let Some(obj) = block.as_object_mut() {
                    obj.remove(n);
                    if c.cipher_type == CIPHER_TYPE_SSH_KEY {
                        obj.insert(pascal(n), serde_json::json!(keys.encrypt(RAGE_MARKER_NOTE)));
                    } else {
                        obj.remove(&pascal(n));
                    }
                }
            }
            _ => {}
        }
    }
    if !block_names.is_empty() {
        set_block_value(c, block)?;
    }
    Ok(())
}

/// What `cipher`'s rage blob holds: the names its `rage:fields` marker lists,
/// or the type's primary field for a blob written before markers existed.
/// Empty when the item has no rage blob.
pub fn protected_field_names(session: &Session, cipher: &Cipher) -> Result<Vec<String>, SyncError> {
    let Some(fields) = &cipher.fields else {
        return Ok(Vec::new());
    };
    if cipher.organization_id.is_some() {
        return Ok(Vec::new());
    }
    let keys = ItemKeys::for_cipher(session, cipher.key.as_ref())?;
    let mut has_blob = false;
    let mut listed = None;
    for f in fields {
        match keys.decrypt(&f.name)?.as_str() {
            RAGE_FIELD_NAME => has_blob = true,
            RAGE_FIELDS_NAME => {
                let json = f.value.as_ref().map(|v| keys.decrypt(v)).transpose()?;
                listed = Some(
                    serde_json::from_str::<Vec<String>>(json.as_deref().unwrap_or("[]"))
                        .map_err(|e| SyncError::Parse(format!("{RAGE_FIELDS_NAME}: {e}")))?,
                );
            }
            _ => {}
        }
    }
    if !has_blob {
        return Ok(Vec::new());
    }
    Ok(listed
        .unwrap_or_else(|| vec![crate::protected::primary_field(cipher.cipher_type).to_string()]))
}

/// Whether reading `requested` (see [`crate::protected::canonical_field`];
/// [`crate::protected::WHOLE_PAYLOAD`] asks for the whole blob) takes
/// `cipher`'s rage blob, and so a tap.
pub fn protects_field(
    session: &Session,
    cipher: &Cipher,
    requested: &str,
) -> Result<bool, SyncError> {
    if requested == crate::protected::WHOLE_PAYLOAD {
        return Ok(!protected_field_names(session, cipher)?.is_empty());
    }
    let name = crate::protected::canonical_field(cipher.cipher_type, requested);
    Ok(protected_field_names(session, cipher)?.contains(&name))
}

/// The Type-2 value of an unprotected field: a login's password, username or
/// TOTP, the notes, a card/identity/SSH key block field, or a custom field by
/// name. `None` when the item has no such field.
pub fn outer_field(
    session: &Session,
    cipher: &Cipher,
    requested: &str,
) -> Result<Option<String>, SyncError> {
    let keys = ItemKeys::for_cipher(session, cipher.key.as_ref())?;
    let name = crate::protected::canonical_field(cipher.cipher_type, requested);
    let login = cipher.login.as_ref();
    let ct = match name.as_str() {
        "notes" => cipher.notes.clone(),
        "password" if cipher.cipher_type == CIPHER_TYPE_LOGIN => {
            login.and_then(|l| l.password.clone())
        }
        "username" if cipher.cipher_type == CIPHER_TYPE_LOGIN => {
            login.and_then(|l| l.username.clone())
        }
        "totp" if cipher.cipher_type == CIPHER_TYPE_LOGIN => login.and_then(|l| l.totp.clone()),
        n if block_fields(cipher.cipher_type).contains(&n) => {
            let c = CipherIn::from_existing(cipher);
            block_value(&c)?
                .get(pascal(n))
                .and_then(|v| v.as_str())
                .map(|s| Type2EncString::from_trusted(s.to_string()))
        }
        n => {
            let mut found = None;
            for f in cipher.fields.iter().flatten() {
                let fname = keys.decrypt(&f.name)?;
                if fname == n && fname != RAGE_FIELD_NAME && fname != RAGE_FIELDS_NAME {
                    found = f.value.clone();
                    break;
                }
            }
            found
        }
    };
    Ok(ct
        .map(|c| keys.decrypt(&c))
        .transpose()?
        .filter(|v| v != RAGE_MARKER_NOTE))
}

fn optional_text(keys: &ItemKeys, s: &str) -> Option<Type2EncString> {
    (!s.is_empty()).then(|| keys.encrypt(s))
}

/// Builds a new item: a login keeps its username, URIs and TOTP; with a rage
/// blob the secret lives in the `rage:v1` field and the Type-2 password stays
/// empty.
pub fn build_cipher(
    session: &Session,
    draft: &CipherDraft,
    rage_blob: Option<&str>,
) -> Result<CipherIn, SyncError> {
    if rage_blob.is_some() && draft.password.is_some() {
        return Err(SyncError::State(
            "a protected item keeps its secret in the rage blob, not a Type-2 password".into(),
        ));
    }
    if !draft.login
        && (draft.username.is_some()
            || !draft.uris.is_empty()
            || draft.totp.is_some()
            || draft.password.is_some())
    {
        return Err(SyncError::State(
            "username, URIs, TOTP and password belong to a login item".into(),
        ));
    }
    let block = requested_block(&draft.card, &draft.identity, &draft.ssh_key)?;
    if draft.login && block.is_some() {
        return Err(SyncError::State(
            "an item is one of login, card, identity or SSH key".into(),
        ));
    }
    if rage_blob.is_none() && !draft.protected_fields.is_empty() {
        return Err(SyncError::State(
            "protected_fields names what a rage blob holds; none was given".into(),
        ));
    }
    let keys = ItemKeys::user(session)?;
    let mut notes = draft.notes.as_deref().and_then(|n| optional_text(&keys, n));
    if notes.is_none() && rage_blob.is_some() {
        notes = Some(keys.encrypt(RAGE_MARKER_NOTE));
    }
    let login = draft.login.then(|| CipherLogin {
        username: draft
            .username
            .as_deref()
            .and_then(|u| optional_text(&keys, u)),
        password: draft
            .password
            .as_deref()
            .and_then(|p| optional_text(&keys, p)),
        totp: draft.totp.as_deref().and_then(|t| optional_text(&keys, t)),
        uris: (!draft.uris.is_empty()).then(|| {
            draft
                .uris
                .iter()
                .map(|u| CipherUri {
                    uri: keys.encrypt(u),
                    match_type: None,
                    extra: BTreeMap::new(),
                })
                .collect()
        }),
        extra: BTreeMap::new(),
    });
    let cipher_type = match (&block, draft.login) {
        (Some((t, _)), _) => *t,
        (None, true) => CIPHER_TYPE_LOGIN,
        (None, false) => CIPHER_TYPE_SECURE_NOTE,
    };
    let mut c = CipherIn {
        cipher_type,
        name: keys.encrypt(&draft.name),
        notes,
        login,
        secure_note: (cipher_type == CIPHER_TYPE_SECURE_NOTE)
            .then_some(SecureNote { note_type: 0 }),
        fields: rage_blob.map(|blob| vec![rage_field(&keys, blob)]),
        folder_id: draft.folder_id.clone(),
        favorite: draft.favorite,
        ..CipherIn::default()
    };
    if let Some((_, values)) = &block {
        apply_block(&keys, &mut c, values)?;
    }
    if rage_blob.is_some() && !draft.protected_fields.is_empty() {
        set_protected_fields(&keys, &mut c, &draft.protected_fields)?;
    }
    Ok(c)
}

fn rage_field(keys: &ItemKeys, blob: &str) -> CipherFieldIn {
    CipherFieldIn {
        name: keys.encrypt(RAGE_FIELD_NAME),
        value: Some(keys.encrypt(blob)),
        field_type: 1,
        extra: BTreeMap::new(),
    }
}

/// `existing` with `edit` applied and, when `rage_blob` is given, its
/// `rage:v1` field set to it. Everything else -- type, login block, URIs and
/// their match rules, TOTP, notes, card/identity/SSH payloads, other custom
/// fields, folder, favourite, reprompt, cipher key, password history -- is
/// carried over unchanged. Protecting a login empties its Type-2 password.
pub fn edit_preserving(
    session: &Session,
    existing: &Cipher,
    rage_blob: Option<&str>,
    edit: &CipherEdit,
) -> Result<CipherIn, SyncError> {
    if rage_blob.is_some() && edit.password.is_some() {
        return Err(SyncError::State(
            "a protected item keeps its secret in the rage blob, not a Type-2 password".into(),
        ));
    }
    let keys = ItemKeys::for_cipher(session, existing.key.as_ref())?;
    let mut c = CipherIn::from_existing(existing);

    if let Some(name) = &edit.name {
        c.name = keys.encrypt(name);
    }
    if let Some(notes) = &edit.notes {
        c.notes = optional_text(&keys, notes);
    }

    let touches_login = edit.username.is_some()
        || edit.uris.is_some()
        || edit.totp.is_some()
        || edit.password.is_some();
    if touches_login {
        if c.cipher_type == CIPHER_TYPE_SECURE_NOTE {
            c.cipher_type = CIPHER_TYPE_LOGIN;
            c.secure_note = None;
        }
        if c.cipher_type != CIPHER_TYPE_LOGIN {
            return Err(SyncError::State(
                "username, URIs, TOTP and password belong to a login item".into(),
            ));
        }
        let login = c.login.get_or_insert_with(CipherLogin::default);
        if let Some(u) = &edit.username {
            login.username = optional_text(&keys, u);
        }
        if let Some(t) = &edit.totp {
            login.totp = optional_text(&keys, t);
        }
        if let Some(wanted) = &edit.uris {
            let mut kept: Vec<(String, CipherUri)> = Vec::new();
            for uri in login.uris.take().unwrap_or_default() {
                kept.push((keys.decrypt(&uri.uri)?, uri));
            }
            login.uris = (!wanted.is_empty()).then(|| {
                wanted
                    .iter()
                    .map(|w| match kept.iter().position(|(plain, _)| plain == w) {
                        Some(i) => kept.remove(i).1,
                        None => CipherUri {
                            uri: keys.encrypt(w),
                            match_type: None,
                            extra: BTreeMap::new(),
                        },
                    })
                    .collect()
            });
        }
        if let Some(p) = &edit.password {
            let old = login.password.take();
            login.password = optional_text(&keys, p);
            if let Some(old) = old {
                let changed = match &login.password {
                    Some(new) => keys.decrypt(&old)? != keys.decrypt(new)?,
                    None => true,
                };
                if changed {
                    let history = c.password_history.get_or_insert_with(Vec::new);
                    history.insert(
                        0,
                        serde_json::json!({
                            "password": old.as_str(),
                            "lastUsedDate": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        }),
                    );
                    history.truncate(PASSWORD_HISTORY_MAX);
                }
            }
        }
    }

    if let Some((t, values)) = requested_block(&edit.card, &edit.identity, &edit.ssh_key)? {
        if c.cipher_type == CIPHER_TYPE_SECURE_NOTE {
            c.cipher_type = t;
            c.secure_note = None;
        }
        if c.cipher_type != t {
            return Err(SyncError::State(format!(
                "a cipher of type {} has no type-{t} block",
                c.cipher_type
            )));
        }
        apply_block(&keys, &mut c, &values)?;
    }

    if edit.clear_folder {
        c.folder_id = None;
    } else if let Some(folder) = &edit.folder_id {
        c.folder_id = Some(folder.clone());
    }
    if let Some(fav) = edit.favorite {
        c.favorite = fav;
    }

    if rage_blob.is_none() && edit.protected_fields.is_some() {
        return Err(SyncError::State(
            "protected_fields names what a rage blob holds; none was given".into(),
        ));
    }
    if let Some(blob) = rage_blob {
        set_rage_field(&keys, &mut c, blob)?;
        if let Some(login) = c.login.as_mut() {
            if c.cipher_type == CIPHER_TYPE_LOGIN && edit.protected_fields.is_none() {
                login.password = None;
            }
        }
        if c.notes.is_none() {
            c.notes = Some(keys.encrypt(RAGE_MARKER_NOTE));
        }
        if let Some(names) = &edit.protected_fields {
            set_protected_fields(&keys, &mut c, names)?;
        }
    }
    Ok(c)
}

/// Applies `incoming` -- a cipher body built from nothing, as older client paths
/// do -- to the server's current `existing` as edits, so it cannot drop what
/// it does not carry. Its name, a note other than the default marker, a folder
/// it names, the login fields it holds and its rage blob replace the server's;
/// favourite, the rest of the login block, other fields and everything else
/// stay as the server has them.
pub fn overlay_preserving(
    session: &Session,
    existing: &Cipher,
    incoming: &CipherIn,
) -> Result<CipherIn, SyncError> {
    let user = ItemKeys::user(session)?;
    let open = |ct: &Option<Type2EncString>| -> Result<Option<String>, SyncError> {
        ct.as_ref().map(|c| user.decrypt(c)).transpose()
    };
    let mut blob = None;
    for f in incoming.fields.iter().flatten() {
        if user.decrypt(&f.name)? == RAGE_FIELD_NAME {
            blob = open(&f.value)?;
        }
    }
    let notes = open(&incoming.notes)?.filter(|n| n != RAGE_MARKER_NOTE);
    let mut edit = CipherEdit {
        name: Some(user.decrypt(&incoming.name)?),
        notes,
        folder_id: incoming.folder_id.clone(),
        ..CipherEdit::default()
    };
    if let Some(login) = &incoming.login {
        edit.username = open(&login.username)?;
        edit.totp = open(&login.totp)?;
        if blob.is_none() {
            edit.password = open(&login.password)?;
        }
        if let Some(uris) = &login.uris {
            edit.uris = Some(
                uris.iter()
                    .map(|u| user.decrypt(&u.uri))
                    .collect::<Result<_, _>>()?,
            );
        }
    }
    edit_preserving(session, existing, blob.as_deref(), &edit)
}

/// [`edit_preserving`] with no edits: re-wrap (protect, rotate, restrict) one
/// item without losing anything else on it.
pub fn rewrap_preserving(
    session: &Session,
    existing: &Cipher,
    rage_blob: &str,
) -> Result<CipherIn, SyncError> {
    edit_preserving(session, existing, Some(rage_blob), &CipherEdit::default())
}

fn set_rage_field(keys: &ItemKeys, c: &mut CipherIn, blob: &str) -> Result<(), SyncError> {
    let fields = c.fields.get_or_insert_with(Vec::new);
    let mut slot = None;
    let mut i = 0;
    while i < fields.len() {
        if keys.decrypt(&fields[i].name)? == RAGE_FIELD_NAME {
            if slot.is_none() {
                slot = Some(i);
                i += 1;
            } else {
                fields.remove(i);
            }
        } else {
            i += 1;
        }
    }
    match slot {
        Some(i) => fields[i].value = Some(keys.encrypt(blob)),
        None => fields.push(rage_field(keys, blob)),
    }
    Ok(())
}

/// One cipher as the server holds it now.
pub async fn get_cipher(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    cipher_id: &str,
) -> Result<Cipher, SyncError> {
    let url = server.api(format_args!("/ciphers/{cipher_id}"))?;
    let res = send(
        client,
        &url,
        Request::Get,
        &[("Authorization".into(), session.bearer())],
    )
    .await?;
    serde_json::from_slice(&res.body).map_err(|e| SyncError::Parse(format!("cipher: {e}")))
}

/// Read-modify-write of one cipher against the server's current copy, so a
/// stale local cache cannot drop fields another client added.
pub async fn update_preserving(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    cipher_id: &str,
    rage_blob: Option<&str>,
    edit: &CipherEdit,
) -> Result<Cipher, SyncError> {
    let existing = get_cipher(client, server, session, cipher_id).await?;
    let cipher_in = edit_preserving(session, &existing, rage_blob, edit)?;
    update_cipher(client, server, session, cipher_id, &cipher_in).await
}

/// A new secure note holding `rage_blob`. For an item that already exists use
/// [`rewrap_preserving`] / [`update_preserving`]: this builds from nothing.
pub fn build_rage_cipher(
    session: &Session,
    name: &str,
    rage_blob: &str,
) -> Result<CipherIn, SyncError> {
    build_rage_cipher_in_folder(session, name, rage_blob, None)
}

/// [`build_rage_cipher`] in a folder.
pub fn build_rage_cipher_in_folder(
    session: &Session,
    name: &str,
    rage_blob: &str,
    folder_id: Option<&str>,
) -> Result<CipherIn, SyncError> {
    build_cipher(
        session,
        &CipherDraft {
            name: name.to_string(),
            folder_id: folder_id.map(String::from),
            ..CipherDraft::default()
        },
        Some(rage_blob),
    )
}

pub const RAGE_FIELD_NAME: &str = "rage:v1";

pub const RAGE_MARKER_NOTE: &str = "\u{26d3} Protected with Ragewarden";

pub const RECIPIENTS_META_CIPHER_NAME: &str = "__ragedroid_recipients_v1__";

pub fn build_meta_cipher(
    session: &Session,
    name: &str,
    notes: &str,
) -> Result<CipherIn, SyncError> {
    Ok(CipherIn {
        cipher_type: CIPHER_TYPE_SECURE_NOTE,
        name: encrypt_string(session, name)?,
        notes: Some(encrypt_string(session, notes)?),
        secure_note: Some(SecureNote { note_type: 0 }),
        ..CipherIn::default()
    })
}

pub fn cipher_name(session: &Session, cipher: &Cipher) -> Result<String, SyncError> {
    decrypt_cipher_string(session, cipher, &cipher.name)
}

pub fn extract_rage_blob(session: &Session, cipher: &Cipher) -> Result<Option<String>, SyncError> {
    let Some(fields) = &cipher.fields else {
        return Ok(None);
    };
    if cipher.organization_id.is_some() {
        return Ok(None);
    }
    let keys = ItemKeys::for_cipher(session, cipher.key.as_ref())?;
    for f in fields {
        let plaintext_name = keys.decrypt(&f.name)?;
        if plaintext_name == RAGE_FIELD_NAME {
            let Some(val) = &f.value else { return Ok(None) };
            return Ok(Some(keys.decrypt(val)?));
        }
    }
    Ok(None)
}

pub fn name_index(session: &Session, vault: &Vault) -> BTreeMap<String, Cipher> {
    let mut out = BTreeMap::new();
    for c in &vault.ciphers {
        if let Ok(name) = cipher_name(session, c) {
            out.entry(name).or_insert_with(|| c.clone());
        }
    }
    out
}

const SERVER_ERROR_BODY_MAX: usize = 4096;

fn server_err(res: &HttpResponse) -> SyncError {
    let head = &res.body[..res.body.len().min(SERVER_ERROR_BODY_MAX)];
    let mut body = String::from_utf8_lossy(head).into_owned();
    if res.body.len() > SERVER_ERROR_BODY_MAX {
        body.push_str("... <truncated>");
    }
    SyncError::Server {
        status: res.status,
        body,
    }
}

impl fmt::Display for HttpBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpBody::Json(b) => write!(f, "Json({} bytes)", b.len()),
            HttpBody::Form(b) => write!(f, "Form({} bytes)", b.len()),
        }
    }
}

#[derive(Debug, Serialize)]
struct FolderRequest {
    name: Type2EncString,
}

async fn send_json<T: for<'de> Deserialize<'de>>(
    client: &dyn HttpClient,
    session: &Session,
    url: &SecureUrl,
    make_req: fn(HttpBody) -> Request,
    body: &impl Serialize,
    what: &str,
) -> Result<T, SyncError> {
    let body = serde_json::to_vec(body).map_err(|e| SyncError::Parse(e.to_string()))?;
    let res = send(
        client,
        url,
        make_req(HttpBody::Json(body)),
        &[("Authorization".into(), session.bearer())],
    )
    .await?;
    serde_json::from_slice(&res.body).map_err(|e| SyncError::Parse(format!("{what}: {e}")))
}

pub async fn create_folder(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    name: &str,
) -> Result<Folder, SyncError> {
    let url = server.api(format_args!("/folders"))?;
    let enc_name = encrypt_string(session, name)?;
    send_json(
        client,
        session,
        &url,
        Request::Post,
        &FolderRequest { name: enc_name },
        "folder create",
    )
    .await
}

pub async fn update_folder(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    folder_id: &str,
    name: &str,
) -> Result<Folder, SyncError> {
    let url = server.api(format_args!("/folders/{folder_id}"))?;
    let enc_name = encrypt_string(session, name)?;
    send_json(
        client,
        session,
        &url,
        Request::Put,
        &FolderRequest { name: enc_name },
        "folder update",
    )
    .await
}

async fn delete_by_path(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    path: fmt::Arguments<'_>,
) -> Result<(), SyncError> {
    let url = server.api(path)?;
    send(
        client,
        &url,
        Request::Delete,
        &[("Authorization".into(), session.bearer())],
    )
    .await?;
    Ok(())
}

pub async fn delete_folder(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    folder_id: &str,
) -> Result<(), SyncError> {
    delete_by_path(
        client,
        server,
        session,
        format_args!("/folders/{folder_id}"),
    )
    .await
}

pub async fn delete_cipher(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    cipher_id: &str,
) -> Result<(), SyncError> {
    delete_by_path(
        client,
        server,
        session,
        format_args!("/ciphers/{cipher_id}"),
    )
    .await
}

#[derive(Debug, Serialize)]
struct PartialCipherRequest<'a> {
    #[serde(rename = "folderId")]
    folder_id: Option<&'a str>,
    favorite: bool,
}

/// Reassigns a cipher's folder (`None` clears it) without touching any
/// encrypted field, so callers need not decrypt-then-re-encrypt. `server_url`
/// is the API base URL ([`Server::api_url`]), for callers that track an
/// api-only base and have no full [`Server`].
///
/// Because there is no [`Server`] here, only the URLs this call dials are
/// validated -- via [`SecureUrl::parse`], which is the same predicate
/// [`Server::require_secure`] applies. Callers holding a full [`Server`]
/// should prefer [`set_folder_on`], which validates both of its URLs.
pub async fn set_folder<C: HttpClient + ?Sized>(
    client: &C,
    server_url: &str,
    session: &Session,
    cipher_id: &str,
    folder_id: Option<&str>,
) -> Result<Cipher, SyncError> {
    let base = server_url.trim_end_matches('/');
    let cipher = SecureUrl::parse(format!("{base}/ciphers/{cipher_id}"))?;
    let partial = SecureUrl::parse(format!("{base}/ciphers/{cipher_id}/partial"))?;
    set_folder_at(client, &cipher, &partial, session, folder_id).await
}

/// [`set_folder`] for callers that hold a full [`Server`]; validates both the
/// api and identity URLs, exactly as every other `&Server` entry point does.
pub async fn set_folder_on<C: HttpClient + ?Sized>(
    client: &C,
    server: &Server,
    session: &Session,
    cipher_id: &str,
    folder_id: Option<&str>,
) -> Result<Cipher, SyncError> {
    let cipher = server.api(format_args!("/ciphers/{cipher_id}"))?;
    let partial = server.api(format_args!("/ciphers/{cipher_id}/partial"))?;
    set_folder_at(client, &cipher, &partial, session, folder_id).await
}

/// `PUT /ciphers/{id}/partial` -- the endpoint Bitwarden and Vaultwarden
/// serve for folder and favourite -- sets both, so the cipher's current
/// favourite is read first and sent back unchanged.
async fn set_folder_at<C: HttpClient + ?Sized>(
    client: &C,
    cipher_url: &SecureUrl,
    partial_url: &SecureUrl,
    session: &Session,
    folder_id: Option<&str>,
) -> Result<Cipher, SyncError> {
    let auth = [("Authorization".to_string(), session.bearer())];
    let current = send(client, cipher_url, Request::Get, &auth).await?;
    let current: Cipher = serde_json::from_slice(&current.body)
        .map_err(|e| SyncError::Parse(format!("set_folder: {e}")))?;
    let body = serde_json::to_vec(&PartialCipherRequest {
        folder_id,
        favorite: current.favorite,
    })
    .map_err(|e| SyncError::Parse(e.to_string()))?;
    let res = send(
        client,
        partial_url,
        Request::Put(HttpBody::Json(body)),
        &auth,
    )
    .await?;
    serde_json::from_slice(&res.body).map_err(|e| SyncError::Parse(format!("set_folder: {e}")))
}
