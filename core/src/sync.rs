use std::collections::BTreeMap;
use std::fmt;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::bitwarden::{
    self, decrypt_type2, derive_master_key, make_rsa_keypair_for_registration, make_user_key,
    master_password_hash, stretch_master_key, KDF_ITERATIONS_DEFAULT, KDF_ITERATIONS_MIN,
    KDF_ITERATIONS_MIN_NEW_ACCOUNT, KDF_PBKDF2,
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
        "server requires KDF type {got}, which this client cannot derive \
         (only {supported} = PBKDF2-SHA256 is implemented)"
    )]
    UnsupportedKdfType { got: u32, supported: u32 },

    #[error(
        "server asked for {got} KDF iterations but this account used {pinned} the last time \
         it was seen; a server that lowers this is trying to weaken your master password"
    )]
    KdfIterationsDowngraded { got: u32, pinned: u32 },
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

    use super::{is_secure_url, ServerInsecureError};

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

    pub kdf_iterations: u32,

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

/// Rejects a count lower than one previously observed for the same account.
///
/// The floor in [`check_kdf_iterations`] cannot see a downgrade that stays
/// above it (600_000 -> 100_000). Pinning can: pass the value stored from the
/// last successful login. `None` means "no prior observation", which is
/// trust-on-first-use and cannot detect anything.
pub fn check_kdf_not_downgraded(got: u32, pinned: Option<u32>) -> Result<(), SyncError> {
    match pinned {
        Some(pinned) if got < pinned => Err(SyncError::KdfIterationsDowngraded { got, pinned }),
        _ => Ok(()),
    }
}

pub fn check_kdf_type(got: u32) -> Result<(), SyncError> {
    if got != KDF_PBKDF2 {
        return Err(SyncError::UnsupportedKdfType {
            got,
            supported: KDF_PBKDF2,
        });
    }
    Ok(())
}

pub async fn register(
    client: &dyn HttpClient,
    server: &Server,
    email: &str,
    master_password: &str,
    name: &str,
    kdf_iterations: u32,
) -> Result<RegisterOutput, SyncError> {
    let url = server.identity(format_args!("/accounts/register"))?;
    check_kdf_iterations_for_new_account(kdf_iterations)?;
    let email_lc = email.trim().to_lowercase();
    let master_key = derive_master_key(master_password, &email_lc, kdf_iterations);
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
        kdf: KDF_PBKDF2,
        kdf_iterations,
        reference_data: None,
    };

    let body_json = serde_json::to_vec(&body).map_err(|e| SyncError::Parse(e.to_string()))?;
    send(client, &url, Request::Post(HttpBody::Json(body_json)), &[]).await?;

    Ok(RegisterOutput {
        email: email_lc,
        kdf_iterations,
        user_enc_key: VaultKey::from_trusted(user_key.enc_key.to_vec()),
        user_mac_key: VaultKey::from_trusted(user_key.mac_key.to_vec()),
    })
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
    #[serde(rename = "referenceData")]
    reference_data: Option<serde_json::Value>,
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

    pub kdf_iterations: u32,

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

pub async fn login(
    client: &dyn HttpClient,
    server: &Server,
    email: &str,
    master_password: &str,
    device_name: &str,
) -> Result<Session, SyncError> {
    let device_id = Uuid::new_v4().to_string();
    login_pinned(client, server, email, master_password, device_name, &device_id, None).await
}

/// [`login`] with a caller-supplied stable device identifier.
///
/// Long-lived clients (the browser extension) persist one id and reuse it on
/// every login so the server sees a single device rather than one per sign-in.
pub async fn login_with_device(
    client: &dyn HttpClient,
    server: &Server,
    email: &str,
    master_password: &str,
    device_name: &str,
    device_id: &str,
) -> Result<Session, SyncError> {
    login_pinned(client, server, email, master_password, device_name, device_id, None).await
}

/// [`login`] plus downgrade detection.
///
/// `pinned_kdf_iterations` is the count recorded by a previous successful
/// login for this account. If the server now offers less, the login is
/// refused before the master-password hash is derived or transmitted.
pub async fn login_pinned(
    client: &dyn HttpClient,
    server: &Server,
    email: &str,
    master_password: &str,
    device_name: &str,
    device_id: &str,
    pinned_kdf_iterations: Option<u32>,
) -> Result<Session, SyncError> {
    let token_url = server.identity(format_args!("/connect/token"))?;
    let email_lc = email.trim().to_lowercase();
    let kdf_iters = match prelogin(client, server, &email_lc).await {
        Ok(p) => {
            check_kdf_type(p.kdf.unwrap_or(KDF_PBKDF2))?;
            let iters = p.kdf_iterations.unwrap_or(KDF_ITERATIONS_DEFAULT);
            check_kdf_iterations(iters)?;
            check_kdf_not_downgraded(iters, pinned_kdf_iterations)?;
            iters
        }

        // A server that will not answer prelogin gets the strongest parameters
        // we know of, never the weakest: our own pin if we have one, else the
        // current default. Neither is a downgrade.
        Err(_) => pinned_kdf_iterations.unwrap_or(KDF_ITERATIONS_DEFAULT),
    };

    let master_key = derive_master_key(master_password, &email_lc, kdf_iters);
    let mphash = master_password_hash(&master_key, master_password);

    let form = TokenForm {
        grant_type: "password".to_string(),
        username: email_lc.clone(),
        password: mphash,
        scope: "api offline_access".to_string(),
        client_id: "cli".to_string(),
        device_type: "8".to_string(),
        device_identifier: device_id.to_string(),
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
        kdf_iterations: kdf_iters,
        device_id: device_id.to_string(),
    })
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
    let res = send(
        client,
        &token_url,
        Request::Post(HttpBody::Form(body)),
        &[],
    )
    .await?;
    let parsed: RefreshResponse =
        serde_json::from_slice(&res.body).map_err(|e| SyncError::Parse(format!("refresh: {e}")))?;
    session.access_token = crate::BearerToken::from_trusted(parsed.access_token);
    if let Some(rt) = parsed.refresh_token {
        session.refresh_token = crate::RefreshToken::from_trusted(rt);
    }
    Ok(())
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureNote {
    #[serde(rename = "Type", alias = "type", default)]
    pub note_type: u8,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CipherCard {
    #[serde(rename = "CardholderName", alias = "cardholderName", default, skip_serializing_if = "Option::is_none")]
    pub cardholder_name: Option<Type2EncString>,

    #[serde(rename = "Brand", alias = "brand", default, skip_serializing_if = "Option::is_none")]
    pub brand: Option<Type2EncString>,

    #[serde(rename = "Number", alias = "number", default, skip_serializing_if = "Option::is_none")]
    pub number: Option<Type2EncString>,

    #[serde(rename = "ExpMonth", alias = "expMonth", default, skip_serializing_if = "Option::is_none")]
    pub exp_month: Option<Type2EncString>,

    #[serde(rename = "ExpYear", alias = "expYear", default, skip_serializing_if = "Option::is_none")]
    pub exp_year: Option<Type2EncString>,

    #[serde(rename = "Code", alias = "code", default, skip_serializing_if = "Option::is_none")]
    pub code: Option<Type2EncString>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CipherIdentity {
    #[serde(rename = "FirstName", alias = "firstName", default, skip_serializing_if = "Option::is_none")]
    pub first_name: Option<Type2EncString>,

    #[serde(rename = "MiddleName", alias = "middleName", default, skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<Type2EncString>,

    #[serde(rename = "LastName", alias = "lastName", default, skip_serializing_if = "Option::is_none")]
    pub last_name: Option<Type2EncString>,

    #[serde(rename = "Address1", alias = "address1", default, skip_serializing_if = "Option::is_none")]
    pub address1: Option<Type2EncString>,

    #[serde(rename = "Address2", alias = "address2", default, skip_serializing_if = "Option::is_none")]
    pub address2: Option<Type2EncString>,

    #[serde(rename = "Address3", alias = "address3", default, skip_serializing_if = "Option::is_none")]
    pub address3: Option<Type2EncString>,

    #[serde(rename = "City", alias = "city", default, skip_serializing_if = "Option::is_none")]
    pub city: Option<Type2EncString>,

    #[serde(rename = "State", alias = "state", default, skip_serializing_if = "Option::is_none")]
    pub state: Option<Type2EncString>,

    #[serde(rename = "PostalCode", alias = "postalCode", default, skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<Type2EncString>,

    #[serde(rename = "Country", alias = "country", default, skip_serializing_if = "Option::is_none")]
    pub country: Option<Type2EncString>,

    #[serde(rename = "Phone", alias = "phone", default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<Type2EncString>,

    #[serde(rename = "Email", alias = "email", default, skip_serializing_if = "Option::is_none")]
    pub email: Option<Type2EncString>,

    #[serde(rename = "Ssn", alias = "ssn", default, skip_serializing_if = "Option::is_none")]
    pub ssn: Option<Type2EncString>,

    #[serde(rename = "PassportNumber", alias = "passportNumber", default, skip_serializing_if = "Option::is_none")]
    pub passport_number: Option<Type2EncString>,

    #[serde(rename = "Dob", alias = "dob", default, skip_serializing_if = "Option::is_none")]
    pub dob: Option<Type2EncString>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CipherSshKey {
    #[serde(rename = "KeyType", alias = "keyType", default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<Type2EncString>,

    #[serde(rename = "Fingerprint", alias = "fingerprint", default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<Type2EncString>,

    #[serde(rename = "PublicKey", alias = "publicKey", default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<Type2EncString>,

    #[serde(rename = "PrivateKey", alias = "privateKey", default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<Type2EncString>,

    #[serde(rename = "Comment", alias = "comment", default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<Type2EncString>,

    #[serde(rename = "Passphrase", alias = "passphrase", default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<Type2EncString>,
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
    Ok(Vault {
        ciphers: payload.ciphers.unwrap_or_default(),
        folders: payload.folders.unwrap_or_default(),
        organizations: payload
            .profile
            .and_then(|p| p.organizations)
            .unwrap_or_default(),
    })
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

#[derive(Debug, Clone, Serialize)]
pub struct CipherIn {
    #[serde(rename = "type")]
    pub cipher_type: u8,

    pub name: Type2EncString,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<Type2EncString>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<CipherLogin>,

    #[serde(rename = "secureNote", skip_serializing_if = "Option::is_none")]
    pub secure_note: Option<SecureNote>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<CipherFieldIn>>,

    #[serde(rename = "folderId", skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,

    #[serde(rename = "organizationId", skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,

    pub favorite: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CipherFieldIn {
    pub name: Type2EncString,

    pub value: Option<Type2EncString>,

    #[serde(rename = "type")]
    pub field_type: u8,
}

pub type CipherOut = Cipher;

pub async fn create_cipher(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    cipher: &CipherIn,
) -> Result<CipherOut, SyncError> {
    let url = server.api(format_args!("/ciphers"))?;
    let body = serde_json::to_vec(cipher).map_err(|e| SyncError::Parse(e.to_string()))?;
    let res = send(
        client,
        &url,
        Request::Post(HttpBody::Json(body)),
        &[("Authorization".into(), session.bearer())],
    )
    .await?;
    serde_json::from_slice(&res.body).map_err(|e| SyncError::Parse(format!("cipher create: {e}")))
}

pub async fn update_cipher(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    cipher_id: &str,
    cipher: &CipherIn,
) -> Result<CipherOut, SyncError> {
    let url = server.api(format_args!("/ciphers/{cipher_id}"))?;
    let body = serde_json::to_vec(cipher).map_err(|e| SyncError::Parse(e.to_string()))?;
    let res = send(
        client,
        &url,
        Request::Put(HttpBody::Json(body)),
        &[("Authorization".into(), session.bearer())],
    )
    .await?;
    serde_json::from_slice(&res.body).map_err(|e| SyncError::Parse(format!("cipher update: {e}")))
}

pub fn encrypt_string(session: &Session, s: &str) -> Result<Type2EncString, SyncError> {
    let enc: [u8; 32] = (&session.user_enc_key[..])
        .try_into()
        .map_err(|_| SyncError::Crypto("user_enc_key wrong length".into()))?;
    let mac: [u8; 32] = (&session.user_mac_key[..])
        .try_into()
        .map_err(|_| SyncError::Crypto("user_mac_key wrong length".into()))?;
    Ok(Type2EncString::from_trusted(bitwarden::encrypt_type2(
        s.as_bytes(),
        &enc,
        &mac,
    )))
}

pub fn decrypt_string(session: &Session, ct: &Type2EncString) -> Result<String, SyncError> {
    let enc: [u8; 32] = (&session.user_enc_key[..])
        .try_into()
        .map_err(|_| SyncError::Crypto("user_enc_key wrong length".into()))?;
    let mac: [u8; 32] = (&session.user_mac_key[..])
        .try_into()
        .map_err(|_| SyncError::Crypto("user_mac_key wrong length".into()))?;
    let bytes = bitwarden::decrypt_type2(ct.as_str(), &enc, &mac)
        .map_err(|e| SyncError::Crypto(format!("decrypt: {e}")))?;
    String::from_utf8(bytes).map_err(|e| SyncError::Crypto(format!("non-utf8: {e}")))
}

pub fn build_rage_cipher(
    session: &Session,
    name: &str,
    rage_blob: &str,
) -> Result<CipherIn, SyncError> {
    build_rage_cipher_in_folder(session, name, rage_blob, None)
}

pub fn build_rage_cipher_in_folder(
    session: &Session,
    name: &str,
    rage_blob: &str,
    folder_id: Option<&str>,
) -> Result<CipherIn, SyncError> {
    let enc_name = encrypt_string(session, name)?;
    let enc_marker = encrypt_string(session, RAGE_MARKER_NOTE)?;
    let enc_field_name = encrypt_string(session, RAGE_FIELD_NAME)?;
    let enc_field_val = encrypt_string(session, rage_blob)?;
    Ok(CipherIn {
        cipher_type: 2,
        name: enc_name,
        notes: Some(enc_marker),
        login: None,
        secure_note: Some(SecureNote { note_type: 0 }),
        fields: Some(vec![CipherFieldIn {
            name: enc_field_name,
            value: Some(enc_field_val),
            field_type: 1,
        }]),
        folder_id: folder_id.map(String::from),
        organization_id: None,
        favorite: false,
    })
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
        cipher_type: 2,
        name: encrypt_string(session, name)?,
        notes: Some(encrypt_string(session, notes)?),
        login: None,
        secure_note: Some(SecureNote { note_type: 0 }),
        fields: None,
        folder_id: None,
        organization_id: None,
        favorite: false,
    })
}

pub fn cipher_name(session: &Session, cipher: &Cipher) -> Result<String, SyncError> {
    decrypt_string(session, &cipher.name)
}

pub fn extract_rage_blob(session: &Session, cipher: &Cipher) -> Result<Option<String>, SyncError> {
    let Some(fields) = &cipher.fields else {
        return Ok(None);
    };
    for f in fields {
        let plaintext_name = decrypt_string(session, &f.name).unwrap_or_default();
        if plaintext_name == RAGE_FIELD_NAME {
            let Some(val) = &f.value else { return Ok(None) };
            return Ok(Some(decrypt_string(session, val)?));
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

fn server_err(res: &HttpResponse) -> SyncError {
    let body_str = match std::str::from_utf8(&res.body) {
        Ok(s) => s.to_string(),
        Err(_) => format!("<{} non-utf8 bytes>", res.body.len()),
    };
    let truncated = if body_str.len() > 4096 {
        format!("{}... <truncated>", &body_str[..4096])
    } else {
        body_str
    };
    SyncError::Server {
        status: res.status,
        body: truncated,
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

pub async fn create_folder(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    name: &str,
) -> Result<Folder, SyncError> {
    let url = server.api(format_args!("/folders"))?;
    let enc_name = encrypt_string(session, name)?;
    let body = serde_json::to_vec(&FolderRequest { name: enc_name })
        .map_err(|e| SyncError::Parse(e.to_string()))?;
    let res = send(
        client,
        &url,
        Request::Post(HttpBody::Json(body)),
        &[("Authorization".into(), session.bearer())],
    )
    .await?;
    serde_json::from_slice(&res.body).map_err(|e| SyncError::Parse(format!("folder create: {e}")))
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
    let body = serde_json::to_vec(&FolderRequest { name: enc_name })
        .map_err(|e| SyncError::Parse(e.to_string()))?;
    let res = send(
        client,
        &url,
        Request::Put(HttpBody::Json(body)),
        &[("Authorization".into(), session.bearer())],
    )
    .await?;
    serde_json::from_slice(&res.body).map_err(|e| SyncError::Parse(format!("folder update: {e}")))
}

pub async fn delete_folder(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    folder_id: &str,
) -> Result<(), SyncError> {
    let url = server.api(format_args!("/folders/{folder_id}"))?;
    send(
        client,
        &url,
        Request::Delete,
        &[("Authorization".into(), session.bearer())],
    )
    .await?;
    Ok(())
}

pub async fn delete_cipher(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    cipher_id: &str,
) -> Result<(), SyncError> {
    let url = server.api(format_args!("/ciphers/{cipher_id}"))?;
    send(
        client,
        &url,
        Request::Delete,
        &[("Authorization".into(), session.bearer())],
    )
    .await?;
    Ok(())
}

#[derive(Debug, Serialize)]
struct SetFolderRequest<'a> {
    #[serde(rename = "folderId")]
    folder_id: Option<&'a str>,
}

/// Reassigns a cipher's folder (`None` clears it) without touching any
/// encrypted field, so callers need not decrypt-then-re-encrypt. `server_url`
/// is the API base URL ([`Server::api_url`]), for callers that track an
/// api-only base and have no full [`Server`].
///
/// Because there is no [`Server`] here, only the one URL this call dials is
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
    let url = SecureUrl::parse(format!("{base}/ciphers/{cipher_id}/folder"))?;
    set_folder_at(client, &url, session, folder_id).await
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
    let url = server.api(format_args!("/ciphers/{cipher_id}/folder"))?;
    set_folder_at(client, &url, session, folder_id).await
}

async fn set_folder_at<C: HttpClient + ?Sized>(
    client: &C,
    url: &SecureUrl,
    session: &Session,
    folder_id: Option<&str>,
) -> Result<Cipher, SyncError> {
    let body = serde_json::to_vec(&SetFolderRequest { folder_id })
        .map_err(|e| SyncError::Parse(e.to_string()))?;
    let res = send(
        client,
        url,
        Request::Put(HttpBody::Json(body)),
        &[("Authorization".into(), session.bearer())],
    )
    .await?;
    serde_json::from_slice(&res.body).map_err(|e| SyncError::Parse(format!("set_folder: {e}")))
}
