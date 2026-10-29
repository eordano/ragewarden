use std::io::{self, IsTerminal, Read};

use age::secrecy::ExposeSecret;
use chrono::Utc;
use ragewarden_core::sync::{
    self, Cipher, CipherDraft, CipherEdit, Server, Session, Vault, build_cipher, build_rage_cipher,
    fetch_vault, name_index,
};
use ragewarden_core::{
    AgeBlob, Identity, Plaintext, PrfEntry, Recipient, decrypt, encrypt_with_prf,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::agent_add::{self, AddOptions, AgentAddError};
use crate::audit_helper;
use crate::config;
use crate::consent;
use crate::fido::{self, FidoIdentity};
use crate::fill::{self, FillError};
use crate::history_helper;
use crate::http::ReqwestClient;
use crate::hw;
use crate::identities::{self, EnrolledIdentity, Identities, IdentityKind};
use crate::idfile::{self, IdFileError};
use crate::install_native_host::{self, Browser as NhBrowser, Scope as NhScope};
use crate::keyring_id::{self, KEYRING_SERVICE, KeyringIdentity};
use crate::lock;
use crate::native_host;
use crate::output::{self, OutputError};
use crate::pass_import::{self, ImportedItem, PassImportError};
use crate::piv::{self, PivIdentity};
use crate::recipients::{self, RecipientEntry};
use crate::recovery::{self as recovery_mod, RecoveryIdentity};
use crate::session::{self, OpenSession, SessionError};
use crate::store::{Store, StoreError};
use crate::vault as vault_cache;
use ragewarden_core::audit::AuditKind;

#[derive(Debug, Error)]
pub enum CmdError {
    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("{0}")]
    IdFile(#[from] IdFileError),

    #[error("{0}")]
    Store(#[from] StoreError),

    #[error("{0}")]
    Session(#[from] SessionError),

    #[error("{0}")]
    VaultCache(#[from] crate::vault::VaultCacheError),

    #[error("sync: {0}")]
    Sync(#[from] sync::SyncError),

    #[error("encrypt: {0}")]
    Encrypt(String),

    #[error("decrypt: {0}")]
    Decrypt(String),

    #[error("output: {0}")]
    Output(#[from] OutputError),

    #[error("cancelled")]
    Cancelled,

    #[error("no item named `{0}`")]
    NotFound(String),

    #[error("{0}")]
    InvalidArg(String),

    #[error("hardware: {0}")]
    Hardware(String),

    #[error("lock: {0}")]
    Lock(String),

    #[error("identities: {0}")]
    Identities(String),

    #[error("recipient list: {0}")]
    RecipientList(String),

    #[error("recovery: {0}")]
    Recovery(String),

    #[error("install-native-host: {0}")]
    InstallNativeHost(String),

    #[error("native-host: {0}")]
    NativeHost(String),

    #[error("pass-import: {0}")]
    PassImport(String),

    #[error("agent-add: {0}")]
    AgentAdd(String),

    #[error("fill: {0}")]
    Fill(String),
}

impl From<AgentAddError> for CmdError {
    fn from(e: AgentAddError) -> Self {
        Self::AgentAdd(e.to_string())
    }
}
impl From<FillError> for CmdError {
    fn from(e: FillError) -> Self {
        Self::Fill(e.to_string())
    }
}

impl From<consent::ConsentError> for CmdError {
    fn from(e: consent::ConsentError) -> Self {
        match e {
            consent::ConsentError::Cancelled => Self::Cancelled,
            consent::ConsentError::Io(io) => Self::Io(io),
            other => Self::InvalidArg(other.to_string()),
        }
    }
}

impl From<piv::PivError> for CmdError {
    fn from(e: piv::PivError) -> Self {
        Self::Hardware(e.to_string())
    }
}
impl From<fido::FidoError> for CmdError {
    fn from(e: fido::FidoError) -> Self {
        Self::Hardware(e.to_string())
    }
}
impl From<keyring_id::KeyringIdentityError> for CmdError {
    fn from(e: keyring_id::KeyringIdentityError) -> Self {
        Self::Hardware(e.to_string())
    }
}
impl From<lock::LockError> for CmdError {
    fn from(e: lock::LockError) -> Self {
        Self::Lock(e.to_string())
    }
}
impl From<identities::IdentitiesError> for CmdError {
    fn from(e: identities::IdentitiesError) -> Self {
        Self::Identities(e.to_string())
    }
}
impl From<recipients::RecipientListError> for CmdError {
    fn from(e: recipients::RecipientListError) -> Self {
        Self::RecipientList(e.to_string())
    }
}
impl From<recovery_mod::RecoveryError> for CmdError {
    fn from(e: recovery_mod::RecoveryError) -> Self {
        Self::Recovery(e.to_string())
    }
}
impl From<install_native_host::InstallError> for CmdError {
    fn from(e: install_native_host::InstallError) -> Self {
        Self::InstallNativeHost(e.to_string())
    }
}
impl From<native_host::NativeHostError> for CmdError {
    fn from(e: native_host::NativeHostError) -> Self {
        Self::NativeHost(e.to_string())
    }
}
impl From<PassImportError> for CmdError {
    fn from(e: PassImportError) -> Self {
        Self::PassImport(e.to_string())
    }
}

/// A new passphrase, typed twice at the terminal.
fn new_identity_passphrase() -> Result<age::secrecy::SecretString, CmdError> {
    let first = Zeroizing::new(rpassword::prompt_password("New identity passphrase: ")?);
    if first.is_empty() {
        return Err(CmdError::InvalidArg("the passphrase is empty".into()));
    }
    let again = Zeroizing::new(rpassword::prompt_password("Repeat the passphrase: ")?);
    if *first != *again {
        return Err(CmdError::InvalidArg("the passphrases did not match".into()));
    }
    Ok(age::secrecy::SecretString::from(first.to_string()))
}

pub fn cmd_protect_identity() -> Result<(), CmdError> {
    let path = config::identity_path()?;
    if idfile::is_protected(&path)? {
        println!("{} is already protected by a passphrase.", path.display());
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        return Err(CmdError::InvalidArg(
            "protect-identity needs a terminal to set the passphrase on".into(),
        ));
    }
    let id = idfile::read(&path)?;
    let pass = new_identity_passphrase()?;
    idfile::write_identity(&path, &id, idfile::AtRest::Passphrase(pass))?;
    let reread = idfile::read(&path)?;
    if reread.to_public().to_string() != id.to_public().to_string() {
        return Err(CmdError::InvalidArg(
            "the protected identity did not read back as the same key".into(),
        ));
    }
    if let Some(open) = session::load()? {
        session::save(&open.server, &open.session)?;
    }
    println!(
        "{} is now protected by a passphrase, and so is the saved session.",
        path.display()
    );
    Ok(())
}

pub fn cmd_enroll_software_identity(plaintext: bool) -> Result<(), CmdError> {
    config::ensure_config_dir()?;
    let path = config::identity_path()?;
    if path.exists() {
        return Err(CmdError::InvalidArg(format!(
            "identity file already exists at {}; refusing to overwrite (delete the file first \
             if you want to re-enroll)",
            path.display()
        )));
    }
    audit_helper::record_detail(
        ragewarden_core::audit::AuditKind::EnrollIdentity,
        "software",
    );
    let at_rest = if plaintext {
        idfile::AtRest::Plaintext
    } else if io::stdin().is_terminal() {
        idfile::AtRest::Passphrase(new_identity_passphrase()?)
    } else {
        eprintln!(
            "rageterm: no terminal to set a passphrase on, so identity.age is written as a \
             bare secret key that anyone who can read the file can use. Run `rageterm \
             protect-identity` from a terminal to protect it."
        );
        idfile::AtRest::Plaintext
    };
    let pub_armored = idfile::generate_and_write(&path, at_rest)?;

    println!("Enrolled software identity at {}", path.display());
    println!("Public key (recipient): {pub_armored}");
    println!(
        "This file holds your secret key. Back it up -- or run `rageterm enroll-recovery` \
         to add a 24-word paper recovery recipient, then `rageterm reencrypt --all` to fold \
         a new recipient into items stored before it."
    );
    Ok(())
}

pub async fn cmd_register(
    server_url: &str,
    email: &str,
    name: &str,
    kdf: sync::KdfParams,
) -> Result<(), CmdError> {
    let password = read_master_password("New master password: ", true)?;
    let server = Server::self_hosted(server_url);
    server
        .require_secure()
        .map_err(|e| CmdError::InvalidArg(e.to_string()))?;
    let client = new_client()?;
    let _out =
        sync::register_with_kdf(&client, &server, email, password.expose_secret(), name, kdf)
            .await?;
    session::save_kdf_pin(server_url, email, &kdf)?;
    println!("Registered `{email}` on {server_url} ({}).", kdf.describe());
    println!("Run `rageterm login --server {server_url} --email {email}` to log in.");
    Ok(())
}

pub async fn cmd_login(
    server_url: &str,
    email: &str,
    allow_weak_kdf: bool,
) -> Result<(), CmdError> {
    audit_helper::record_detail(ragewarden_core::audit::AuditKind::Login, email.to_string());
    let password = read_master_password("Master password: ", false)?;
    let server = Server::self_hosted(server_url);
    server
        .require_secure()
        .map_err(|e| CmdError::InvalidArg(e.to_string()))?;
    let client = new_client()?;
    let device_name = format!("rageterm@{}", hostname_or_unknown());
    let mut opts = sync::LoginOptions {
        device_id: None,
        kdf_pin: session::kdf_pin(server_url, email)?,
        allow_legacy_kdf: allow_weak_kdf,
    };
    let attempt = sync::login_with_options(
        &client,
        &server,
        email,
        password.expose_secret(),
        &device_name,
        &opts,
    )
    .await;
    let mut s = match attempt {
        Err(sync::SyncError::LegacyKdfNeedsConsent { got, min }) => {
            consent::confirm(&format!(
                "This account derives its master key with only {got} PBKDF2 iterations \
                 (below {min}). Log in anyway and raise it to {} on the server now?",
                sync::KdfParams::default().describe()
            ))
            .map_err(|e| match e {
                consent::ConsentError::NoConsentSurface { .. } => CmdError::InvalidArg(format!(
                    "this account uses only {got} PBKDF2 iterations (below {min}); re-run \
                     with `--allow-weak-kdf` to log in and raise it to the current default"
                )),
                other => other.into(),
            })?;
            opts.allow_legacy_kdf = true;
            sync::login_with_options(
                &client,
                &server,
                email,
                password.expose_secret(),
                &device_name,
                &opts,
            )
            .await?
        }
        other => other?,
    };
    if kdf_is_legacy(&s.kdf) {
        let target = sync::KdfParams::default();
        s = sync::upgrade_kdf(
            &client,
            &server,
            &s,
            password.expose_secret(),
            &device_name,
            target,
        )
        .await?;
        eprintln!(
            "rageterm: raised this account's key derivation to {} on the server; other \
             Bitwarden clients of the account need to log in again.",
            target.describe()
        );
    }
    session::save(&server, &s)?;
    session::save_kdf_pin(server_url, email, &s.kdf)?;
    println!(
        "Logged in as {} on {} ({}). Session saved at {}.",
        s.email,
        server_url,
        s.kdf.describe(),
        session::session_path()?.display()
    );
    upload_local_store(&client, &server, &s).await?;
    println!("Run `rageterm sync` to pull the vault.");
    Ok(())
}

/// PBKDF2 below the client's minimum: accepted only with consent, then upgraded.
fn kdf_is_legacy(k: &sync::KdfParams) -> bool {
    k.kdf == 0 && k.iterations < ragewarden_core::bitwarden::KDF_ITERATIONS_MIN
}

/// Items stored with `set --offline` go to the account on login, as the same
/// rage blobs (no re-encryption). An item whose name already exists on the
/// server stays local and is reported; the store is retired once it is empty.
async fn upload_local_store(
    client: &ReqwestClient,
    server: &Server,
    session: &Session,
) -> Result<(), CmdError> {
    let store_path = config::store_path()?;
    let mut store = Store::load(&store_path)?;
    if store.items.is_empty() {
        return Ok(());
    }
    let vault = fetch_vault(client, server, session).await?;
    let on_server = name_index(session, &vault);
    let names: Vec<String> = store.items.keys().cloned().collect();
    let mut uploaded = 0usize;
    let mut cache = vault;
    for name in names {
        if on_server.contains_key(&name) {
            eprintln!(
                "rageterm: `{name}` exists both locally and on the server; left in {} for you \
                 to resolve",
                store_path.display()
            );
            continue;
        }
        let blob = store.items[&name].rage_blob.clone();
        let cipher_in = build_rage_cipher(session, &name, &blob)?;
        let saved = sync::save_cipher(client, server, session, None, &cipher_in).await?;
        cache.upsert_cipher(saved);
        store.items.remove(&name);
        store.save(&store_path)?;
        uploaded += 1;
    }
    vault_cache::save(&cache)?;
    if store.items.is_empty() {
        std::fs::remove_file(&store_path)?;
    }
    if uploaded > 0 {
        println!("Uploaded {uploaded} item(s) from the local store to the account.");
    }
    Ok(())
}

pub fn cmd_audit(limit: usize) -> Result<(), CmdError> {
    let tail = audit_helper::tail(limit).map_err(CmdError::InvalidArg)?;
    for e in &tail.events {
        let result = match e.result {
            Some(ragewarden_core::audit::AuditResult::Ok) => "ok",
            Some(ragewarden_core::audit::AuditResult::Declined) => "declined",
            Some(ragewarden_core::audit::AuditResult::Failed) => "failed",
            None => "-",
        };
        println!(
            "{}  {:?}  {}  {}  {}",
            e.recorded_at.format("%Y-%m-%d %H:%M:%S"),
            e.kind,
            result,
            e.target.as_deref().unwrap_or("-"),
            e.detail.as_deref().unwrap_or("")
        );
    }
    if tail.skipped_lines > 0 {
        eprintln!(
            "rageterm: {} audit line(s) could not be read and were skipped -- the log is \
             damaged or was edited",
            tail.skipped_lines
        );
    }
    Ok(())
}

pub fn cmd_logout() -> Result<(), CmdError> {
    audit_helper::record_kind(ragewarden_core::audit::AuditKind::Logout);
    session::clear()?;
    println!("Logged out (session + vault cache cleared). identity.age preserved.");
    Ok(())
}

pub async fn cmd_sync() -> Result<(), CmdError> {
    audit_helper::record_kind(ragewarden_core::audit::AuditKind::Sync);
    let open = require_session()?;
    let client = new_client()?;
    let vault = fetch_vault(&client, &open.server, &open.session).await?;
    vault_cache::save(&vault)?;

    let total = vault.ciphers.len();
    let rage_count = vault
        .ciphers
        .iter()
        .filter(|c| {
            sync::extract_rage_blob(&open.session, c)
                .ok()
                .flatten()
                .is_some()
        })
        .count();
    println!(
        "Synced. {total} cipher(s); {rage_count} rage-protected. Cache at {}.",
        vault_cache::path()?.display()
    );

    if let Err(e) = recipients::publish_local_identity_to_registry().await {
        eprintln!(
            "(warning: couldn't publish this rageterm to the cross-device registry: {e}. \
             Other devices may not be able to encrypt to you yet.)"
        );
    }
    publish_attestation_keys().await;
    Ok(())
}

#[derive(Debug, Clone)]
pub enum SetCipherType {
    SecureNote,
    Login {
        username: Option<String>,
        urls: Vec<String>,
    },
    Card,
    Identity,
    SshKey,
}

impl SetCipherType {
    fn code(&self) -> u8 {
        match self {
            Self::SecureNote => sync::CIPHER_TYPE_SECURE_NOTE,
            Self::Login { .. } => sync::CIPHER_TYPE_LOGIN,
            Self::Card => sync::CIPHER_TYPE_CARD,
            Self::Identity => sync::CIPHER_TYPE_IDENTITY,
            Self::SshKey => sync::CIPHER_TYPE_SSH_KEY,
        }
    }
}

/// What `rageterm set` was asked to write.
pub struct SetArgs<'a> {
    pub name: &'a str,
    pub cipher_type: Option<SetCipherType>,
    pub from_stdin: bool,
    pub folder: Option<&'a str>,
    pub offline: bool,
    pub generate: Option<&'a Generate>,
    pub field: Option<&'a str>,
    pub protect: Vec<String>,
    pub with: Vec<(String, String)>,
    pub yes: bool,
    pub no_wait: bool,
}

type FieldValues = std::collections::BTreeMap<String, Zeroizing<Vec<u8>>>;

/// The fields `set` can protect on an item of `cipher_type`: the type's own
/// secret-bearing fields and its notes, plus an SSH key's passphrase, which has
/// no unprotected home.
pub fn protectable_fields(cipher_type: u8) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = match cipher_type {
        sync::CIPHER_TYPE_LOGIN => vec!["password", "totp"],
        sync::CIPHER_TYPE_CARD => sync::CARD_FIELDS.to_vec(),
        sync::CIPHER_TYPE_IDENTITY => sync::IDENTITY_FIELDS.to_vec(),
        sync::CIPHER_TYPE_SSH_KEY => [sync::SSH_KEY_FIELDS, &["passphrase"]].concat(),
        _ => Vec::new(),
    };
    out.push("notes");
    out
}

/// `requested` as canonical field names, refusing one the type has no place for
/// unless the item already protects it.
fn protectable(
    cipher_type: u8,
    requested: &[String],
    already: &[String],
) -> Result<Vec<String>, CmdError> {
    let allowed = protectable_fields(cipher_type);
    let mut out: Vec<String> = Vec::new();
    for r in requested {
        let name = ragewarden_core::protected::canonical_field(cipher_type, r.trim());
        if !allowed.contains(&name.as_str()) && !already.contains(&name) {
            return Err(CmdError::InvalidArg(format!(
                "`{name}` is not a field this item type can protect; expected one of: {}",
                allowed.join(", ")
            )));
        }
        if !out.contains(&name) {
            out.push(name);
        }
    }
    Ok(out)
}

/// The values `set` writes into `fields`: generated, prompted (one hidden
/// prompt per field), raw stdin for one field, or for several a JSON object
/// on stdin mapping each to its value.
fn read_set_values(
    name: &str,
    fields: &[String],
    labelled: bool,
    from_stdin: bool,
    generate: Option<&Generate>,
) -> Result<FieldValues, CmdError> {
    let mut out = FieldValues::new();
    if let Some(spec) = generate {
        let [only] = fields else {
            return Err(CmdError::InvalidArg(
                "--generate fills one field; generate another with `set NAME --field F --generate`"
                    .into(),
            ));
        };
        out.insert(
            only.clone(),
            Zeroizing::new(generated_secret(spec)?.as_bytes().to_vec()),
        );
        return Ok(out);
    }
    if io::stdin().is_terminal() && !from_stdin {
        for f in fields {
            let prompt = if labelled {
                format!("Value for `{name}` {f} (hidden): ")
            } else {
                format!("Value for `{name}` (hidden): ")
            };
            let value = Zeroizing::new(
                rpassword::prompt_password(prompt)
                    .map_err(|e| CmdError::InvalidArg(format!("could not read value: {e}")))?
                    .into_bytes(),
            );
            if value.is_empty() {
                return Err(CmdError::InvalidArg(format!("no value for `{f}`")));
            }
            out.insert(f.clone(), value);
        }
        return Ok(out);
    }
    let mut buf = Zeroizing::new(Vec::new());
    io::stdin().read_to_end(&mut buf)?;
    if let [only] = fields {
        if buf.last() == Some(&b'\n') {
            buf.pop();
        }
        if buf.is_empty() {
            return Err(CmdError::InvalidArg(if from_stdin {
                "no plaintext on stdin (pipe a value before invoking with --from-stdin)".into()
            } else {
                "no plaintext provided".into()
            }));
        }
        out.insert(only.clone(), buf);
        return Ok(out);
    }
    let given: std::collections::BTreeMap<String, Zeroizing<String>> =
        serde_json::from_slice::<std::collections::BTreeMap<String, String>>(&buf)
            .map_err(|e| {
                CmdError::InvalidArg(format!(
                    "with several protected fields stdin is a JSON object of them ({}): {e}",
                    fields.join(", ")
                ))
            })?
            .into_iter()
            .map(|(k, v)| (k, Zeroizing::new(v)))
            .collect();
    if let Some(extra) = given.keys().find(|k| !fields.contains(k)) {
        return Err(CmdError::InvalidArg(format!(
            "stdin names `{extra}`, which is not among the protected fields ({})",
            fields.join(", ")
        )));
    }
    for f in fields {
        match given.get(f) {
            Some(v) if !v.is_empty() => {
                out.insert(f.clone(), Zeroizing::new(v.as_bytes().to_vec()));
            }
            _ => {
                return Err(CmdError::InvalidArg(format!(
                    "stdin has no value for `{f}`"
                )));
            }
        }
    }
    Ok(out)
}

/// The payload once `values` are written into it, keeping every other field
/// of `current` (the item's decrypted payload, read as `current_type`), and the
/// field list the item's marker then names.
pub fn payload_with(
    current: Option<(u8, &[u8])>,
    cipher_type: u8,
    values: FieldValues,
) -> Result<(Zeroizing<Vec<u8>>, Vec<String>), CmdError> {
    use ragewarden_core::protected;
    let mut fields = match current {
        Some((t, payload)) => {
            protected::open(t, payload).map_err(|e| CmdError::Decrypt(e.to_string()))?
        }
        None => FieldValues::new(),
    };
    fields.extend(values);
    let sealed =
        protected::seal(cipher_type, &fields).map_err(|e| CmdError::Encrypt(e.to_string()))?;
    Ok((sealed, fields.into_keys().collect()))
}

fn block_of(with: &[(String, String)]) -> std::collections::BTreeMap<String, String> {
    with.iter().cloned().collect()
}

/// A password from core's generator for `set --generate` and `generate`.
pub fn generated_secret(spec: &Generate) -> Result<Zeroizing<String>, CmdError> {
    use ragewarden_core::generator;
    match spec.words {
        Some(words) => generator::passphrase(words, "-"),
        None => generator::password(&generator::PasswordPolicy {
            length: spec.length,
            symbols: !spec.no_symbols,
            ..generator::PasswordPolicy::default()
        }),
    }
    .map_err(|e| CmdError::InvalidArg(e.to_string()))
}

#[derive(Debug, Clone)]
pub struct Generate {
    pub length: usize,
    pub no_symbols: bool,
    pub words: Option<usize>,
}

pub fn cmd_generate(spec: &Generate) -> Result<(), CmdError> {
    let secret = generated_secret(spec)?;
    println!("{}", secret.as_str());
    Ok(())
}

pub async fn cmd_set(args: SetArgs<'_>) -> Result<(), CmdError> {
    let SetArgs {
        name,
        cipher_type,
        from_stdin,
        folder,
        offline,
        generate,
        field,
        protect,
        with,
        yes,
        no_wait,
    } = args;
    let session = if offline { None } else { session::load()? };
    if session.is_none() && !offline {
        return Err(CmdError::InvalidArg(
            "not logged in: run `rageterm login` to store it on the server, or pass \
             `--offline` to keep it in this machine's local store (`login` uploads it \
             later)"
                .into(),
        ));
    }
    let typed = matches!(
        cipher_type,
        Some(SetCipherType::Card | SetCipherType::Identity | SetCipherType::SshKey)
    );
    let has_block = |t: u8| {
        [
            sync::CIPHER_TYPE_CARD,
            sync::CIPHER_TYPE_IDENTITY,
            sync::CIPHER_TYPE_SSH_KEY,
        ]
        .contains(&t)
    };
    let with_needs_block = || {
        CmdError::InvalidArg(
            "--with sets card, identity or SSH key fields; pass `--type card`, `identity` \
             or `ssh-key`"
                .into(),
        )
    };
    let Some(open) = session else {
        if field.is_some() || !protect.is_empty() || !with.is_empty() || typed {
            return Err(CmdError::InvalidArg(
                "--field, --protect, --with and card/identity/SSH key items live on the \
                 server; the local store keeps one secret per item"
                    .into(),
            ));
        }
        if folder.is_some() {
            return Err(CmdError::InvalidArg(
                "--folder requires a logged-in session (folders live on the server)".into(),
            ));
        }
        let primary = ["notes".to_string()];
        let mut values = read_set_values(name, &primary, false, from_stdin, generate)?;
        let plaintext = values.remove("notes").unwrap_or_default();
        let armored = encrypt_for_current_recipients(&plaintext).await?.0;
        drop(plaintext);
        let store_path = config::store_path()?;
        config::ensure_config_dir()?;
        let mut store = Store::load(&store_path)?;
        let was_new = !store.items.contains_key(name);
        audit_helper::record_target(
            if was_new {
                ragewarden_core::audit::AuditKind::Set
            } else {
                ragewarden_core::audit::AuditKind::Update
            },
            name.to_string(),
        );
        store.upsert(name, armored, Utc::now());
        store.save(&store_path)?;
        if was_new {
            println!("Stored `{name}` in the local store; `rageterm login` uploads it.");
        } else {
            println!("Updated `{name}` in the local store; `rageterm login` uploads it.");
        }
        return Ok(());
    };

    let client = new_client()?;
    let cached = vault_cache::load()?;
    let folder_id: Option<String> = if let Some(want) = folder {
        let vault_for_lookup = cached.as_ref().ok_or_else(|| {
            CmdError::InvalidArg(
                "no cached vault -- run `rageterm sync` first to populate folders".into(),
            )
        })?;
        Some(resolve_folder_name(&open.session, vault_for_lookup, want)?)
    } else {
        None
    };
    let existing = cached
        .as_ref()
        .and_then(|v| find_cipher_by_name(&open.session, v, name));

    let saved = if let Some(existing) = existing {
        let id = existing.id.clone().ok_or_else(|| {
            CmdError::InvalidArg(format!(
                "cached `{name}` has no server id; run `rageterm sync`"
            ))
        })?;
        if !protect.is_empty() {
            return Err(CmdError::InvalidArg(format!(
                "`{name}` exists; --protect is for a new item. Protect another of its fields \
                 with `rageterm set {name} --field F`"
            )));
        }
        let old_type = existing.cipher_type;
        let new_type = cipher_type.as_ref().map_or(old_type, SetCipherType::code);
        if new_type != old_type && old_type != sync::CIPHER_TYPE_SECURE_NOTE {
            return Err(CmdError::InvalidArg(format!(
                "`{name}` already exists as cipher type {old_type}; only a secure note can \
                 become another type"
            )));
        }
        if !with.is_empty() && !has_block(new_type) {
            return Err(with_needs_block());
        }
        let protected = sync::protected_field_names(&open.session, existing)?;
        let target = protectable(new_type, &[field.unwrap_or("").to_string()], &protected)?;
        if let Some((k, _)) = with
            .iter()
            .find(|(k, _)| protected.contains(k) || target.contains(k))
        {
            return Err(CmdError::InvalidArg(format!(
                "`{k}` is protected in `{name}`; write it with `--field {k}` so it stays in \
                 the blob and out of argv"
            )));
        }
        let values = read_set_values(name, &target, field.is_some(), from_stdin, generate)?;
        let keeps_others = protected.iter().any(|p| !target.contains(p));
        let current = if keeps_others {
            let guard = consent::require(
                "Re-seal",
                name,
                "a new copy that keeps its other protected fields",
                yes,
            )?;
            lock::set_wait(!no_wait);
            Some(decrypt_payload(name, &guard)?)
        } else {
            None
        };
        let (payload, fields) = payload_with(
            current.as_ref().map(|p| (old_type, p.as_slice())),
            new_type,
            values,
        )?;
        drop(current);
        let (armored, recipients_vec) = encrypt_for_current_recipients(&payload).await?;
        drop(payload);

        let block = (!with.is_empty() || new_type != old_type).then(|| block_of(&with));
        let mut edit = CipherEdit {
            folder_id: folder_id.clone(),
            protected_fields: Some(fields),
            ..CipherEdit::default()
        };
        match (cipher_type, new_type) {
            (Some(SetCipherType::Login { username, urls }), _) => {
                edit.username = username;
                edit.uris = (!urls.is_empty()).then_some(urls);
                if old_type == sync::CIPHER_TYPE_SECURE_NOTE
                    && edit.username.is_none()
                    && edit.uris.is_none()
                {
                    edit.username = Some(String::new());
                }
            }
            (_, sync::CIPHER_TYPE_CARD) => edit.card = block,
            (_, sync::CIPHER_TYPE_IDENTITY) => edit.identity = block,
            (_, sync::CIPHER_TYPE_SSH_KEY) => edit.ssh_key = block,
            _ => {}
        }
        audit_helper::record_target(ragewarden_core::audit::AuditKind::Update, name.to_string());
        history_helper::record_prior_revision(existing, &recipients_vec).await;
        sync::update_preserving(
            &client,
            &open.server,
            &open.session,
            &id,
            Some(&armored),
            &edit,
        )
        .await?
    } else {
        if field.is_some() {
            return Err(CmdError::InvalidArg(format!(
                "no item `{name}` to write a field of; create it with `rageterm set {name} \
                 [--type T] [--protect F,...]`"
            )));
        }
        let new_type = cipher_type
            .as_ref()
            .map_or(sync::CIPHER_TYPE_SECURE_NOTE, SetCipherType::code);
        let fields = if protect.is_empty() {
            vec![ragewarden_core::protected::primary_field(new_type).to_string()]
        } else {
            protectable(new_type, &protect, &[])?
        };
        if !with.is_empty() && !typed {
            return Err(with_needs_block());
        }
        if let Some((k, _)) = with.iter().find(|(k, _)| fields.contains(k)) {
            return Err(CmdError::InvalidArg(format!(
                "`{k}` is protected; give its value on stdin or at the prompt, not in argv"
            )));
        }
        let labelled = !protect.is_empty();
        let values = read_set_values(name, &fields, labelled, from_stdin, generate)?;
        let (payload, fields) = payload_with(None, new_type, values)?;
        let (armored, _) = encrypt_for_current_recipients(&payload).await?;
        drop(payload);

        audit_helper::record_target(ragewarden_core::audit::AuditKind::Set, name.to_string());
        let draft = new_item_draft(name, cipher_type, folder_id.clone(), fields, &with);
        let cipher_in = build_cipher(&open.session, &draft, Some(&armored))?;
        sync::create_cipher(&client, &open.server, &open.session, &cipher_in).await?
    };

    let mut vault = vault_cache::load()?.or(cached).unwrap_or_default();
    vault.upsert_cipher(saved);
    vault_cache::save(&vault)?;
    println!("Stored `{name}` on server.");
    Ok(())
}

/// The draft for a new item whose rage blob holds `fields`; `with` fills the
/// unprotected part of a card, identity or SSH key block.
pub fn new_item_draft(
    name: &str,
    cipher_type: Option<SetCipherType>,
    folder_id: Option<String>,
    fields: Vec<String>,
    with: &[(String, String)],
) -> CipherDraft {
    let mut draft = CipherDraft {
        name: name.to_string(),
        folder_id,
        protected_fields: fields,
        ..CipherDraft::default()
    };
    match cipher_type {
        Some(SetCipherType::Login { username, urls }) => {
            draft.login = true;
            draft.username = username;
            draft.uris = urls;
        }
        Some(SetCipherType::Card) => draft.card = Some(block_of(with)),
        Some(SetCipherType::Identity) => draft.identity = Some(block_of(with)),
        Some(SetCipherType::SshKey) => draft.ssh_key = Some(block_of(with)),
        Some(SetCipherType::SecureNote) | None => {}
    }
    draft
}

/// `payload` encrypted to this machine's current recipient set (skips
/// reported), with one fresh PRF evaluation per FIDO2 recipient.
async fn encrypt_for_current_recipients(
    payload: &[u8],
) -> Result<(String, Vec<Recipient>), CmdError> {
    let plan = recipients::load_encrypt_plan().await?;
    recipients::warn_about_skips(&plan.skips);
    let recipients_vec: Vec<Recipient> = plan.selection.recipients;
    let prf_outputs = build_prf_outputs_for(&recipients_vec)?;
    let prf_table: Vec<PrfEntry<'_>> = prf_table_from(&prf_outputs);
    let blob = encrypt_with_prf(payload, &recipients_vec, &prf_table)
        .map_err(|e| CmdError::Encrypt(e.to_string()))?;
    let armored = String::from_utf8(blob.0)
        .map_err(|e| CmdError::Encrypt(format!("blob is not valid UTF-8: {e}")))?;
    Ok((armored, recipients_vec))
}

fn resolve_folder_name(session: &Session, vault: &Vault, name: &str) -> Result<String, CmdError> {
    for f in &vault.folders {
        let Ok(decrypted) = sync::decrypt_string(session, &f.name) else {
            continue;
        };
        if decrypted == name {
            return Ok(f.id.clone());
        }
    }
    Err(CmdError::InvalidArg(format!(
        "no folder named `{name}` -- create it with `rageterm folders create {name}`"
    )))
}

pub async fn cmd_list(filter: Option<&str>, json: bool) -> Result<(), CmdError> {
    let needle = filter.map(str::to_lowercase);
    let matches = |name: &str| match &needle {
        None => true,
        Some(n) => name.to_lowercase().contains(n),
    };

    if let Some(open) = session::load()? {
        let vault = match vault_cache::load()? {
            Some(v) => v,
            None => {
                if json {
                    println!("[]");
                } else {
                    eprintln!("(no cached vault -- run `rageterm sync` first)");
                }
                return Ok(());
            }
        };
        if vault.ciphers.is_empty() {
            if json {
                println!("[]");
            } else {
                eprintln!("(vault is empty)");
            }
            return Ok(());
        }

        let folder_names: std::collections::HashMap<String, String> = vault
            .folders
            .iter()
            .filter_map(|f| {
                sync::decrypt_string(&open.session, &f.name)
                    .ok()
                    .map(|n| (f.id.clone(), n))
            })
            .collect();

        let mut entries: Vec<(String, bool, bool, Option<String>)> =
            Vec::with_capacity(vault.ciphers.len());
        for c in &vault.ciphers {
            let Ok(name) = sync::cipher_name(&open.session, c) else {
                continue;
            };
            if !matches(&name) {
                continue;
            }
            let blob = sync::extract_rage_blob(&open.session, c).ok().flatten();
            let legacy = blob.as_deref().map(wrap_is_legacy).unwrap_or(false);
            let folder = c
                .folder_id
                .as_ref()
                .and_then(|id| folder_names.get(id).cloned());
            entries.push((name, blob.is_some(), legacy, folder));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        if json {
            let json_entries: Vec<serde_json::Value> = entries
                .into_iter()
                .map(|(name, is_rage, legacy, folder)| {
                    serde_json::json!({
                        "name": name,
                        "kind": if is_rage { "rage" } else { "plain" },
                        "source": "vault",
                        "folder": folder,
                        "legacy_wrap": legacy,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json_entries)
                    .map_err(|e| CmdError::InvalidArg(format!("json encode failed: {e}")))?
            );
            return Ok(());
        }

        let max = entries.iter().map(|(n, ..)| n.len()).max().unwrap_or(0);
        let mut any_legacy = false;
        for (name, is_rage, legacy, _folder) in entries {
            let marker = match (is_rage, legacy) {
                (true, true) => "protected [legacy-wrap]",
                (true, false) => "protected",
                (false, _) => "unprotected",
            };
            any_legacy |= legacy;
            println!("{:<width$}  {marker}", name, width = max);
        }
        if any_legacy {
            eprintln!(
                "([legacy-wrap] items share a FIDO2/passkey body key with every other item \
                 wrapped the old way; `rageterm reencrypt --legacy` rewrites them)"
            );
        }
        if let Some(synced) = vault_cache::last_synced_at() {
            eprintln!("(last synced {})", synced.format("%Y-%m-%d %H:%M:%S UTC"));
        }
    } else {
        let store_path = config::store_path()?;
        let store = Store::load(&store_path)?;
        if store.items.is_empty() {
            if json {
                println!("[]");
            } else {
                eprintln!("(no items -- use `rageterm set <name>` to add one or `rageterm login`)");
            }
            return Ok(());
        }

        let mut filtered: Vec<(&String, &crate::store::Item)> = store
            .items
            .iter()
            .filter(|(name, _)| matches(name))
            .collect();
        filtered.sort_by(|a, b| a.0.cmp(b.0));

        if json {
            let json_entries: Vec<serde_json::Value> = filtered
                .into_iter()
                .map(|(name, item)| {
                    serde_json::json!({
                        "name": name,
                        "kind": "rage",
                        "source": "store",
                        "modified": item.modified.to_rfc3339(),
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json_entries)
                    .map_err(|e| CmdError::InvalidArg(format!("json encode failed: {e}")))?
            );
            return Ok(());
        }

        let max_name = filtered.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        for (name, item) in filtered {
            println!(
                "{:<width$}  modified {}",
                name,
                item.modified.format("%Y-%m-%d %H:%M:%S UTC"),
                width = max_name
            );
        }
    }
    Ok(())
}

pub async fn cmd_get(
    name: &str,
    field: Option<&str>,
    append_newline: bool,
    yes: bool,
    no_wait: bool,
) -> Result<(), CmdError> {
    if io::stdout().is_terminal() {
        if let Some(envs) = detect_scrollback_hostility_from(std::env::vars()) {
            return Err(CmdError::InvalidArg(format!(
                "refusing to print `{name}` to an interactive terminal in {envs}; secrets \
                 may be retained in scrollback. Pipe or redirect it (`rageterm get {name} \
                 | ...`), or use `rageterm copy/exec/agent`, or `rageterm reveal --force`."
            )));
        }
    }
    let consent_guard = consent::require("Print", name, "stdout", yes)?;
    lock::set_wait(!no_wait);
    let r = decrypt_named_field(name, field.unwrap_or(""), &consent_guard);
    audit_helper::record_result(AuditKind::Reveal, name, Some("stdout"), &r);
    output::deliver_stdout(r?, append_newline)?;
    Ok(())
}

pub async fn cmd_copy(
    name: &str,
    clear_secs: u64,
    yes: bool,
    no_wait: bool,
) -> Result<(), CmdError> {
    let consent_guard = consent::require("Copy", name, "clipboard", yes)?;
    let r = decrypt_named_locked(name, no_wait, &consent_guard).await;
    audit_helper::record_result(AuditKind::Copy, name, Some("clipboard"), &r);
    let plaintext = r?;
    let expected_hash = output::hex_sha256(&plaintext);
    output::deliver_clipboard(plaintext, clear_secs, &expected_hash)?;

    if clear_secs > 0 {
        eprintln!("Copied `{name}` to clipboard. Auto-clearing in {clear_secs}s.");
    } else {
        eprintln!("Copied `{name}` to clipboard. (No auto-clear.)");
    }
    Ok(())
}

pub async fn cmd_totp(name: &str, copy: bool, yes: bool, no_wait: bool) -> Result<(), CmdError> {
    let destination = if copy { "clipboard" } else { "stdout" };
    let consent_guard = consent::require("Generate a TOTP code from", name, destination, yes)?;
    let r = decrypt_named_locked(name, no_wait, &consent_guard).await;
    audit_helper::record_result(AuditKind::Totp, name, Some(destination), &r);
    let plaintext = r?;
    let seed = Zeroizing::new(
        std::str::from_utf8(&plaintext)
            .map_err(|_| CmdError::InvalidArg("totp seed is not utf-8".into()))?
            .trim()
            .to_string(),
    );
    let code = ragewarden_core::totp::generate_for_uri_or_secret(seed.as_str())
        .map_err(|e| CmdError::InvalidArg(format!("totp: {e}")))?;
    drop(plaintext);

    if copy {
        let bytes = Zeroizing::new(code.code.as_bytes().to_vec());
        let plaintext_for_clipboard = Plaintext::from(bytes);
        let expected_hash = output::hex_sha256(&plaintext_for_clipboard);
        output::deliver_clipboard(
            plaintext_for_clipboard,
            output::DEFAULT_CLIPBOARD_CLEAR_SECS,
            &expected_hash,
        )?;
        eprintln!(
            "TOTP for `{name}` copied. Code valid for {}s; clipboard auto-clears in {}s.",
            code.seconds_remaining,
            output::DEFAULT_CLIPBOARD_CLEAR_SECS
        );
    } else {
        println!("{}\t{}", code.code, code.seconds_remaining);
    }
    Ok(())
}

pub async fn cmd_reveal(name: &str, yes: bool, no_wait: bool, force: bool) -> Result<(), CmdError> {
    if !force {
        if let Some(envs) = detect_scrollback_hostility_from(std::env::vars()) {
            return Err(CmdError::InvalidArg(format!(
                "refusing to reveal in {envs}; secrets may be retained in scrollback. \
                 Re-run with `--force`, or use `rageterm copy/exec/agent` to keep the \
                 plaintext off-screen."
            )));
        }
    }
    let consent_guard = consent::require("Reveal", name, "this terminal", yes)?;
    let r = decrypt_named_locked(name, no_wait, &consent_guard).await;
    audit_helper::record_result(AuditKind::Reveal, name, Some("this terminal"), &r);
    let plaintext = r?;
    output::deliver_reveal(plaintext)?;
    Ok(())
}

pub(crate) fn detect_scrollback_hostility_from<I, K, V>(envs: I) -> Option<String>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut tmux = false;
    let mut screen = false;
    let mut ssh = false;
    for (k, v) in envs {
        match k.as_ref() {
            "TMUX" if !v.as_ref().is_empty() => tmux = true,
            "STY" if !v.as_ref().is_empty() => screen = true,
            "SSH_CONNECTION" | "SSH_TTY" if !v.as_ref().is_empty() => ssh = true,
            _ => {}
        }
    }
    let mut tags: Vec<&str> = Vec::new();
    if tmux {
        tags.push("tmux");
    }
    if screen {
        tags.push("GNU screen");
    }
    if ssh {
        tags.push("ssh");
    }
    if tags.is_empty() {
        None
    } else {
        Some(tags.join(", "))
    }
}

pub async fn cmd_exec(
    name: &str,
    argv: &[String],
    via_env: bool,
    env: &output::ExecEnv,
    yes: bool,
    no_wait: bool,
) -> Result<i32, CmdError> {
    if argv.is_empty() {
        return Err(CmdError::InvalidArg(
            "exec: missing command after `--`".into(),
        ));
    }
    let dest = if via_env {
        format!("env $RAGEWARDEN_SECRET of `{}`", argv[0])
    } else {
        format!("FD 3 of `{}`", argv[0])
    };
    let consent_guard = consent::require("Pass", name, &dest, yes)?;
    let r = match decrypt_named_locked(name, no_wait, &consent_guard).await {
        Ok(plaintext) => {
            output::deliver_exec(plaintext, argv, via_env, env).map_err(CmdError::from)
        }
        Err(e) => Err(e),
    };
    audit_helper::record_result(AuditKind::Exec, name, Some(&dest), &r);
    r
}

async fn decrypt_named_locked(
    name: &str,
    no_wait: bool,
    consent: &consent::ConsentGuard,
) -> Result<Plaintext, CmdError> {
    lock::set_wait(!no_wait);
    decrypt_named(name, consent)
}

/// The cipher type of `name` in the synced vault; an offline item has no
/// server type and reads as a secure note (its payload is always v1).
fn item_cipher_type(name: &str) -> Result<u8, CmdError> {
    if let Some(open) = session::load()? {
        if let Some(vault) = vault_cache::load()? {
            if let Some(c) = find_cipher_by_name(&open.session, &vault, name) {
                return Ok(c.cipher_type);
            }
        }
    }
    Ok(ragewarden_core::protected::TYPE_SECURE_NOTE)
}

/// One field of `name`'s protected payload (core::protected): `""` is the
/// item's primary field, which is the whole secret of every single-field item.
pub fn decrypt_named_field(
    name: &str,
    field: &str,
    consent: &consent::ConsentGuard,
) -> Result<Plaintext, CmdError> {
    let payload = decrypt_payload(name, consent)?;
    ragewarden_core::protected::field(item_cipher_type(name)?, &payload, field)
        .map_err(|e| CmdError::Decrypt(e.to_string()))
}

/// The item's primary secret; see [`decrypt_named_field`].
pub fn decrypt_named(name: &str, consent: &consent::ConsentGuard) -> Result<Plaintext, CmdError> {
    decrypt_named_field(name, "", consent)
}

fn find_cipher_by_name<'a>(
    session: &ragewarden_core::sync::Session,
    vault: &'a Vault,
    name: &str,
) -> Option<&'a Cipher> {
    vault.ciphers.iter().find(|c| {
        sync::cipher_name(session, c)
            .map(|n| n == name)
            .unwrap_or(false)
    })
}

/// The stored age blob for `name`, from the synced vault or the offline store.
pub fn load_item_blob(name: &str) -> Result<AgeBlob, CmdError> {
    let rage_blob_armored = if let Some(open) = session::load()? {
        let vault = vault_cache::load()?.ok_or_else(|| {
            CmdError::InvalidArg(
                "no cached vault -- run `rageterm sync` first to fetch the vault".into(),
            )
        })?;
        let cipher = find_cipher_by_name(&open.session, &vault, name)
            .ok_or_else(|| CmdError::NotFound(name.to_string()))?;
        sync::extract_rage_blob(&open.session, cipher)
            .map_err(CmdError::Sync)?
            .ok_or_else(|| {
                CmdError::Decrypt(format!(
                    "cipher `{name}` has no `rage:v1` field -- was it created outside ragewarden?"
                ))
            })?
    } else {
        let store_path = config::store_path()?;
        let store = Store::load(&store_path)?;
        let item = store
            .get(name)
            .ok_or_else(|| CmdError::NotFound(name.to_string()))?;
        item.rage_blob.clone()
    };
    Ok(AgeBlob::from_bytes(rage_blob_armored.into_bytes()))
}

/// Labels of the enrolled physical devices whose keys this blob's header names.
/// Header-only: no device is touched. Empty means only a software key (or
/// nothing on this machine) can open it, so no tap will be asked for.
pub fn enrolled_devices_named_in(blob: &AgeBlob) -> Result<Vec<String>, CmdError> {
    let stanzas = ragewarden_core::parse_header_stanzas(blob)
        .map_err(|e| CmdError::Decrypt(e.to_string()))?;
    let registry = Identities::load()?;
    let mut out = Vec::new();
    for entry in registry.iter_chronological() {
        let named = match &entry.kind {
            IdentityKind::YubiKeyPiv {
                public_key_hex,
                serial,
                slot,
                mock: false,
            } => {
                let id = PivIdentity {
                    public_key: piv::PivPublicKey::from_hex(public_key_hex)?,
                    serial: *serial,
                    slot: *slot,
                    label: entry.label.clone(),
                    mock: false,
                };
                stanzas.iter().any(|s| id.names(s).unwrap_or(false))
            }
            IdentityKind::Fido2HmacSecret {
                credential_id_b64,
                rp_id,
                mock: false,
                uv,
                ..
            } => {
                use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
                let id = FidoIdentity {
                    credential_id: B64URL
                        .decode(credential_id_b64)
                        .map_err(|e| CmdError::Decrypt(format!("malformed cred id: {e}")))?,
                    rp_id: rp_id.clone(),
                    label: entry.label.clone(),
                    mock: false,
                    uv: *uv,
                    public_key: None,
                };
                stanzas.iter().any(|s| id.names(s).unwrap_or(false))
            }
            _ => false,
        };
        if named {
            out.push(entry.label.clone());
        }
    }
    Ok(out)
}

/// The only route from a stored blob to plaintext.
///
/// Takes a `ConsentGuard` by reference rather than an `action`/`yes` pair: the
/// guard cannot be built outside `consent`, so every caller has been through
/// the gate, and the guard is what decides which identities are allowed to see
/// the header.
///
/// Order matters and is the whole fix for "enrolling a YubiKey made `get`
/// weaker". When a real device is enrolled, the hardware-only identity list
/// goes first. It contains no software key, so:
///
///   * blob names one of our devices, device present -> the file key comes off
///     the device, which is the tap;
///   * blob names one of our devices, device absent / wrong / cancelled -> the
///     identity returns an error, `age` propagates it, and we return it. No
///     fallback: this is the fail-closed case;
///   * blob names none of our devices -> `NoMatchingIdentity`, which is the one
///     error that means "nothing physical can authorize this". Only then is the
///     software path offered, and only after `authorize_software` succeeds.
pub fn decrypt_payload(name: &str, consent: &consent::ConsentGuard) -> Result<Plaintext, CmdError> {
    if consent.item() != name {
        return Err(CmdError::Decrypt(format!(
            "refusing to decrypt `{name}` with consent taken for `{}`",
            consent.item()
        )));
    }

    let blob = load_item_blob(name)?;

    if consent.hardware() == consent::HardwareState::Real {
        let hardware = build_identity_list_for(consent::IdentityPolicy::HardwareOnly)?;
        if !hardware.is_empty() {
            match decrypt(&blob, &hardware) {
                Ok(plaintext) => return Ok(plaintext),
                Err(ragewarden_core::DecryptError::NoMatchingIdentity) => {}
                Err(e) => {
                    return Err(CmdError::Decrypt(format!(
                        "`{name}` is protected by an enrolled device and the device \
                         did not authorize it: {e}. Refusing to fall back to the \
                         software key -- that fallback is what would make an \
                         enrolled YubiKey worse than none."
                    )));
                }
            }
        }
    }

    consent.authorize_software()?;

    let identities = build_identity_list_for(consent::IdentityPolicy::SoftwareAllowed)?;
    let plaintext = decrypt(&blob, &identities).map_err(|e| CmdError::Decrypt(e.to_string()))?;
    Ok(plaintext)
}

/// Every enrolled identity, software keys included. For callers that are not
/// producing user-visible plaintext (`native-host` with its own opt-in, the
/// revision history writer).
pub fn build_identity_list() -> Result<Vec<Box<dyn Identity>>, CmdError> {
    build_identity_list_for(consent::IdentityPolicy::SoftwareAllowed)
}

/// `HardwareOnly` returns exactly the identities whose `try_unwrap_stanza`
/// reaches a physical device: real PIV and real FIDO2. The software key file,
/// the OS keyring key, paper recovery and every `mock: true` stand-in are left
/// out, so a file key produced from this list cost a device interaction.
pub fn build_identity_list_for(
    policy: consent::IdentityPolicy,
) -> Result<Vec<Box<dyn Identity>>, CmdError> {
    let hardware_only = policy == consent::IdentityPolicy::HardwareOnly;
    let mut out: Vec<Box<dyn Identity>> = Vec::new();

    let id_path = config::identity_path()?;
    if !hardware_only && id_path.exists() {
        let id = idfile::read(&id_path)?;
        let armored_secret = ragewarden_core::ArmoredAgeSecret::from_trusted(
            id.to_string().expose_secret().to_string(),
        );
        let sw = ragewarden_core::software_passphrase_identity(&armored_secret)
            .map_err(|e| CmdError::Decrypt(e.to_string()))?;
        out.push(Box::new(sw));
    }

    let registry = Identities::load()?;
    for entry in registry.iter_chronological() {
        match &entry.kind {
            IdentityKind::YubiKeyPiv {
                public_key_hex,
                serial,
                slot,
                mock,
            } => {
                if hardware_only && *mock {
                    continue;
                }
                out.push(Box::new(PivIdentity {
                    public_key: piv::PivPublicKey::from_hex(public_key_hex)?,
                    serial: *serial,
                    slot: *slot,
                    label: entry.label.clone(),
                    mock: *mock,
                }));
            }
            IdentityKind::Fido2HmacSecret {
                credential_id_b64,
                rp_id,
                mock,
                uv,
                public_key_hex,
                ..
            } => {
                if hardware_only && *mock {
                    continue;
                }
                use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
                let credential_id = B64URL
                    .decode(credential_id_b64)
                    .map_err(|e| CmdError::Decrypt(format!("malformed cred id: {e}")))?;
                out.push(Box::new(FidoIdentity {
                    credential_id,
                    rp_id: rp_id.clone(),
                    label: entry.label.clone(),
                    mock: *mock,
                    uv: *uv,
                    public_key: identities::fido_public_key(public_key_hex),
                }));
            }
            IdentityKind::OsKeyring {
                keyring_service,
                keyring_user,
                ..
            } => {
                if hardware_only {
                    continue;
                }
                match KeyringIdentity::open(keyring_service, keyring_user, entry.label.clone()) {
                    Ok(k) => out.push(Box::new(k)),
                    Err(e) => {
                        eprintln!(
                            "rageterm: keyring identity `{}` unavailable ({}); skipping",
                            entry.label, e
                        );
                    }
                }
            }
            IdentityKind::PaperRecovery { .. } => {
                if hardware_only {
                    continue;
                }
                if let Ok(Some(rec)) = RecoveryIdentity::load_if_enrolled() {
                    out.push(Box::new(rec));
                }
            }
        }
    }

    Ok(out)
}

fn hex_encode_32(b: &[u8; 32]) -> String {
    hex::encode(b)
}

pub fn list_item_names() -> Result<Vec<String>, CmdError> {
    if let Some(open) = session::load()? {
        let Some(vault) = vault_cache::load()? else {
            return Ok(Vec::new());
        };
        let mut names: Vec<String> = name_index(&open.session, &vault).keys().cloned().collect();
        names.sort();
        Ok(names)
    } else {
        let store_path = config::store_path()?;
        let store = Store::load(&store_path)?;
        Ok(store.items.keys().cloned().collect())
    }
}

fn require_session() -> Result<OpenSession, CmdError> {
    session::load()?.ok_or_else(|| {
        CmdError::InvalidArg(
            "not logged in -- run `rageterm login --server <URL> --email <addr>` first".into(),
        )
    })
}

fn require_session_plain() -> Result<OpenSession, CmdError> {
    session::load()?.ok_or_else(|| CmdError::InvalidArg("not logged in".into()))
}

fn new_client() -> Result<ReqwestClient, CmdError> {
    ReqwestClient::new().map_err(|e| CmdError::Sync(sync::SyncError::Http(e)))
}

static PASSWORD_STDIN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `--password-stdin`: take the master password from the first line of stdin.
pub fn set_password_stdin(on: bool) {
    PASSWORD_STDIN.store(on, std::sync::atomic::Ordering::SeqCst);
}

fn read_master_password(prompt: &str, confirm: bool) -> Result<secrecy::SecretString, CmdError> {
    use secrecy::SecretString;
    use std::io::BufRead;

    let from_stdin = PASSWORD_STDIN.load(std::sync::atomic::Ordering::SeqCst);
    let is_tty = io::stdin().is_terminal() && !from_stdin;
    if !is_tty && !from_stdin {
        eprintln!(
            "rageterm: reading the master password from stdin because it is not a terminal; \
             pass `--password-stdin` to say so explicitly."
        );
    }
    let confirm = confirm && is_tty;
    let raw = if is_tty {
        rpassword::prompt_password(prompt).map_err(CmdError::Io)?
    } else {
        let mut s = String::new();
        io::stdin().lock().read_line(&mut s)?;
        s.strip_suffix('\n').unwrap_or(&s).to_string()
    };
    if raw.is_empty() {
        return Err(CmdError::InvalidArg("master password is empty".into()));
    }
    if confirm {
        let again = if is_tty {
            rpassword::prompt_password("Confirm master password: ").map_err(CmdError::Io)?
        } else {
            let mut s = String::new();
            io::stdin().lock().read_line(&mut s)?;
            s.strip_suffix('\n').unwrap_or(&s).to_string()
        };
        if again != raw {
            return Err(CmdError::InvalidArg("passwords did not match".into()));
        }
    }
    Ok(SecretString::new(raw.into()))
}

fn hostname_or_unknown() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string())
}

/// Confirmation for *destructive* operations (delete an item, remove a
/// recipient, overwrite a native-host manifest). These are not credential uses,
/// so they never involve a device.
///
/// The read goes to the controlling terminal, not to stdin: the old stdin read
/// meant `printf 'y\n' | rageterm delete x` answered its own prompt, and any
/// piped input was consumed as consent.
pub fn confirm_action(prompt: &str) -> Result<(), CmdError> {
    consent::confirm(prompt).map_err(CmdError::from)
}

/// Read `--public-key` as a path first, then as a literal.
fn read_public_key_arg(arg: &str) -> Result<String, CmdError> {
    let path = std::path::Path::new(arg);
    if path.is_file() {
        return Ok(std::fs::read_to_string(path)?);
    }
    Ok(arg.to_string())
}

#[allow(clippy::too_many_arguments)]
pub async fn cmd_enroll_yubikey(
    slot: u8,
    label: Option<&str>,
    public_key: Option<&str>,
    no_wait: bool,
    allow_untouched_slot: bool,
    stanza_v2: bool,
    x25519: bool,
) -> Result<(), CmdError> {
    audit_helper::record_detail(
        ragewarden_core::audit::AuditKind::EnrollIdentity,
        "yubikey-piv",
    );
    let _guard = lock::acquire(!no_wait)?;
    let _ceremony = crate::ceremony::set(crate::ceremony::Ceremony::new(
        "Enroll",
        "a YubiKey PIV slot",
        "this vault's recipient set",
    ));
    let enrolled = enroll_piv_slot(
        slot,
        label,
        public_key,
        allow_untouched_slot,
        stanza_v2,
        x25519,
    )
    .await?;
    if !enrolled.mock {
        offer_fold_in(&enrolled.label).await?;
    }
    Ok(())
}

/// A PIV slot just enrolled: its identity id (also its recipient id), label
/// and recipient.
pub struct EnrolledSlot {
    pub id: String,
    pub label: String,
    pub recipient: Recipient,
    pub mock: bool,
}

const P256_SLOT_HINT: &str = "Generate a P-256 key in a free slot with `ykman piv keys generate \
     --algorithm ECCP256 --touch-policy always --pin-policy once <slot> p256.pem` (any \
     YubiKey 4/5) and pass the file.";

/// Prove possession of `slot`'s key, record it as an identity and a
/// recipient, and publish it. P-256 unless `x25519`: an X25519 slot cannot
/// sign the browser's unwrap proofs.
async fn enroll_piv_slot(
    slot: u8,
    label: Option<&str>,
    public_key: Option<&str>,
    allow_untouched_slot: bool,
    stanza_v2: bool,
    x25519: bool,
) -> Result<EnrolledSlot, CmdError> {
    let enrolled = if hw::mock_enabled() {
        enroll_mock_piv(slot, x25519)?
    } else {
        let pem = public_key.ok_or_else(|| {
            CmdError::InvalidArg(format!(
                "`enroll-yubikey` needs `--public-key` -- the public key already in the \
                 slot. {P256_SLOT_HINT} Enrollment then proves the card holds the matching \
                 private key, and reads the slot's touch policy back off the card (GET \
                 METADATA) before that proof. A slot that does not require a touch is \
                 refused, so rageterm never announces a tap the card will not wait for."
            ))
        })?;
        let material = read_public_key_arg(pem)?;
        let claimed = piv::parse_public_key(&material)?;
        if matches!(claimed, piv::PivPublicKey::X25519(_)) && !x25519 {
            return Err(CmdError::InvalidArg(format!(
                "this is an X25519 slot. New slots are P-256, which also sign the \
                 browser's per-unwrap proof; an X25519 slot cannot, so its browser \
                 unwraps stay unattested. {P256_SLOT_HINT} To enrol this slot anyway, pass \
                 `--x25519`; `rageterm migrate-piv` moves its items to a P-256 slot later."
            )));
        }
        piv::real_enroll_allowing_untouched_slot(slot, claimed, allow_untouched_slot)?
    };

    let base_label = label
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("YubiKey #{:08x} (slot {:#04x})", enrolled.serial, slot));
    let label = if enrolled.mock {
        hw::mock_label(&base_label)
    } else {
        base_label
    };

    let entry_id = identities::fresh_id();

    let mut ids = Identities::load()?;
    ids.insert(EnrolledIdentity {
        id: entry_id.clone(),
        kind: IdentityKind::YubiKeyPiv {
            public_key_hex: enrolled.public_key.to_hex(),
            serial: enrolled.serial,
            slot: enrolled.slot,
            mock: enrolled.mock,
        },
        label: label.clone(),
        created: Utc::now(),
        last_used: None,
    });
    ids.save()?;

    let recipient = match &enrolled.public_key {
        piv::PivPublicKey::X25519(pk) => Recipient::YubiKeyPiv {
            public_key: *pk,
            serial: enrolled.serial,
            slot: enrolled.slot,
            stanza_version: if stanza_v2 { 2 } else { 1 },
        },
        piv::PivPublicKey::P256(pk) => Recipient::YubiKeyPivP256 {
            public_key: pk.to_vec(),
            serial: enrolled.serial,
            slot: enrolled.slot,
        },
    };
    register_recipient(&entry_id, &label, recipient.clone()).await?;

    if enrolled.mock {
        eprintln!(
            "rageterm: NOT publishing this recipient to the cross-device registry -- it is \
             a software stand-in, and other devices would encrypt to it believing a \
             YubiKey guards it. The recipient exists only in this installation."
        );
    } else if let Err(e) =
        recipients::publish_wire_entry_to_registry(ragewarden_core::registry::WireEntry {
            stanza_version: (stanza_v2
                && matches!(enrolled.public_key, piv::PivPublicKey::X25519(_)))
            .then_some(2),
            ..recipients::piv_wire_entry(
                enrolled.public_key.bytes(),
                enrolled.serial,
                enrolled.slot,
                &label,
            )
        })
        .await
    {
        eprintln!(
            "(warning: enrolled locally but couldn't publish YubiKey to the cross-device registry: {e}. Other devices won't see this recipient until next `rageterm sync`.)"
        );
    }

    println!(
        "Enrolled YubiKey PIV identity `{label}` (id={entry_id}, serial={:08x}, slot={:#04x}, {}).",
        enrolled.serial,
        enrolled.slot,
        enrolled.public_key.curve()
    );
    Ok(EnrolledSlot {
        id: entry_id,
        label,
        recipient,
        mock: enrolled.mock,
    })
}

#[cfg(any(test, feature = "mock-hardware"))]
fn enroll_mock_piv(slot: u8, x25519: bool) -> Result<piv::EnrolledPiv, CmdError> {
    Ok(if x25519 {
        piv::mock_enroll(slot)?
    } else {
        piv::mock_enroll_p256(slot)?
    })
}

#[cfg(not(any(test, feature = "mock-hardware")))]
fn enroll_mock_piv(_slot: u8, _x25519: bool) -> Result<piv::EnrolledPiv, CmdError> {
    unreachable!("hw::mock_enabled() is a compile-time false in this build")
}

pub async fn cmd_enroll_fido2(
    rp: &str,
    label: Option<&str>,
    no_wait: bool,
) -> Result<(), CmdError> {
    audit_helper::record_detail(
        ragewarden_core::audit::AuditKind::EnrollIdentity,
        "fido2-hmac",
    );
    let _guard = lock::acquire(!no_wait)?;
    let _ceremony = crate::ceremony::set(crate::ceremony::Ceremony::new(
        "Enroll",
        "a FIDO2 credential",
        "this vault's recipient set",
    ));
    let enrolled = if hw::mock_enabled() {
        enroll_mock_fido(rp)?
    } else {
        fido::real_enroll(rp)?
    };

    let base_label = label
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("FIDO2 credential ({rp})"));
    let label = if enrolled.mock {
        hw::mock_label(&base_label)
    } else {
        base_label
    };
    let entry_id = identities::fresh_id();

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
    let credential_id_b64 = B64URL.encode(&enrolled.credential_id);
    let salt_hex: String = hex::encode(enrolled.salt);

    let mut ids = Identities::load()?;
    ids.insert(EnrolledIdentity {
        id: entry_id.clone(),
        kind: IdentityKind::Fido2HmacSecret {
            credential_id_b64: credential_id_b64.clone(),
            salt_hex,
            rp_id: enrolled.rp_id.clone(),
            mock: enrolled.mock,
            uv: enrolled.uv,
            public_key_hex: enrolled.public_key.map(hex::encode),
        },
        label: label.clone(),
        created: Utc::now(),
        last_used: None,
    });
    ids.save()?;

    register_recipient(
        &entry_id,
        &label,
        Recipient::Fido2HmacSecret {
            credential_id: enrolled.credential_id.clone(),
            salt: enrolled.salt,
            rp_id: enrolled.rp_id.clone(),
        },
    )
    .await?;

    if enrolled.mock {
        eprintln!(
            "rageterm: NOT publishing this recipient to the cross-device registry -- it is \
             a software stand-in, and other devices would encrypt to it believing a \
             security key guards it. The recipient exists only in this installation."
        );
    } else if let Err(e) = recipients::publish_wire_entry_to_registry(recipients::fido2_wire_entry(
        &enrolled.credential_id,
        &enrolled.salt,
        &enrolled.rp_id,
        &label,
        enrolled.public_key.as_ref().map(|k| &k[..]),
    ))
    .await
    {
        eprintln!(
            "(warning: enrolled locally but couldn't publish FIDO2 to the cross-device registry: {e}.)"
        );
    }

    println!("Enrolled FIDO2 identity `{label}` (id={entry_id}).");
    offer_fold_in(&label).await?;
    Ok(())
}

#[cfg(any(test, feature = "mock-hardware"))]
fn enroll_mock_fido(rp: &str) -> Result<fido::EnrolledFido, CmdError> {
    Ok(fido::mock_enroll(rp)?)
}

#[cfg(not(any(test, feature = "mock-hardware")))]
fn enroll_mock_fido(_rp: &str) -> Result<fido::EnrolledFido, CmdError> {
    unreachable!("hw::mock_enabled() is a compile-time false in this build")
}

pub async fn cmd_enroll_keyring(user: Option<&str>, label: Option<&str>) -> Result<(), CmdError> {
    audit_helper::record_detail(
        ragewarden_core::audit::AuditKind::EnrollIdentity,
        "os-keyring",
    );
    let user_owned = user
        .map(|s| s.to_string())
        .unwrap_or_else(hostname_or_unknown);
    let user = user_owned.as_str();
    let enrolled = keyring_id::enroll(KEYRING_SERVICE, user)?;

    let label = label
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("OS keyring ({user})"));
    let entry_id = identities::fresh_id();

    let pub_bytes = age_pubkey_to_bytes(enrolled.armored_pubkey.as_str())?;

    let mut ids = Identities::load()?;
    ids.insert(EnrolledIdentity {
        id: entry_id.clone(),
        kind: IdentityKind::OsKeyring {
            public_key_hex: hex_encode_32(&pub_bytes),
            armored_pubkey: enrolled.armored_pubkey.clone(),
            keyring_service: enrolled.service.clone(),
            keyring_user: enrolled.user.clone(),
        },
        label: label.clone(),
        created: Utc::now(),
        last_used: None,
    });
    ids.save()?;

    register_recipient(
        &entry_id,
        &label,
        Recipient::SoftwarePassphrase {
            armored_pubkey: enrolled.armored_pubkey.clone(),
        },
    )
    .await?;

    if let Err(e) = recipients::publish_wire_entry_to_registry(recipients::software_wire_entry(
        enrolled.armored_pubkey.as_str(),
        &label,
    ))
    .await
    {
        eprintln!(
            "(warning: enrolled locally but couldn't publish OS keyring to the cross-device registry: {e}.)"
        );
    }

    println!(
        "Enrolled OS keyring identity `{label}` (id={entry_id}, keyring service `{}` user `{}`).",
        enrolled.service, enrolled.user
    );
    offer_fold_in(&label).await?;
    Ok(())
}

pub async fn cmd_enroll_recovery(label: &str, no_confirm: bool) -> Result<(), CmdError> {
    audit_helper::record_detail(
        ragewarden_core::audit::AuditKind::EnrollIdentity,
        "paper-recovery",
    );
    let enrolled = recovery_mod::enroll(no_confirm)?;
    let entry_id = identities::fresh_id();

    let mut ids = Identities::load()?;
    ids.insert(EnrolledIdentity {
        id: entry_id.clone(),
        kind: IdentityKind::PaperRecovery {
            armored_pubkey: enrolled.armored_pubkey.clone(),
        },
        label: label.to_string(),
        created: Utc::now(),
        last_used: None,
    });
    ids.save()?;

    register_recipient(
        &entry_id,
        label,
        Recipient::SoftwarePassphrase {
            armored_pubkey: enrolled.armored_pubkey.clone(),
        },
    )
    .await?;

    if let Err(e) = recipients::publish_wire_entry_to_registry(recipients::recovery_wire_entry(
        enrolled.armored_pubkey.as_str(),
        label,
    ))
    .await
    {
        eprintln!(
            "(warning: enrolled locally but couldn't publish recovery to the cross-device registry: {e}.)"
        );
    }

    println!("Enrolled paper recovery recipient (id={entry_id}).");
    println!("Public key (recipient): {}", enrolled.armored_pubkey);
    println!(
        "The secret exists only as the 24 words. On a machine that has lost its other \
         keys, run `rageterm recover --save` and type them."
    );
    offer_fold_in(label).await?;
    Ok(())
}

pub fn cmd_recover(save: bool) -> Result<(), CmdError> {
    use age::secrecy::ExposeSecret;

    let identity = recovery_mod::recover_from_typed_phrase()?;
    let armored_pub = identity.to_public().to_string();

    if save {
        let path = config::recovery_path()?;
        if path.exists() {
            let existing = recovery_mod::read_if_enrolled()?;
            if let Some(existing) = existing {
                if existing.to_public().to_string() == armored_pub {
                    println!("Recovery identity at {} already matches.", path.display());
                    return Ok(());
                }
                return Err(CmdError::InvalidArg(format!(
                    "{} holds a different recovery key (pubkey={}); refusing to overwrite. \
                     Remove the file first if you really want to replace it.",
                    path.display(),
                    existing.to_public(),
                )));
            }
        }
        config::ensure_config_dir()?;
        let secret = identity.to_string();
        config::write_private(&path, secret.expose_secret().as_bytes())?;
        println!("Wrote recovery identity to {}.", path.display());
    } else {
        println!("Recovered public key (recipient): {armored_pub}");
        println!("Re-run with `--save` to write it to recovery.age.");
    }
    Ok(())
}

/// No `--yes` bypass. `--yes` documents itself as a way past the *read*
/// confirmation on a software-only vault; this prompt guards a bare
/// `delete_cipher` with no trash, no soft delete and no history revision, so a
/// flag that skips a re-readable secret must not also skip an unrecoverable one.
pub async fn cmd_delete(name: &str) -> Result<(), CmdError> {
    let open = session::load()?
        .ok_or_else(|| CmdError::InvalidArg("not logged in -- run `rageterm login`".into()))?;
    let client = new_client()?;
    let cached = vault_cache::load()?;
    let existing = cached
        .as_ref()
        .and_then(|v| find_cipher_by_name(&open.session, v, name))
        .ok_or_else(|| CmdError::NotFound(name.to_string()))?;
    let cipher_id = existing
        .id
        .clone()
        .ok_or_else(|| CmdError::InvalidArg("cached cipher has no id".into()))?;

    confirm_action(&format!("Delete cipher `{name}` (id={cipher_id})"))?;
    history_helper::record_deletion(existing)
        .await
        .map_err(|e| {
            CmdError::InvalidArg(format!(
                "could not record `{name}` in the revision history ({e}); not deleting it"
            ))
        })?;
    let r = sync::delete_cipher(&client, &open.server, &open.session, &cipher_id).await;
    audit_helper::record_result(AuditKind::Delete, name, None, &r);
    r?;

    let mut vault = cached.unwrap_or_default();
    vault
        .ciphers
        .retain(|c| c.id.as_deref() != Some(cipher_id.as_str()));
    vault_cache::save(&vault)?;

    println!("Deleted `{name}`.");
    Ok(())
}

/// Move an item into a folder (or out of every folder) without touching its
/// secret: the folder is set through the partial endpoint, so no plaintext is
/// produced and no tap is needed.
pub async fn cmd_mv(name: &str, folder: Option<&str>) -> Result<(), CmdError> {
    let open = require_session_plain()?;
    let client = new_client()?;
    let vault = fetch_vault(&client, &open.server, &open.session).await?;
    let cipher = find_cipher_by_name(&open.session, &vault, name)
        .ok_or_else(|| CmdError::NotFound(name.to_string()))?;
    let cipher_id = cipher
        .id
        .clone()
        .ok_or_else(|| CmdError::InvalidArg("cipher has no id".into()))?;
    let folder_id = folder
        .map(|f| resolve_folder_name(&open.session, &vault, f))
        .transpose()?;
    let saved = sync::set_folder_on(
        &client,
        &open.server,
        &open.session,
        &cipher_id,
        folder_id.as_deref(),
    )
    .await?;
    let mut vault = vault;
    vault.upsert_cipher(saved);
    vault_cache::save(&vault)?;
    match folder {
        Some(f) => println!("Moved `{name}` into folder `{f}`."),
        None => println!("Moved `{name}` out of its folder."),
    }
    Ok(())
}

pub async fn cmd_folders_list() -> Result<(), CmdError> {
    let open = require_session_plain()?;
    let cached = vault_cache::load()?;
    let vault = match cached {
        Some(v) => v,
        None => {
            let client = new_client()?;
            let v = fetch_vault(&client, &open.server, &open.session).await?;
            vault_cache::save(&v)?;
            v
        }
    };
    let folders = &vault.folders;
    if folders.is_empty() {
        println!("(no folders)");
        return Ok(());
    }

    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for c in &vault.ciphers {
        if let Some(fid) = c.folder_id.as_deref() {
            *counts.entry(fid).or_insert(0) += 1;
        }
    }

    let max_id = folders.iter().map(|f| f.id.len()).max().unwrap_or(0);
    let max_count = folders
        .iter()
        .map(|f| counts.get(f.id.as_str()).copied().unwrap_or(0))
        .max()
        .unwrap_or(0);
    let count_w = max_count.to_string().len();
    for f in folders {
        let name = sync::decrypt_string(&open.session, &f.name)
            .unwrap_or_else(|_| "(undecryptable)".into());
        let n = counts.get(f.id.as_str()).copied().unwrap_or(0);
        println!(
            "{:<id_w$}  {:>count_w$}  {name}",
            f.id,
            n,
            id_w = max_id,
            count_w = count_w,
        );
    }
    Ok(())
}

pub async fn cmd_folders_create(name: &str) -> Result<(), CmdError> {
    let open = require_session_plain()?;
    let client = new_client()?;
    let f = sync::create_folder(&client, &open.server, &open.session, name).await?;
    let mut vault = vault_cache::load()?.unwrap_or_default();
    vault.folders.retain(|x| x.id != f.id);
    vault.folders.push(f.clone());
    vault_cache::save(&vault)?;
    println!("Created folder `{name}` (id={}).", f.id);
    Ok(())
}

pub async fn cmd_folders_rename(folder_id: &str, name: &str) -> Result<(), CmdError> {
    let open = require_session_plain()?;
    let client = new_client()?;
    let f = sync::update_folder(&client, &open.server, &open.session, folder_id, name).await?;
    let mut vault = vault_cache::load()?.unwrap_or_default();
    vault.folders.retain(|x| x.id != f.id);
    vault.folders.push(f.clone());
    vault_cache::save(&vault)?;
    println!("Renamed folder `{folder_id}` to `{name}`.");
    Ok(())
}

/// No `--yes` bypass -- see [`cmd_delete`].
pub async fn cmd_folders_delete(folder_id: &str) -> Result<(), CmdError> {
    let open = require_session_plain()?;
    let client = new_client()?;
    confirm_action(&format!("Delete folder `{folder_id}`"))?;
    sync::delete_folder(&client, &open.server, &open.session, folder_id).await?;
    let mut vault = vault_cache::load()?.unwrap_or_default();
    vault.folders.retain(|x| x.id != folder_id);
    vault_cache::save(&vault)?;
    println!("Deleted folder `{folder_id}`.");
    Ok(())
}

pub async fn cmd_recipients_list() -> Result<(), CmdError> {
    let list = recipients::load().await?;
    if list.entries.is_empty() {
        println!(
            "(no recipients enrolled -- run `rageterm enroll-software-identity` or one of the `enroll-*` commands)"
        );
        return Ok(());
    }
    let max_id = list.entries.keys().map(|k| k.len()).max().unwrap_or(0);
    let max_kind = list
        .iter_chronological()
        .map(|e| recipient_kind_str(&e.recipient).len())
        .max()
        .unwrap_or(0);
    let enrolled = Identities::load()?;
    println!(
        "{:<id_w$}  {:<kind_w$}  {:<20}  LABEL",
        "ID",
        "KIND",
        "CREATED",
        id_w = max_id,
        kind_w = max_kind,
    );
    let mut any_mock = false;
    for e in list.iter_chronological() {
        let mock = hw::is_mock_label(&e.label) || recipient_is_mock(&enrolled, &e.recipient);
        any_mock |= mock;
        let kind = recipient_kind_str(&e.recipient);
        println!(
            "{:<id_w$}  {:<kind_w$}  {:<20}  {}{}{}",
            e.id,
            kind,
            e.created.format("%Y-%m-%d %H:%M:%S"),
            if mock { "[MOCK] " } else { "" },
            e.label,
            attestation_flag(&enrolled, &e.recipient),
            id_w = max_id,
            kind_w = max_kind,
        );
    }
    if any_mock {
        eprintln!(
            "\nrageterm: entries marked [MOCK] are software stand-ins, not devices. \
             They are never published to the cross-device registry, and a release build \
             cannot decrypt with them."
        );
    }

    match recipients::load_encrypt_plan().await {
        Ok(plan) if !plan.skips.is_empty() => {
            println!("\nNot wrapped to by writes from this machine:");
            for s in &plan.skips {
                println!("  {}", s.describe());
            }
        }
        Ok(_) => {}
        Err(e) => eprintln!(
            "\nrageterm: could not determine which recipients this machine can wrap to: {e}"
        ),
    }
    Ok(())
}

/// What `recipients list` says about a device whose browser unwraps cannot be
/// attested yet, and the step that fixes it.
pub(crate) fn attestation_flag(enrolled: &Identities, recipient: &Recipient) -> &'static str {
    match recipient {
        Recipient::YubiKeyPiv { .. } => "  [unattested, legacy X25519: `rageterm migrate-piv`]",
        Recipient::Fido2HmacSecret { credential_id, .. } => {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
            let unknown_key = enrolled.items.values().any(|e| {
                matches!(&e.kind, IdentityKind::Fido2HmacSecret {
                    credential_id_b64,
                    public_key_hex: None,
                    ..
                } if B64URL.decode(credential_id_b64).ok().as_ref() == Some(credential_id))
            });
            if unknown_key {
                "  [unattested: `rageterm attest-fido2`, one touch]"
            } else {
                ""
            }
        }
        _ => "",
    }
}

fn recipient_is_mock(enrolled: &Identities, recipient: &Recipient) -> bool {
    match recipient {
        Recipient::Fido2HmacSecret { credential_id, .. } => {
            enrolled.is_mock_fido_credential(credential_id)
        }
        Recipient::YubiKeyPiv { serial, slot, .. }
        | Recipient::YubiKeyPivP256 { serial, slot, .. } => {
            let want = match recipient {
                Recipient::YubiKeyPiv { public_key, .. } => hex::encode(public_key),
                Recipient::YubiKeyPivP256 { public_key, .. } => hex::encode(public_key),
                _ => unreachable!("matched above"),
            };
            enrolled.items.values().any(|e| match &e.kind {
                IdentityKind::YubiKeyPiv {
                    public_key_hex,
                    serial: s,
                    slot: sl,
                    mock,
                } => {
                    *mock && s == serial && sl == slot && public_key_hex.eq_ignore_ascii_case(&want)
                }
                _ => false,
            })
        }
        _ => false,
    }
}

/// No `--yes` bypass -- see [`cmd_delete`]. Removing a recipient also drops the
/// keyring entry behind it, and nothing already wrapped to it can be re-wrapped
/// afterwards.
pub async fn cmd_recipients_remove(id: &str) -> Result<(), CmdError> {
    let list = recipients::load().await?;
    let entry = list
        .entries
        .get(id)
        .ok_or_else(|| CmdError::NotFound(id.to_string()))?;

    confirm_action(&format!(
        "Remove recipient `{}` (kind: {}, label: {})",
        entry.id,
        recipient_kind_str(&entry.recipient),
        entry.label,
    ))?;
    retire_recipient(id).await?;
    println!("Removed recipient `{id}`.");
    Ok(())
}

/// Forget recipient `id` here and unpublish it from the registry, without
/// asking (the caller has).
async fn retire_recipient(id: &str) -> Result<(), CmdError> {
    let list = recipients::load().await?;
    let entry = list
        .entries
        .get(id)
        .ok_or_else(|| CmdError::NotFound(id.to_string()))?;

    audit_helper::record_with(
        ragewarden_core::audit::AuditKind::RemoveRecipient,
        entry.id.clone(),
        format!("{} ({})", entry.label, recipient_kind_str(&entry.recipient)),
    );

    recipients::remove(id).await?;

    let mut ids = Identities::load()?;
    if let Some(removed) = ids.remove(id) {
        if let Some(registry_id) = recipients::registry_id_for_enrolled_identity(&removed.kind) {
            if let Err(e) = recipients::unpublish_from_registry(&registry_id).await {
                eprintln!(
                    "(warning: removed locally but couldn't unpublish from the cross-device registry: {e})"
                );
            }
        }
        if let IdentityKind::OsKeyring {
            keyring_service,
            keyring_user,
            ..
        } = &removed.kind
        {
            if let Err(e) = keyring_id::delete(keyring_service, keyring_user) {
                eprintln!("rageterm: removed recipient but could not delete keyring entry: {e}");
            }
        }
    }
    ids.save()?;
    Ok(())
}

/// Recover each FIDO2 credential's public key that enrollment did not keep
/// (or `id`'s), with one touch each, store it, and publish it as the registry
/// entry's `attestationPublicKey` so the browser can verify that credential's
/// native-host unwraps.
pub async fn cmd_attest_fido2(id: Option<&str>, no_wait: bool) -> Result<(), CmdError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
    let mut ids = Identities::load()?;
    let targets: Vec<(String, String, Vec<u8>, String, bool)> = ids
        .items
        .iter()
        .filter_map(|(key, e)| match &e.kind {
            IdentityKind::Fido2HmacSecret {
                credential_id_b64,
                rp_id,
                mock,
                public_key_hex,
                ..
            } if id.map_or(public_key_hex.is_none(), |want| want == key) => Some((
                key.clone(),
                e.label.clone(),
                B64URL.decode(credential_id_b64).ok()?,
                rp_id.clone(),
                *mock,
            )),
            _ => None,
        })
        .collect();
    if targets.is_empty() {
        return match id {
            Some(want) => Err(CmdError::NotFound(format!("FIDO2 identity `{want}`"))),
            None => {
                println!("Every enrolled FIDO2 credential's public key is already known.");
                Ok(())
            }
        };
    }
    let _guard = lock::acquire(!no_wait)?;
    let _ceremony = crate::ceremony::set(crate::ceremony::Ceremony::new(
        "Attest",
        "a FIDO2 credential",
        "the browser's unwrap proofs",
    ));
    for (key, label, credential_id, rp_id, mock) in targets {
        let public_key = fido::recover_public_key(&credential_id, &rp_id, mock)?;
        if let Some(e) = ids.items.get_mut(&key) {
            if let IdentityKind::Fido2HmacSecret { public_key_hex, .. } = &mut e.kind {
                *public_key_hex = Some(hex::encode(public_key));
            }
        }
        ids.save()?;
        println!("Recovered the public key of `{label}` (id={key}).");
    }
    publish_attestation_keys().await;
    Ok(())
}

/// Publish the attestation keys of this machine's devices that the registry
/// lacks; a failure is a warning, retried at the next sync.
async fn publish_attestation_keys() {
    match recipients::publish_missing_attestation_keys().await {
        Ok(0) => {}
        Ok(n) => println!("Published the attestation key of {n} device(s) to the registry."),
        Err(e) => eprintln!(
            "(warning: couldn't publish attestation keys to the registry: {e}; the next \
             `rageterm sync` retries)"
        ),
    }
}

/// The enrolled P-256 slot holding `key`, if any.
fn enrolled_p256_slot(ids: &Identities, key: &piv::PivPublicKey) -> Option<EnrolledSlot> {
    let piv::PivPublicKey::P256(pk) = key else {
        return None;
    };
    ids.items.iter().find_map(|(id, e)| match &e.kind {
        IdentityKind::YubiKeyPiv {
            public_key_hex,
            serial,
            slot,
            mock,
        } if public_key_hex.eq_ignore_ascii_case(&key.to_hex()) => Some(EnrolledSlot {
            id: id.clone(),
            label: e.label.clone(),
            recipient: Recipient::YubiKeyPivP256 {
                public_key: pk.to_vec(),
                serial: *serial,
                slot: *slot,
            },
            mock: *mock,
        }),
        _ => None,
    })
}

/// Every protected item's name: the synced vault's and the local store's.
fn all_protected_item_names() -> Result<Vec<String>, CmdError> {
    let mut names = Vec::new();
    if let Some(open) = session::load()? {
        if let Some(vault) = vault_cache::load()? {
            for c in &vault.ciphers {
                if sync::extract_rage_blob(&open.session, c)
                    .ok()
                    .flatten()
                    .is_none()
                {
                    continue;
                }
                if let Ok(n) = sync::cipher_name(&open.session, c) {
                    names.push(n);
                }
            }
        }
    }
    for n in Store::load(&config::store_path()?)?.items.keys() {
        if !names.contains(n) {
            names.push(n.clone());
        }
    }
    Ok(names)
}

/// Move every item from an enrolled X25519 PIV slot to a P-256 one: enrol the
/// P-256 slot, re-wrap each item that names the X25519 slot to the current
/// recipient set with the P-256 slot in its place, and retire the X25519
/// recipient once nothing needs it.
#[allow(clippy::too_many_arguments)]
pub async fn cmd_migrate_piv(
    slot: Option<u8>,
    public_key: Option<&str>,
    label: Option<&str>,
    from: Option<&str>,
    allow_untouched_slot: bool,
    yes: bool,
    no_wait: bool,
) -> Result<(), CmdError> {
    let ids = Identities::load()?;
    let legacy: Vec<(String, EnrolledIdentity)> = ids
        .items
        .iter()
        .filter(|(key, e)| {
            matches!(&e.kind, IdentityKind::YubiKeyPiv { public_key_hex, .. } if public_key_hex.len() == 64)
                && from.is_none_or(|f| f == key.as_str())
        })
        .map(|(k, e)| (k.clone(), e.clone()))
        .collect();
    let (legacy_id, legacy_entry) = match legacy.as_slice() {
        [] => {
            println!("No X25519 PIV slot is enrolled here; nothing to migrate.");
            return Ok(());
        }
        [one] => one.clone(),
        many => {
            return Err(CmdError::InvalidArg(format!(
                "several X25519 slots are enrolled; name one with --from: {}",
                many.iter()
                    .map(|(k, e)| format!("{k} ({})", e.label))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    };
    let IdentityKind::YubiKeyPiv {
        public_key_hex,
        serial,
        slot: legacy_slot,
        mock,
    } = &legacy_entry.kind
    else {
        unreachable!("filtered to PIV above");
    };
    let legacy_key = piv::PivPublicKey::from_hex(public_key_hex)?;
    let legacy_identity = PivIdentity {
        public_key: legacy_key.clone(),
        serial: *serial,
        slot: *legacy_slot,
        label: legacy_entry.label.clone(),
        mock: *mock,
    };

    refresh_vault_cache().await?;
    let mut names = Vec::new();
    for name in all_protected_item_names()? {
        let blob = load_item_blob(&name)?;
        let stanzas = ragewarden_core::parse_header_stanzas(&blob)
            .map_err(|e| CmdError::Decrypt(e.to_string()))?;
        if stanzas
            .iter()
            .any(|s| legacy_identity.names(s).unwrap_or(false))
        {
            names.push(name);
        }
    }

    let Some(slot) = slot.filter(|_| public_key.is_some() || hw::mock_enabled()) else {
        return Err(CmdError::InvalidArg(format!(
            "Migrating `{}` (X25519, slot {:#04x}) to a P-256 slot, which also signs the \
             browser's per-unwrap proof:\n  1. Generate a P-256 key in a free slot, e.g. \
             9d: `ykman piv keys generate --algorithm ECCP256 --touch-policy always \
             --pin-policy once 9d p256.pem`\n  2. `rageterm migrate-piv --slot 0x9d \
             --public-key p256.pem`\nrageterm proves the card holds that key, re-wraps the \
             {} item(s) that name the X25519 slot to it (a touch each), and retires the \
             X25519 recipient.",
            legacy_entry.label,
            legacy_slot,
            names.len()
        )));
    };

    let hw_real = consent::hardware_state()
        .map(|s| s == consent::HardwareState::Real)
        .unwrap_or(false);
    if !(yes && !hw_real) {
        confirm_action(&format!(
            "Use slot {slot:#04x}, re-wrap {} item(s) from `{}` to it (a touch each) and \
             retire `{}`",
            names.len(),
            legacy_entry.label,
            legacy_entry.label
        ))?;
    }
    let already = match public_key {
        Some(pk) => enrolled_p256_slot(&ids, &piv::parse_public_key(&read_public_key_arg(pk)?)?),
        None => None,
    };
    let new_slot = match already {
        Some(existing) => {
            println!(
                "Slot `{}` is already enrolled; re-wrapping to it.",
                existing.label
            );
            existing
        }
        None => {
            let _guard = lock::acquire(!no_wait)?;
            let _ceremony = crate::ceremony::set(crate::ceremony::Ceremony::new(
                "Enroll",
                "a P-256 YubiKey PIV slot",
                "this vault's recipient set",
            ));
            enroll_piv_slot(slot, label, public_key, allow_untouched_slot, false, false).await?
        }
    };

    let plan = recipients::load_encrypt_plan().await?;
    recipients::warn_about_skips(&plan.skips);
    let legacy_bytes = legacy_key.bytes().to_vec();
    let target: Vec<Recipient> = plan
        .selection
        .recipients
        .into_iter()
        .filter(|r| !matches!(r, Recipient::YubiKeyPiv { public_key, .. } if public_key[..] == legacy_bytes[..]))
        .collect();
    let same_key = |r: &Recipient| match (r, &new_slot.recipient) {
        (
            Recipient::YubiKeyPivP256 { public_key: a, .. },
            Recipient::YubiKeyPivP256 { public_key: b, .. },
        ) => a == b,
        _ => false,
    };
    if !target.iter().any(same_key) {
        return Err(CmdError::InvalidArg(format!(
            "the new slot `{}` is not in this machine's encrypt plan (is it set not to be \
             wrapped to by default?); nothing was re-wrapped",
            new_slot.label
        )));
    }

    let mut failed = Vec::new();
    for n in &names {
        audit_helper::record_with(
            ragewarden_core::audit::AuditKind::Rotate,
            n.clone(),
            format!("migrate-piv {legacy_id} -> {}", new_slot.id),
        );
        match rewrap_one(
            n,
            "the P-256 slot",
            &target,
            &target,
            "Migrate",
            true,
            no_wait,
        )
        .await
        {
            Ok(_) => println!("  re-wrapped `{n}` to `{}`", new_slot.label),
            Err(CmdError::Cancelled) => return Err(CmdError::Cancelled),
            Err(e) => {
                eprintln!("  FAILED `{n}`: {e}");
                failed.push(n.clone());
            }
        }
    }
    if !failed.is_empty() {
        return Err(CmdError::InvalidArg(format!(
            "{} item(s) still name `{}` ({}); it stays enrolled. Run `rageterm migrate-piv \
             --from {legacy_id} --slot {slot:#04x} --public-key ...` again to finish.",
            failed.len(),
            legacy_entry.label,
            failed.join(", ")
        )));
    }
    retire_recipient(&legacy_id).await?;
    println!(
        "Migrated {} item(s) from `{}` to `{}` and retired the X25519 slot.",
        names.len(),
        legacy_entry.label,
        new_slot.label
    );
    Ok(())
}

/// Decrypt `name` and re-encrypt it to `target_recipients`, saving the new
/// blob. The pre-rotation value goes to the history document as it was, so it
/// stays openable by the recipients it was wrapped to even when `target`
/// narrows; `history_recipients` names them on the entry. `action` is the
/// consent/ceremony label. Decrypting is a
/// use of the credential, so it takes the same gate as `get`.
async fn rewrap_one(
    name: &str,
    destination: &str,
    history_recipients: &[Recipient],
    target_recipients: &[Recipient],
    action: &str,
    yes: bool,
    no_wait: bool,
) -> Result<Vec<String>, CmdError> {
    let consent_guard = consent::require(action, name, destination, yes)?;

    let prf_outputs = build_prf_outputs_for(target_recipients)?;
    let prf_table: Vec<PrfEntry<'_>> = prf_table_from(&prf_outputs);

    if let Some(open) = session::load()? {
        if let Some(cached) = vault_cache::load()? {
            if let Some(existing) = find_cipher_by_name(&open.session, &cached, name) {
                history_helper::record_prior_revision(existing, history_recipients).await;
            }
        }
    }

    lock::set_wait(!no_wait);
    let plaintext = decrypt_payload(name, &consent_guard)?;

    let blob = encrypt_with_prf(&plaintext, target_recipients, &prf_table)
        .map_err(|e| CmdError::Encrypt(e.to_string()))?;
    drop(plaintext);

    let armored = String::from_utf8(blob.0)
        .map_err(|e| CmdError::Encrypt(format!("blob is not valid UTF-8: {e}")))?;
    save_rage_blob_under_name(name, &armored).await?;

    let session = session::load()?;
    Ok(history_helper::recipient_summary_labels(
        session.as_ref().map(|o| &o.session),
        target_recipients,
    )
    .await)
}

/// The protected (rage-wrapped) item names in the vault, optionally filtered to
/// one folder. Fetches a fresh vault so a bulk re-encrypt can't miss an item a
/// sibling device added since this machine last synced.
/// The item's blob has a PRF stanza in the pre-`wrap_salt` format, whose body
/// key every secret wrapped to that authenticator shares; `reencrypt --legacy`
/// rewrites it in the current format.
pub fn wrap_is_legacy(armored: &str) -> bool {
    ragewarden_core::legacy_prf_wraps(&AgeBlob::from_bytes(armored.as_bytes().to_vec()))
        .map(|n| n > 0)
        .unwrap_or(false)
}

async fn protected_item_names(
    folder_filter: Option<&str>,
    legacy_only: bool,
) -> Result<Vec<String>, CmdError> {
    let Some(open) = session::load()? else {
        return Ok(Vec::new());
    };
    let client = new_client()?;
    let vault = fetch_vault(&client, &open.server, &open.session).await?;
    vault_cache::save(&vault)?;

    let folder_names: std::collections::HashMap<String, String> = vault
        .folders
        .iter()
        .filter_map(|f| {
            sync::decrypt_string(&open.session, &f.name)
                .ok()
                .map(|n| (f.id.clone(), n))
        })
        .collect();

    let mut names = Vec::new();
    for c in &vault.ciphers {
        let Ok(name) = sync::cipher_name(&open.session, c) else {
            continue;
        };
        let Some(blob) = sync::extract_rage_blob(&open.session, c).ok().flatten() else {
            continue;
        };
        if legacy_only && !wrap_is_legacy(&blob) {
            continue;
        }
        if let Some(want) = folder_filter {
            let folder = c
                .folder_id
                .as_ref()
                .and_then(|id| folder_names.get(id).map(String::as_str));
            if folder != Some(want) {
                continue;
            }
        }
        names.push(name);
    }
    names.sort();
    names.dedup();
    Ok(names)
}

/// Re-encrypt items to the CURRENT recipient set -- folds a newly-enrolled
/// recipient into secrets stored before it existed. One item by name, or a
/// batch via `--all` (optionally `--folder`) or `--only a,b,c`.
/// Fetch the vault fresh and save it to the cache, so a following decrypt reads
/// the CURRENT blob. `reencrypt` is decrypt-then-(last-write-wins)-write, so
/// operating off a stale cache would re-wrap an OLD plaintext over a sibling's
/// newer server value. The `--all` path gets this via protected_item_names; the
/// single/`--only` paths call this before they decrypt.
async fn refresh_vault_cache() -> Result<(), CmdError> {
    if let Some(open) = session::load()? {
        let client = new_client()?;
        let vault = fetch_vault(&client, &open.server, &open.session).await?;
        vault_cache::save(&vault)?;
    }
    Ok(())
}

/// True when an item simply could not be handled by THIS machine -- it holds no
/// key that opens it, or it is not present -- which is a reason to skip it in a
/// batch, not to fail the whole run. Network/disk/write failures are NOT this:
/// they must propagate so the caller (e.g. offer_fold_in) knows the fold-in was
/// incomplete.
fn is_decrypt_skippable(e: &CmdError) -> bool {
    matches!(
        e,
        CmdError::Decrypt(_) | CmdError::NotFound(_) | CmdError::Hardware(_)
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn cmd_reencrypt(
    name: Option<&str>,
    all: bool,
    legacy: bool,
    folder: Option<&str>,
    only: Option<&str>,
    allow_revoke: bool,
    yes: bool,
    no_wait: bool,
) -> Result<(), CmdError> {
    let selectors = [name.is_some(), all, legacy, only.is_some()]
        .iter()
        .filter(|b| **b)
        .count();
    if selectors == 0 {
        return Err(CmdError::InvalidArg(
            "name one item, or pass --all, --legacy or --only <names>".into(),
        ));
    }
    if selectors > 1 {
        return Err(CmdError::InvalidArg(
            "choose one of: a single item name, --all, --legacy, or --only".into(),
        ));
    }
    if folder.is_some() && !(all || legacy) {
        return Err(CmdError::InvalidArg(
            "--folder only applies with --all or --legacy".into(),
        ));
    }

    let plan = recipients::load_encrypt_plan().await?;
    recipients::warn_about_skips(&plan.skips);
    let target = plan.selection.recipients;

    let would_revoke = plan
        .skips
        .iter()
        .any(|s| s.reason != ragewarden_core::policy::SkipReason::DefaultEncryptOff);

    let names: Vec<String> = if let Some(only) = only {
        refresh_vault_cache().await?;
        only.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    } else if all || legacy {
        protected_item_names(folder, legacy).await?
    } else {
        refresh_vault_cache().await?;
        vec![name.unwrap().to_string()]
    };

    if names.is_empty() {
        eprintln!("(no protected items to re-encrypt)");
        return Ok(());
    }

    if would_revoke && yes && !allow_revoke {
        let n = plan
            .skips
            .iter()
            .filter(|s| s.reason != ragewarden_core::policy::SkipReason::DefaultEncryptOff)
            .count();
        return Err(CmdError::InvalidArg(format!(
            "refusing to re-encrypt under --yes: {n} recipient(s) cannot be re-wrapped from \
             this machine and would LOSE access to the affected item(s) (listed above). \
             Re-run interactively to confirm, or pass --allow-revoke to drop them deliberately."
        )));
    }

    let batch = names.len() > 1;
    let hw_real = consent::hardware_state()
        .map(|s| s == consent::HardwareState::Real)
        .unwrap_or(false);
    let effective_yes = if batch {
        if !(yes && !hw_real) {
            let taps = if hw_real {
                format!("; on a hardware vault that is {} taps", names.len())
            } else {
                String::new()
            };
            let revoke_note = if would_revoke {
                " -- WARNING: this DROPS the recipient(s) listed above; they lose access"
            } else {
                ""
            };
            confirm_action(&format!(
                "Re-encrypt {} item(s) to the current recipient set{taps}{revoke_note}",
                names.len()
            ))?;
        }
        true
    } else {
        if would_revoke && !yes {
            confirm_action(&format!(
                "Re-encrypting `{}` will DROP the recipient(s) listed above; they lose access. Continue",
                names[0]
            ))?;
        }
        yes
    };

    let mut done = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    let mut first_failure: Option<CmdError> = None;
    for n in &names {
        audit_helper::record_target(ragewarden_core::audit::AuditKind::Rotate, n.clone());
        match rewrap_one(
            n,
            "the current recipient set",
            &target,
            &target,
            "Reencrypt",
            effective_yes,
            no_wait,
        )
        .await
        {
            Ok(labels) => {
                done += 1;
                if batch {
                    println!("  re-encrypted `{n}` -> {} recipient(s)", labels.len());
                } else {
                    println!("Re-encrypted `{n}` to {} recipient(s):", labels.len());
                    for label in &labels {
                        println!("  {label}");
                    }
                }
            }
            Err(CmdError::Cancelled) => {
                eprintln!("(cancelled at `{n}`; {done} re-encrypted, stopping)");
                return Ok(());
            }
            Err(e) if batch => {
                if is_decrypt_skippable(&e) {
                    eprintln!("  skipped `{n}` (no key for it on this machine): {e}");
                    skipped += 1;
                } else {
                    eprintln!("  FAILED `{n}` (network/write): {e}");
                    failed += 1;
                    if first_failure.is_none() {
                        first_failure = Some(e);
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
    if batch {
        let mut parts = vec![format!("re-encrypted {done}")];
        if skipped > 0 {
            parts.push(format!("skipped {skipped} (no key here)"));
        }
        if failed > 0 {
            parts.push(format!("FAILED {failed} (network/write)"));
        }
        println!("{}.", parts.join(", "));
    }
    if let Some(e) = first_failure {
        return Err(e);
    }
    Ok(())
}

/// Restrict an item to a named subset of recipients, dropping the rest -- the
/// narrow/revoke operation, split out from `reencrypt` so dropping a recipient
/// can never be a stray flag on the everyday widen path.
pub async fn cmd_restrict(
    name: &str,
    to_csv: &str,
    yes: bool,
    no_wait: bool,
) -> Result<(), CmdError> {
    let plan = recipients::load_encrypt_plan().await?;
    recipients::warn_about_skips(&plan.skips);

    let list = recipients::load().await?;
    let mut chosen: Vec<Recipient> = Vec::new();
    for id in to_csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let entry = list
            .entries
            .get(id)
            .ok_or_else(|| CmdError::NotFound(format!("recipient {id}")))?;
        chosen.push(entry.recipient.clone());
    }
    if chosen.is_empty() {
        return Err(CmdError::InvalidArg(
            "--to must name at least one recipient".into(),
        ));
    }
    if !recipients::any_readable_on_this_machine(&chosen)? {
        return Err(CmdError::InvalidArg(format!(
            "refusing to restrict `{name}`: no recipient named by --to has its private \
             half on this machine, so the item would be re-wrapped to keys this \
             terminal cannot open and the current wrap would be gone. Name a \
             recipient enrolled here as well, or run this from the machine that \
             holds the key."
        )));
    }

    audit_helper::record_with(
        ragewarden_core::audit::AuditKind::Rotate,
        name.to_string(),
        format!("restrict to {to_csv}"),
    );

    let labels = rewrap_one(
        name,
        "a narrower recipient set",
        &plan.selection.recipients,
        &chosen,
        "Restrict",
        yes,
        no_wait,
    )
    .await?;
    println!("Restricted `{name}` to {} recipient(s):", labels.len());
    for label in &labels {
        println!("  {label}");
    }
    Ok(())
}

/// After enrolling a new recipient, offer to fold it into the items that
/// already exist -- they were wrapped before it, so it cannot open them until
/// they are re-encrypted. Declining (or no terminal to ask on) is not an error:
/// the enrollment itself already succeeded.
async fn offer_fold_in(new_recipient_label: &str) -> Result<(), CmdError> {
    let names = match protected_item_names(None, false).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("(could not list existing items to fold in: {e})");
            return Ok(());
        }
    };
    if names.is_empty() {
        return Ok(());
    }
    println!(
        "{} existing item(s) are not yet readable by `{new_recipient_label}`.",
        names.len()
    );
    match confirm_action(&format!(
        "Fold `{new_recipient_label}` into them now (re-encrypts {} item(s))",
        names.len()
    )) {
        Ok(()) => {
            if let Err(e) = cmd_reencrypt(None, true, false, None, None, false, false, false).await
            {
                eprintln!("(fold-in incomplete: {e}. Run `rageterm reencrypt --all` to finish.)");
            }
            Ok(())
        }
        Err(CmdError::Cancelled) => {
            println!("Skipped. Run `rageterm reencrypt --all` later to fold it in.");
            Ok(())
        }
        Err(_) => {
            println!("Run `rageterm reencrypt --all` to fold it into existing items.");
            Ok(())
        }
    }
}

/// One PRF evaluation for one write: (rp_id, credential_id, salt, output).
type PrfOutput = (String, Vec<u8>, [u8; 32], [u8; 32]);

/// Every FIDO2 recipient is evaluated with a fresh salt for this write
/// (`core::prf_requests_for`), so one captured PRF output opens one secret.
pub(crate) fn build_prf_outputs_for(recipients: &[Recipient]) -> Result<Vec<PrfOutput>, CmdError> {
    if recipients
        .iter()
        .any(|r| matches!(r, Recipient::PasskeyPrf { .. }))
    {
        return Err(CmdError::InvalidArg(
            "passkey-prf recipients can only be encrypted from a browser context".into(),
        ));
    }
    let enrolled = Identities::load()?;
    let mut out: Vec<PrfOutput> = Vec::new();
    for req in ragewarden_core::prf_requests_for(recipients) {
        let mock = enrolled.is_mock_fido_credential(&req.credential_id);
        let uv = enrolled.fido_uv_mode(&req.credential_id);
        let prf =
            fido::derive_prf_for_encrypt(&req.credential_id, &req.salt, &req.rp_id, mock, uv)?;
        out.push((req.rp_id, req.credential_id, req.salt, prf));
    }
    Ok(out)
}

pub(crate) fn prf_table_from(outputs: &[PrfOutput]) -> Vec<PrfEntry<'_>> {
    outputs
        .iter()
        .map(|(rp_id, credential_id, salt, prf)| PrfEntry {
            rp_id,
            credential_id,
            salt,
            prf_output: prf,
        })
        .collect()
}

async fn save_rage_blob_under_name(name: &str, armored: &str) -> Result<(), CmdError> {
    if let Some(open) = session::load()? {
        let client = new_client()?;
        let cached = vault_cache::load()?;
        let existing_id = cached
            .as_ref()
            .and_then(|v| find_cipher_by_name(&open.session, v, name))
            .and_then(|c| c.id.clone());
        let saved = match existing_id {
            Some(id) => {
                sync::update_preserving(
                    &client,
                    &open.server,
                    &open.session,
                    &id,
                    Some(armored),
                    &CipherEdit::default(),
                )
                .await?
            }
            None => {
                let cipher_in = build_rage_cipher(&open.session, name, armored)?;
                sync::create_cipher(&client, &open.server, &open.session, &cipher_in).await?
            }
        };
        let mut vault = cached.unwrap_or_default();
        vault.upsert_cipher(saved);
        vault_cache::save(&vault)?;
    } else {
        let store_path = config::store_path()?;
        config::ensure_config_dir()?;
        let mut store = Store::load(&store_path)?;
        store.upsert(name, armored.to_string(), Utc::now());
        store.save(&store_path)?;
    }
    Ok(())
}

async fn register_recipient(id: &str, label: &str, recipient: Recipient) -> Result<(), CmdError> {
    let mock = Identities::load()?
        .items
        .get(id)
        .map(|e| match &e.kind {
            IdentityKind::YubiKeyPiv { mock, .. } | IdentityKind::Fido2HmacSecret { mock, .. } => {
                *mock
            }
            _ => false,
        })
        .unwrap_or(false);
    let entry = RecipientEntry {
        id: id.to_string(),
        label: label.to_string(),
        created: Utc::now(),
        last_used: None,
        recipient,
        default_encrypt: true,
        mock,
    };
    recipients::add(entry).await?;
    Ok(())
}

fn age_pubkey_to_bytes(armored: &str) -> Result<[u8; 32], CmdError> {
    ragewarden_core::bech32::decode_age_x25519(armored)
        .ok_or_else(|| CmdError::InvalidArg(format!("malformed age recipient: {armored}")))
}

fn recipient_kind_str(r: &Recipient) -> &'static str {
    match r {
        Recipient::X25519 { .. } => "x25519",
        Recipient::YubiKeyPiv { .. } => "yubikey-piv",
        Recipient::YubiKeyPivP256 { .. } => "yubikey-piv-p256",
        Recipient::Fido2HmacSecret { .. } => "fido2-hmac",
        Recipient::PasskeyPrf { .. } => "passkey-prf",
        Recipient::AndroidKeystore { .. } => "android-keystore",
        Recipient::SoftwarePassphrase { .. } => "software/recovery",
    }
}

pub fn cmd_install_native_host(
    browser: &str,
    system: bool,
    extension_id: Option<&str>,
    yes: bool,
) -> Result<(), CmdError> {
    let browser = NhBrowser::parse(browser)?;
    let scope = if system {
        NhScope::System
    } else {
        NhScope::User
    };
    if browser == NhBrowser::Safari {
        return check_safari_relay();
    }
    let ext_id = match browser {
        NhBrowser::Chromium => {
            let id = match extension_id {
                Some(s) => s.trim().to_string(),
                None => prompt_chromium_extension_id()?,
            };
            install_native_host::validate_chromium_extension_id(&id)?;
            id
        }
        NhBrowser::Firefox => extension_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| install_native_host::DEFAULT_FIREFOX_EXTENSION_ID.to_string()),
        NhBrowser::Safari => unreachable!("handled above"),
    };
    let outcome = install_native_host::install(browser, scope, &ext_id, yes)?;
    if outcome.already_present {
        println!("Overwrote existing manifest at {}.", outcome.path.display());
    } else {
        println!("Installed manifest at {}.", outcome.path.display());
    }
    println!(
        "Browser will launch `{}` for native messages tagged `{}`.",
        std::env::current_exe()?.display(),
        install_native_host::HOST_NAME
    );
    Ok(())
}

fn prompt_chromium_extension_id() -> Result<String, CmdError> {
    use std::io::BufRead;

    if !io::stdin().is_terminal() {
        return Err(CmdError::InvalidArg(
            "--extension-id is required for chromium: the 32-character id (letters a-p) \
             shown at chrome://extensions once the Ragewarden extension is loaded. There \
             is no usable default -- Chrome ignores a manifest whose allowed origin is \
             not a real extension id."
                .into(),
        ));
    }
    eprint!("Chrome extension id (32 characters a-p, from chrome://extensions): ");
    io::Write::flush(&mut io::stderr())?;
    let mut buf = String::new();
    io::stdin().lock().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

/// Safari has no manifest to install: report which rageterm the Ragewarden
/// Safari app will run, or how to put one where it looks.
fn check_safari_relay() -> Result<(), CmdError> {
    remove_legacy_safari_metadata()?;
    let here = std::env::current_exe()?;
    match install_native_host::safari_relay_target()? {
        Some(target) => {
            println!(
                "Safari has no native-messaging manifest: the Ragewarden Safari app relays to \
                 rageterm itself, and runs {} (unless the app bundles its own).",
                target.display()
            );
            let same = std::fs::canonicalize(&target).ok() == std::fs::canonicalize(&here).ok();
            if !same {
                println!("That is not this rageterm ({}).", here.display());
            }
            Ok(())
        }
        None => Err(CmdError::InvalidArg(format!(
            "the Ragewarden Safari app finds no rageterm: it runs the one bundled into the app \
             (ragemanifest/safari-host-app/build.sh), else the first of {}. Link this one there, \
             e.g. `ln -s {} /usr/local/bin/rageterm`.",
            install_native_host::SAFARI_RELAY_PATHS.join(", "),
            here.display()
        ))),
    }
}

fn remove_legacy_safari_metadata() -> Result<bool, CmdError> {
    let old = install_native_host::legacy_safari_metadata()?;
    if !old.exists() {
        return Ok(false);
    }
    std::fs::remove_file(&old)?;
    println!(
        "Removed {}, which an older rageterm wrote for Safari and nothing read.",
        old.display()
    );
    Ok(true)
}

pub fn cmd_uninstall_native_host(browser: &str, system: bool) -> Result<(), CmdError> {
    let browser = NhBrowser::parse(browser)?;
    if browser == NhBrowser::Safari {
        if !remove_legacy_safari_metadata()? {
            println!(
                "Safari has no native-messaging manifest to remove; turn the Ragewarden \
                 extension off in Safari's settings, or remove the Ragewarden app."
            );
        }
        return Ok(());
    }
    let scope = if system {
        NhScope::System
    } else {
        NhScope::User
    };
    let path = install_native_host::uninstall(browser, scope)?;
    println!(
        "Uninstalled native messaging host (was at {}).",
        path.display()
    );
    Ok(())
}

pub fn cmd_native_host() -> Result<(), CmdError> {
    native_host::run()?;
    Ok(())
}

pub struct PassImportOpts<'a> {
    pub source: Option<&'a std::path::Path>,
    pub folder: Option<&'a str>,
    pub default_recipient: Option<&'a str>,
    pub dry_run: bool,
    pub also_export: bool,
    pub yes: bool,
}

pub async fn cmd_pass_import(opts: PassImportOpts<'_>) -> Result<(), CmdError> {
    let source = pass_import::resolve_store_dir(opts.source)?;
    let plan = pass_import::plan_import(&source, opts.folder)?;

    if plan.items.is_empty() {
        println!("No `.gpg` files found under {}.", source.display());
        return Ok(());
    }

    println!(
        "Found {} item(s) under {}.",
        plan.items.len(),
        source.display()
    );

    if opts.dry_run {
        for it in &plan.items {
            println!("  would import {} (from {})", it.name, it.source.display());
        }
        return Ok(());
    }

    let target_recipients: Vec<Recipient> = if let Some(id) = opts.default_recipient {
        let list = recipients::load().await?;
        let entry = list
            .entries
            .get(id)
            .ok_or_else(|| CmdError::NotFound(format!("recipient {id}")))?;
        let target = vec![entry.recipient.clone()];
        if !recipients::any_readable_on_this_machine(&target)? {
            return Err(CmdError::InvalidArg(format!(
                "recipient `{id}` cannot be opened on this machine; importing every item \
                 to it alone would leave them unreadable here. Pick one of this \
                 machine's recipients, or omit --default-recipient to use the policy."
            )));
        }
        target
    } else {
        let plan = recipients::load_encrypt_plan().await?;
        recipients::warn_about_skips(&plan.skips);
        if plan.selection.recipients.is_empty() {
            return Err(CmdError::PassImport(
                PassImportError::NoRecipients.to_string(),
            ));
        }
        plan.selection.recipients
    };

    if !opts.yes {
        confirm_action(&format!(
            "Import {} item(s) from {} to {} recipient(s)",
            plan.items.len(),
            source.display(),
            target_recipients.len()
        ))?;
    }

    let prf_outputs = build_prf_outputs_for(&target_recipients)?;
    let prf_table: Vec<PrfEntry<'_>> = prf_table_from(&prf_outputs);

    let mut imported: Vec<ImportedItem> = Vec::with_capacity(plan.items.len());
    let mut skipped: Vec<(String, String)> = Vec::new();

    for it in &plan.items {
        match import_one(&it.source, &it.name, &target_recipients, &prf_table).await {
            Ok(()) => {
                imported.push(ImportedItem {
                    name: it.name.clone(),
                    source: it.source.clone(),
                });
                println!("  imported {}", it.name);
            }
            Err(e) => {
                eprintln!("  skipped {} ({})", it.name, e);
                skipped.push((it.name.clone(), e.to_string()));
            }
        }
    }

    println!(
        "Imported {} item(s); skipped {}.",
        imported.len(),
        skipped.len()
    );

    if opts.also_export {
        let path = pass_import::write_log(&imported)?;
        println!("Wrote import log at {}.", path.display());
    }

    Ok(())
}

async fn import_one(
    source: &std::path::Path,
    name: &str,
    recipients_vec: &[Recipient],
    prf_table: &[PrfEntry<'_>],
) -> Result<(), CmdError> {
    let plaintext = pass_import::gpg_decrypt(source)?;
    if plaintext.is_empty() {
        return Err(CmdError::PassImport(
            PassImportError::EmptyPlaintext(source.to_path_buf()).to_string(),
        ));
    }
    let (password, _notes) = pass_import::split_password_and_notes(&plaintext);
    drop(plaintext);

    let armored =
        pass_import::encrypt_password_to_recipients(&password, recipients_vec, prf_table)?;
    drop(password);

    save_rage_blob_under_name(name, &armored).await?;
    Ok(())
}

pub async fn cmd_agent_add(
    name: &str,
    lifetime_secs: Option<u32>,
    yes: bool,
    no_wait: bool,
) -> Result<(), CmdError> {
    let consent_guard = consent::require("Add", name, "ssh-agent", yes)?;
    let r = match decrypt_named_locked(name, no_wait, &consent_guard).await {
        Ok(plaintext) => agent_add::add_to_agent(AddOptions {
            plaintext: &plaintext,
            comment: name,
            lifetime_secs,
        })
        .map_err(CmdError::from),
        Err(e) => Err(e),
    };
    audit_helper::record_result(AuditKind::AgentAdd, name, Some("ssh-agent"), &r);
    let outcome = r?;

    let lifetime_text = match outcome.lifetime_secs {
        Some(secs) => format!("{secs}s lifetime"),
        None => "until ssh-agent restarts".to_string(),
    };
    println!(
        "Added `{name}` ({}) to ssh-agent -- fingerprint {} -- {}",
        outcome.algorithm, outcome.fingerprint, lifetime_text
    );
    Ok(())
}

pub async fn cmd_fill(
    name: &str,
    to: Option<&str>,
    yes: bool,
    no_wait: bool,
) -> Result<(), CmdError> {
    let spec = fill::parse_window_spec(to)?;
    let backend = fill::default_backend()?;
    let consent_guard = consent::require(
        "Type",
        name,
        &format!("{} (via {})", spec.describe(), backend.name()),
        yes,
    )?;
    let r = decrypt_named_locked(name, no_wait, &consent_guard).await;
    audit_helper::record_result(AuditKind::Autofill, name, Some(&spec.describe()), &r);
    let plaintext = r?;
    backend.type_into(&plaintext, &spec)?;
    drop(plaintext);
    eprintln!(
        "Typed `{name}` into {} (via {}).",
        spec.describe(),
        backend.name()
    );
    Ok(())
}
