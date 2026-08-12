use std::io::{self, IsTerminal, Read};

use age::secrecy::ExposeSecret;
use chrono::Utc;
use ragewarden_core::sync::{
    self, build_rage_cipher, build_rage_cipher_in_folder, create_cipher, encrypt_string,
    fetch_vault, login, name_index, register, update_cipher, Cipher, CipherFieldIn, CipherIn,
    CipherLogin, RAGE_FIELD_NAME, RAGE_MARKER_NOTE, Server, Session, SyncError, Vault,
};
use ragewarden_core::{
    decrypt, encrypt_with_prf, AgeBlob, Identity, Plaintext, PrfEntry, Recipient,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::agent_add::{self, AddOptions, AgentAddError};
use crate::audit_helper;
use crate::config;
use crate::consent;
use crate::hw;
use crate::history_helper;
use crate::fido::{self, FidoIdentity};
use crate::fill::{self, FillError};
use crate::http::ReqwestClient;
use crate::identities::{self, EnrolledIdentity, Identities, IdentityKind};
use crate::idfile::{self, IdFileError};
use crate::install_native_host::{self, Browser as NhBrowser, Scope as NhScope};
use crate::keyring_id::{self, KeyringIdentity, KEYRING_SERVICE};
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

pub fn cmd_enroll_software_identity() -> Result<(), CmdError> {
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
    let pub_armored = idfile::generate_and_write(&path)?;

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
    kdf_iterations: u32,
) -> Result<(), CmdError> {
    let password = read_master_password("New master password: ", true)?;
    let server = Server::self_hosted(server_url);
    server
        .require_secure()
        .map_err(|e| CmdError::InvalidArg(e.to_string()))?;
    let client = ReqwestClient::new().map_err(|e| CmdError::Sync(sync::SyncError::Http(e)))?;
    let _out = register(
        &client,
        &server,
        email,
        password.expose_secret(),
        name,
        kdf_iterations,
    )
    .await?;
    println!("Registered `{email}` on {server_url}.");
    println!("Run `rageterm login --server {server_url} --email {email}` to log in.");
    Ok(())
}

pub async fn cmd_login(server_url: &str, email: &str) -> Result<(), CmdError> {
    audit_helper::record_detail(ragewarden_core::audit::AuditKind::Login, email.to_string());
    let password = read_master_password("Master password: ", false)?;
    let server = Server::self_hosted(server_url);
    server
        .require_secure()
        .map_err(|e| CmdError::InvalidArg(e.to_string()))?;
    let client = ReqwestClient::new().map_err(|e| CmdError::Sync(sync::SyncError::Http(e)))?;
    let device_name = format!("rageterm@{}", hostname_or_unknown());
    let s = login(
        &client,
        &server,
        email,
        password.expose_secret(),
        &device_name,
    )
    .await?;
    session::save(&server, &s)?;
    println!(
        "Logged in as {} on {} (kdf iters {}). Session saved at {}.",
        s.email,
        server_url,
        s.kdf_iterations,
        session::session_path()?.display()
    );
    println!("Run `rageterm sync` to pull the vault.");
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
    let client = ReqwestClient::new().map_err(|e| CmdError::Sync(sync::SyncError::Http(e)))?;
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
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub enum SetCipherType {
    SecureNote,
    Login,
}

pub async fn cmd_set(
    name: &str,
    cipher_type: SetCipherType,
    from_stdin: bool,
    folder: Option<&str>,
) -> Result<(), CmdError> {
    let stdin_is_tty = io::stdin().is_terminal();
    let buf: Vec<u8> = if stdin_is_tty && !from_stdin {
        let secret = rpassword::prompt_password(format!("Value for `{name}` (hidden): "))
            .map_err(|e| CmdError::InvalidArg(format!("could not read value: {e}")))?;
        secret.into_bytes()
    } else {
        let mut buf: Vec<u8> = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    };
    if buf.is_empty() {
        return Err(CmdError::InvalidArg(if from_stdin {
            "no plaintext on stdin (pipe a value before invoking with --from-stdin)".into()
        } else {
            "no plaintext provided".into()
        }));
    }
    let mut buf = buf;
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    let plaintext = Zeroizing::new(buf);

    // One load, one warning: the same set wraps the new value below and the
    // prior revision handed to `record_prior_revision`.
    let plan = recipients::load_encrypt_plan().await?;
    recipients::warn_about_skips(&plan.skips);
    let recipients_vec: Vec<Recipient> = plan.selection.recipients;

    let prf_outputs = build_prf_outputs_for(&recipients_vec)?;
    let prf_table: Vec<PrfEntry<'_>> = prf_outputs
        .iter()
        .map(|(rp_id, salt, prf)| PrfEntry {
            rp_id,
            salt,
            prf_output: prf,
        })
        .collect();

    let blob = encrypt_with_prf(&plaintext, &recipients_vec, &prf_table)
        .map_err(|e| CmdError::Encrypt(e.to_string()))?;
    drop(plaintext);

    let armored = String::from_utf8(blob.0)
        .map_err(|e| CmdError::Encrypt(format!("blob is not valid UTF-8: {e}")))?;

    if let Some(open) = session::load()? {
        let client = ReqwestClient::new().map_err(|e| CmdError::Sync(sync::SyncError::Http(e)))?;
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

        let cipher_in = match cipher_type {
            SetCipherType::SecureNote => build_rage_cipher_in_folder(
                &open.session,
                name,
                &armored,
                folder_id.as_deref(),
            )?,
            SetCipherType::Login => build_rage_login_cipher(
                &open.session,
                name,
                &armored,
                folder_id.as_deref(),
            )?,
        };
        let existing = cached
            .as_ref()
            .and_then(|v| find_cipher_by_name(&open.session, v, name));

        if let Some(existing) = existing {
            audit_helper::record_target(
                ragewarden_core::audit::AuditKind::Update,
                name.to_string(),
            );
            history_helper::record_prior_revision(existing, &recipients_vec).await;
        } else {
            audit_helper::record_target(
                ragewarden_core::audit::AuditKind::Set,
                name.to_string(),
            );
        }

        let saved: Cipher = if let Some(existing) = existing {
            update_cipher(
                &client,
                &open.server,
                &open.session,
                existing.id.as_deref().unwrap_or(""),
                &cipher_in,
            )
            .await?
        } else {
            create_cipher(&client, &open.server, &open.session, &cipher_in).await?
        };

        let mut vault = vault_cache::load()?.or(cached).unwrap_or_default();
        if let Some(id) = &saved.id {
            vault
                .ciphers
                .retain(|c| c.id.as_deref() != Some(id.as_str()));
        }
        vault.ciphers.push(saved);
        vault_cache::save(&vault)?;
        println!("Stored `{name}` on server.");
    } else {
        if folder.is_some() {
            return Err(CmdError::InvalidArg(
                "--folder requires a logged-in session (folders live on the server)".into(),
            ));
        }
        let store_path = config::store_path()?;
        config::ensure_config_dir()?;
        let mut store = Store::load(&store_path)?;
        let now = Utc::now();
        let was_new = !store.items.contains_key(name);
        if was_new {
            audit_helper::record_target(
                ragewarden_core::audit::AuditKind::Set,
                name.to_string(),
            );
        } else {
            audit_helper::record_target(
                ragewarden_core::audit::AuditKind::Update,
                name.to_string(),
            );
        }
        store.upsert(name, armored, now);
        store.save(&store_path)?;
        if was_new {
            println!("Stored `{name}` (new item, local-only -- run `rageterm login` to sync).");
        } else {
            println!("Updated `{name}` (local-only -- run `rageterm login` to sync).");
        }
    }
    Ok(())
}

fn resolve_folder_name(
    session: &Session,
    vault: &Vault,
    name: &str,
) -> Result<String, CmdError> {
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

        let mut entries: Vec<(String, bool, Option<String>)> =
            Vec::with_capacity(vault.ciphers.len());
        for c in &vault.ciphers {
            let Ok(name) = sync::cipher_name(&open.session, c) else {
                continue;
            };
            if !matches(&name) {
                continue;
            }
            let is_rage = sync::extract_rage_blob(&open.session, c)
                .ok()
                .flatten()
                .is_some();
            let folder = c
                .folder_id
                .as_ref()
                .and_then(|id| folder_names.get(id).cloned());
            entries.push((name, is_rage, folder));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        if json {
            let json_entries: Vec<serde_json::Value> = entries
                .into_iter()
                .map(|(name, is_rage, folder)| {
                    serde_json::json!({
                        "name": name,
                        "kind": if is_rage { "rage" } else { "plain" },
                        "source": "vault",
                        "folder": folder,
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

        let max = entries.iter().map(|(n, _, _)| n.len()).max().unwrap_or(0);
        for (name, is_rage, _folder) in entries {
            let marker = if is_rage { "protected" } else { "unprotected" };
            println!("{:<width$}  {marker}", name, width = max);
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
                eprintln!(
                    "(no items -- use `rageterm set <name>` to add one or `rageterm login`)"
                );
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
    append_newline: bool,
    yes: bool,
    no_wait: bool,
) -> Result<(), CmdError> {
    // `get` / `pipe` used to be the one delivery path with no gate at all:
    // `rageterm get NAME` decrypted and printed with zero interaction. It now
    // goes through the same consent path as every other delivery. Scripts that
    // relied on the silence need `--yes`, which is honest about being
    // software-only; with a hardware identity enrolled the tap is still
    // required and `--yes` changes nothing.
    // Symmetric with `reveal`: `get`'s job is pipes and files, but if its stdout
    // IS an interactive terminal in a scrollback-retaining session, printing the
    // plaintext there leaks it into history exactly as `reveal` refuses to. Gate
    // only on a TTY, so pipelines and redirects -- get's real use -- are untouched.
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
    audit_helper::record_target(ragewarden_core::audit::AuditKind::Reveal, name.to_string());
    let plaintext = decrypt_named_locked(name, no_wait, &consent_guard).await?;
    output::deliver_stdout(plaintext, append_newline)?;
    Ok(())
}

pub async fn cmd_copy(
    name: &str,
    clear_secs: u64,
    yes: bool,
    no_wait: bool,
) -> Result<(), CmdError> {
    let consent_guard = consent::require("Copy", name, "clipboard", yes)?;
    audit_helper::record_target(ragewarden_core::audit::AuditKind::Copy, name.to_string());
    let plaintext = decrypt_named_locked(name, no_wait, &consent_guard).await?;
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
    // The seed is decrypted either way, so the gate applies either way -- not
    // only on the `--copy` branch as it did before.
    let destination = if copy { "clipboard" } else { "stdout" };
    let consent_guard = consent::require("Generate a TOTP code from", name, destination, yes)?;
    let plaintext = decrypt_named_locked(name, no_wait, &consent_guard).await?;
    // Zeroizing: the base32 TOTP secret is a long-lived reusable credential, so
    // its heap copy must be wiped on drop like the Zeroizing<Vec<u8>> plaintext
    // it came from (the same care output.rs takes).
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

pub async fn cmd_reveal(
    name: &str,
    yes: bool,
    no_wait: bool,
    force: bool,
) -> Result<(), CmdError> {
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
    audit_helper::record_target(ragewarden_core::audit::AuditKind::Reveal, name.to_string());
    let plaintext = decrypt_named_locked(name, no_wait, &consent_guard).await?;
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
    let plaintext = decrypt_named_locked(name, no_wait, &consent_guard).await?;
    let code = output::deliver_exec(plaintext, argv, via_env)?;
    Ok(code)
}

async fn decrypt_named_locked(
    name: &str,
    no_wait: bool,
    consent: &consent::ConsentGuard,
) -> Result<Plaintext, CmdError> {
    let need_lock = identities_need_hardware()?;
    let _guard = if need_lock {
        Some(lock::acquire(!no_wait)?)
    } else {
        None
    };
    decrypt_named(name, consent)
}

fn identities_need_hardware() -> Result<bool, CmdError> {
    let ids = Identities::load()?;
    Ok(ids.items.values().any(|e| {
        matches!(
            e.kind,
            IdentityKind::YubiKeyPiv { .. } | IdentityKind::Fido2HmacSecret { .. }
        )
    }))
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
pub fn decrypt_named(
    name: &str,
    consent: &consent::ConsentGuard,
) -> Result<Plaintext, CmdError> {
    if consent.item() != name {
        return Err(CmdError::Decrypt(format!(
            "refusing to decrypt `{name}` with consent taken for `{}`",
            consent.item()
        )));
    }

    let rage_blob_armored = if let Some(open) = session::load()? {
        let vault = vault_cache::load()?.ok_or_else(|| {
            CmdError::InvalidArg(
                "no cached vault -- run `rageterm sync` first to fetch the vault".into(),
            )
        })?;
        let cipher = find_cipher_by_name(&open.session, &vault, name)
            .ok_or_else(|| CmdError::NotFound(name.to_string()))?;
        let blob = sync::extract_rage_blob(&open.session, cipher)
            .map_err(|e| CmdError::Sync(e))?
            .ok_or_else(|| {
                CmdError::Decrypt(format!(
                    "cipher `{name}` has no `rage:v1` field -- was it created outside ragewarden?"
                ))
            })?;
        blob
    } else {
        let store_path = config::store_path()?;
        let store = Store::load(&store_path)?;
        let item = store
            .get(name)
            .ok_or_else(|| CmdError::NotFound(name.to_string()))?;
        item.rage_blob.clone()
    };

    let blob = AgeBlob::from_bytes(rage_blob_armored.into_bytes());

    if consent.hardware() == consent::HardwareState::Real {
        let hardware = build_identity_list_for(consent::IdentityPolicy::HardwareOnly)?;
        if !hardware.is_empty() {
            match decrypt(&blob, &hardware) {
                Ok(plaintext) => return Ok(plaintext),
                Err(ragewarden_core::DecryptError::NoMatchingIdentity) => {
                    // Not device-protected. Falls through to the software path,
                    // which announces itself as software-only and re-gates.
                }
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
                // A stand-in reads a file in the config directory; under
                // `HardwareOnly` it would be the software path wearing a
                // YubiKey's name.
                if hardware_only && *mock {
                    continue;
                }
                let pub_bytes = hex_decode_32(public_key_hex)?;
                out.push(Box::new(PivIdentity {
                    public_key: pub_bytes,
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
                ..
            } => {
                if hardware_only && *mock {
                    continue;
                }
                use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
                let credential_id = B64URL
                    .decode(credential_id_b64)
                    .map_err(|e| CmdError::Decrypt(format!("malformed cred id: {e}")))?;
                out.push(Box::new(FidoIdentity {
                    credential_id,
                    rp_id: rp_id.clone(),
                    label: entry.label.clone(),
                    mock: *mock,
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

fn hex_decode_32(s: &str) -> Result<[u8; 32], CmdError> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).map_err(|e| CmdError::Decrypt(format!("hex: {e}")))?;
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

fn read_master_password(prompt: &str, confirm: bool) -> Result<secrecy::SecretString, CmdError> {
    use secrecy::SecretString;
    use std::io::BufRead;

    let is_tty = io::stdin().is_terminal();
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

pub async fn cmd_enroll_yubikey(
    slot: u8,
    label: Option<&str>,
    public_key: Option<&str>,
    no_wait: bool,
    allow_untouched_slot: bool,
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

    let enrolled = if hw::mock_enabled() {
        enroll_mock_piv(slot)?
    } else {
        let pem = public_key.ok_or_else(|| {
            CmdError::InvalidArg(
                "`enroll-yubikey` needs `--public-key` -- the X25519 public key already in \
                 the slot. Generate one with `ykman piv keys generate --algorithm X25519 \
                 --touch-policy always --pin-policy once <slot> pub.pem` and pass the \
                 file. Enrollment then proves the card holds the matching private key, \
                 and reads the slot's touch policy back off the card (GET METADATA) \
                 before that proof. A slot that does not require a touch is refused, so \
                 rageterm never announces a tap the card will not wait for."
                    .into(),
            )
        })?;
        let material = read_public_key_arg(pem)?;
        let claimed = piv::parse_x25519_public_key(&material)?;
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
            public_key_hex: hex_encode_32(&enrolled.public_key),
            serial: enrolled.serial,
            slot: enrolled.slot,
            mock: enrolled.mock,
        },
        label: label.clone(),
        created: Utc::now(),
        last_used: None,
    });
    ids.save()?;

    register_recipient(
        &entry_id,
        &label,
        Recipient::YubiKeyPiv {
            public_key: enrolled.public_key,
            serial: enrolled.serial,
            slot: enrolled.slot,
        },
    )
    .await?;

    if enrolled.mock {
        // A previous audit found mock enrollments being published to the
        // cross-device registry as `kinds::YUBIKEY`, which every other frontend
        // then treats as genuine hardware. The registry has no "test recipient"
        // flag to set, so the only safe answer is to not publish at all.
        eprintln!(
            "rageterm: NOT publishing this recipient to the cross-device registry -- it is \
             a software stand-in, and other devices would encrypt to it believing a \
             YubiKey guards it. The recipient exists only in this installation."
        );
    } else if let Err(e) =
        recipients::publish_wire_entry_to_registry(recipients::piv_wire_entry(
            &enrolled.public_key,
            enrolled.serial,
            enrolled.slot,
            &label,
        ))
        .await
    {
        eprintln!(
            "(warning: enrolled locally but couldn't publish YubiKey to the cross-device registry: {e}. Other devices won't see this recipient until next `rageterm sync`.)"
        );
    }

    println!(
        "Enrolled YubiKey PIV identity `{label}` (id={entry_id}, serial={:08x}, slot={:#04x}).",
        enrolled.serial, enrolled.slot
    );
    if !enrolled.mock {
        offer_fold_in(&label).await?;
    }
    Ok(())
}

#[cfg(any(test, feature = "mock-hardware"))]
fn enroll_mock_piv(slot: u8) -> Result<piv::EnrolledPiv, CmdError> {
    Ok(piv::mock_enroll(slot)?)
}

#[cfg(not(any(test, feature = "mock-hardware")))]
fn enroll_mock_piv(_slot: u8) -> Result<piv::EnrolledPiv, CmdError> {
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

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
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
    } else if let Err(e) =
        recipients::publish_wire_entry_to_registry(recipients::fido2_wire_entry(
            &enrolled.credential_id,
            &enrolled.salt,
            &enrolled.rp_id,
            &label,
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

    println!(
        "Enrolled paper recovery identity at {} (id={entry_id}).",
        enrolled.path.display()
    );
    println!("Public key (recipient): {}", enrolled.armored_pubkey);
    println!(
        "If you lose this file, run `rageterm recover --save` and re-type the 24 words."
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
    let client = ReqwestClient::new().map_err(|e| CmdError::Sync(sync::SyncError::Http(e)))?;
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
    sync::delete_cipher(&client, &open.server, &open.session, &cipher_id).await?;

    let mut vault = cached.unwrap_or_default();
    vault.ciphers.retain(|c| c.id.as_deref() != Some(cipher_id.as_str()));
    vault_cache::save(&vault)?;

    println!("Deleted `{name}`.");
    Ok(())
}

pub async fn cmd_folders_list() -> Result<(), CmdError> {
    let open = session::load()?
        .ok_or_else(|| CmdError::InvalidArg("not logged in".into()))?;
    let cached = vault_cache::load()?;
    let vault = match cached {
        Some(v) => v,
        None => {
            let client = ReqwestClient::new().map_err(|e| CmdError::Sync(sync::SyncError::Http(e)))?;
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
    let open = session::load()?
        .ok_or_else(|| CmdError::InvalidArg("not logged in".into()))?;
    let client = ReqwestClient::new().map_err(|e| CmdError::Sync(sync::SyncError::Http(e)))?;
    let f = sync::create_folder(&client, &open.server, &open.session, name).await?;
    let mut vault = vault_cache::load()?.unwrap_or_default();
    vault.folders.retain(|x| x.id != f.id);
    vault.folders.push(f.clone());
    vault_cache::save(&vault)?;
    println!("Created folder `{name}` (id={}).", f.id);
    Ok(())
}

pub async fn cmd_folders_rename(folder_id: &str, name: &str) -> Result<(), CmdError> {
    let open = session::load()?
        .ok_or_else(|| CmdError::InvalidArg("not logged in".into()))?;
    let client = ReqwestClient::new().map_err(|e| CmdError::Sync(sync::SyncError::Http(e)))?;
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
    let open = session::load()?
        .ok_or_else(|| CmdError::InvalidArg("not logged in".into()))?;
    let client = ReqwestClient::new().map_err(|e| CmdError::Sync(sync::SyncError::Http(e)))?;
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
        println!("(no recipients enrolled -- run `rageterm enroll-software-identity` or one of the `enroll-*` commands)");
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
        "{:<id_w$}  {:<kind_w$}  {:<20}  {}",
        "ID",
        "KIND",
        "CREATED",
        "LABEL",
        id_w = max_id,
        kind_w = max_kind,
    );
    let mut any_mock = false;
    for e in list.iter_chronological() {
        // A mock recipient is marked twice: by the label prefix written at
        // enrollment, and by re-deriving the flag from `identities.json` here,
        // so an edited label cannot disguise one.
        let mock = hw::is_mock_label(&e.label) || recipient_is_mock(&enrolled, &e.recipient);
        any_mock |= mock;
        let kind = recipient_kind_str(&e.recipient);
        println!(
            "{:<id_w$}  {:<kind_w$}  {:<20}  {}{}",
            e.id,
            kind,
            e.created.format("%Y-%m-%d %H:%M:%S"),
            if mock { "[MOCK] " } else { "" },
            e.label,
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

    // The list above is account-wide -- it round-trips through the vault -- so on
    // a second terminal part of it belongs to other machines. Which part is
    // otherwise invisible until a write quietly leaves someone out, so the
    // policy's own answer is printed here rather than only at write time.
    match recipients::load_encrypt_plan().await {
        Ok(plan) if !plan.skips.is_empty() => {
            println!("\nNot wrapped to by writes from this machine:");
            for s in &plan.skips {
                println!("  {}", s.describe());
            }
        }
        Ok(_) => {}
        // Listing must not fail because the encrypt side cannot be worked out
        // (no identity.age yet, vault unreachable); say so and keep the table.
        Err(e) => eprintln!(
            "\nrageterm: could not determine which recipients this machine can wrap to: {e}"
        ),
    }
    Ok(())
}

fn recipient_is_mock(enrolled: &Identities, recipient: &Recipient) -> bool {
    match recipient {
        Recipient::Fido2HmacSecret { credential_id, .. } => {
            enrolled.is_mock_fido_credential(credential_id)
        }
        Recipient::YubiKeyPiv {
            public_key,
            serial,
            slot,
        } => enrolled.items.values().any(|e| match &e.kind {
            IdentityKind::YubiKeyPiv {
                public_key_hex,
                serial: s,
                slot: sl,
                mock,
            } => {
                *mock && s == serial && sl == slot && public_key_hex == &hex_encode_32(public_key)
            }
            _ => false,
        }),
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

    audit_helper::record_with(
        ragewarden_core::audit::AuditKind::RemoveRecipient,
        entry.id.clone(),
        format!(
            "{} ({})",
            entry.label,
            recipient_kind_str(&entry.recipient)
        ),
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
        match &removed.kind {
            IdentityKind::OsKeyring {
                keyring_service,
                keyring_user,
                ..
            } => {
                if let Err(e) = keyring_id::delete(keyring_service, keyring_user) {
                    eprintln!(
                        "rageterm: removed recipient but could not delete keyring entry: {e}"
                    );
                }
            }

            _ => {}
        }
    }
    ids.save()?;

    println!("Removed recipient `{id}`.");
    Ok(())
}

/// Decrypt `name` and re-encrypt it to `target_recipients`, saving the new
/// blob. `history_recipients` is the set the pre-rotation revision is recorded
/// against (the current set, so the old value stays recoverable even when
/// `target` narrows). `action` is the consent/ceremony label. Decrypting is a
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

    if let Some(open) = session::load()? {
        if let Some(cached) = vault_cache::load()? {
            if let Some(existing) = find_cipher_by_name(&open.session, &cached, name) {
                history_helper::record_prior_revision(existing, history_recipients).await;
            }
        }
    }

    let plaintext = decrypt_named_locked(name, no_wait, &consent_guard).await?;

    let prf_outputs = build_prf_outputs_for(target_recipients)?;
    let prf_table: Vec<PrfEntry<'_>> = prf_outputs
        .iter()
        .map(|(rp_id, salt, prf)| PrfEntry {
            rp_id,
            salt,
            prf_output: prf,
        })
        .collect();

    let blob = encrypt_with_prf(&plaintext, target_recipients, &prf_table)
        .map_err(|e| CmdError::Encrypt(e.to_string()))?;
    drop(plaintext);

    let armored = String::from_utf8(blob.0)
        .map_err(|e| CmdError::Encrypt(format!("blob is not valid UTF-8: {e}")))?;
    save_rage_blob_under_name(name, &armored).await?;

    let session = session::load()?;
    Ok(history_helper::recipient_summary_labels(session.as_ref().map(|o| &o.session), target_recipients).await)
}

/// The protected (rage-wrapped) item names in the vault, optionally filtered to
/// one folder. Fetches a fresh vault so a bulk re-encrypt can't miss an item a
/// sibling device added since this machine last synced.
async fn protected_item_names(folder_filter: Option<&str>) -> Result<Vec<String>, CmdError> {
    let Some(open) = session::load()? else {
        return Ok(Vec::new());
    };
    let client = ReqwestClient::new().map_err(|e| CmdError::Sync(sync::SyncError::Http(e)))?;
    let vault = fetch_vault(&client, &open.server, &open.session).await?;
    vault_cache::save(&vault)?;

    let folder_names: std::collections::HashMap<String, String> = vault
        .folders
        .iter()
        .filter_map(|f| sync::decrypt_string(&open.session, &f.name).ok().map(|n| (f.id.clone(), n)))
        .collect();

    let mut names = Vec::new();
    for c in &vault.ciphers {
        let Ok(name) = sync::cipher_name(&open.session, c) else {
            continue;
        };
        let is_protected = sync::extract_rage_blob(&open.session, c).ok().flatten().is_some();
        if !is_protected {
            continue;
        }
        if let Some(want) = folder_filter {
            let folder = c.folder_id.as_ref().and_then(|id| folder_names.get(id).map(String::as_str));
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
        let client = ReqwestClient::new().map_err(|e| CmdError::Sync(sync::SyncError::Http(e)))?;
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

pub async fn cmd_reencrypt(
    name: Option<&str>,
    all: bool,
    folder: Option<&str>,
    only: Option<&str>,
    allow_revoke: bool,
    yes: bool,
    no_wait: bool,
) -> Result<(), CmdError> {
    let selectors = [name.is_some(), all, only.is_some()].iter().filter(|b| **b).count();
    if selectors == 0 {
        return Err(CmdError::InvalidArg(
            "name one item, or pass --all or --only <names>".into(),
        ));
    }
    if selectors > 1 {
        return Err(CmdError::InvalidArg(
            "choose one of: a single item name, --all, or --only".into(),
        ));
    }
    if folder.is_some() && !all {
        return Err(CmdError::InvalidArg("--folder only applies with --all".into()));
    }

    let plan = recipients::load_encrypt_plan().await?;
    recipients::warn_about_skips(&plan.skips);
    let target = plan.selection.recipients;

    // Every recipient this machine cannot wrap to (a browser passkey-PRF a
    // laptop can't evaluate, an unattached FIDO2) is dropped from the new wrap,
    // so re-encrypting here REVOKES their access to the affected items.
    // warn_about_skips already named them; the DefaultEncryptOff skip is an
    // owner setting, not a revocation.
    let would_revoke = plan
        .skips
        .iter()
        .any(|s| s.reason != ragewarden_core::policy::SkipReason::DefaultEncryptOff);

    let names: Vec<String> = if let Some(only) = only {
        refresh_vault_cache().await?;
        only.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
    } else if all {
        protected_item_names(folder).await?
    } else {
        refresh_vault_cache().await?;
        vec![name.unwrap().to_string()]
    };

    if names.is_empty() {
        eprintln!("(no protected items to re-encrypt)");
        return Ok(());
    }

    // A revocation must never happen unattended. Under `--yes` we refuse unless
    // `--allow-revoke` is also given; the interactive paths get an explicit
    // confirmation that names the loss.
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

    // A single named item keeps `get`'s per-item gate verbatim. A batch takes
    // ONE confirmation up front, then re-encrypts each with the software gate
    // pre-authorized -- a hardware vault still taps per item, since `--yes`
    // never applies to a real device.
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
        // Single item: the per-item consent gate still fires inside rewrap_one;
        // add an explicit revocation confirm on top when interactive.
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
        match rewrap_one(n, "the current recipient set", &target, &target, "Reencrypt", effective_yes, no_wait).await {
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
    // #4: a transient failure must propagate so callers (offer_fold_in) surface
    // the incompleteness instead of exiting 0 on a half-done fold-in.
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

    // Resolved before the decrypt: every refusal is decidable without the
    // plaintext, and a restrict that was never going to happen should not have
    // cost a PIN and a tap first.
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
    // The recipient list is account-wide, so nothing stops `--to` naming only
    // another machine's key. Writing there would overwrite the one wrap this
    // terminal can open and then print success -- refused, because narrowing an
    // item to a device you don't hold is data loss.
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

    // Named, not counted: `restrict` is the one command that drops a recipient
    // outright, so the exact set it wrote is spelled out.
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
    let names = match protected_item_names(None).await {
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
    match confirm_action(&format!("Fold `{new_recipient_label}` into them now (re-encrypts {} item(s))", names.len())) {
        Ok(()) => {
            // The enrollment already succeeded; a fold-in failure must never
            // turn that into an error exit -- report and point at the manual run.
            if let Err(e) = cmd_reencrypt(None, true, None, None, false, false, false).await {
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

fn build_prf_outputs_for(
    recipients: &[Recipient],
) -> Result<Vec<(String, [u8; 32], [u8; 32])>, CmdError> {
    let mut out: Vec<(String, [u8; 32], [u8; 32])> = Vec::new();
    let enrolled = Identities::load()?;
    for r in recipients {
        match r {
            Recipient::Fido2HmacSecret {
                credential_id,
                salt,
                rp_id,
            } => {
                // The `Recipient` on the wire carries no mock flag; the local
                // enrollment record is the only trustworthy source.
                let mock = enrolled.is_mock_fido_credential(credential_id);
                let prf = fido::derive_prf_for_encrypt(credential_id, salt, rp_id, mock)?;
                out.push((rp_id.clone(), *salt, prf));
            }
            Recipient::PasskeyPrf { .. } => {
                return Err(CmdError::InvalidArg(
                    "passkey-prf recipients can only be encrypted from a browser context".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(out)
}

fn build_rage_login_cipher(
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
        cipher_type: 1,
        name: enc_name,
        notes: Some(enc_marker),
        login: Some(CipherLogin {
            username: None,
            password: None,
            totp: None,
            uris: None,
        }),
        secure_note: None,
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

async fn save_rage_blob_under_name(name: &str, armored: &str) -> Result<(), CmdError> {
    if let Some(open) = session::load()? {
        let client = ReqwestClient::new().map_err(|e| CmdError::Sync(sync::SyncError::Http(e)))?;
        let cipher_in = build_rage_cipher(&open.session, name, armored)?;
        let cached = vault_cache::load()?;
        let existing = cached
            .as_ref()
            .and_then(|v| find_cipher_by_name(&open.session, v, name));
        let saved: Cipher = if let Some(existing) = existing {
            update_cipher(
                &client,
                &open.server,
                &open.session,
                existing.id.as_deref().unwrap_or(""),
                &cipher_in,
            )
            .await?
        } else {
            create_cipher(&client, &open.server, &open.session, &cipher_in).await?
        };
        let mut vault = cached.unwrap_or_default();
        if let Some(id) = &saved.id {
            vault
                .ciphers
                .retain(|c| c.id.as_deref() != Some(id.as_str()));
        }
        vault.ciphers.push(saved);
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
    let entry = RecipientEntry {
        id: id.to_string(),
        label: label.to_string(),
        created: Utc::now(),
        last_used: None,
        recipient,
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
    // Chromium has no default: an `allowed_origins` entry that is not a real
    // 32-char a-p extension id makes Chrome silently refuse to start the host,
    // so the id is required (prompted for at a terminal) and validated before
    // anything is written.
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
        NhBrowser::Safari => extension_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| "com.ragewarden.safari".to_string()),
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

pub fn cmd_uninstall_native_host(browser: &str, system: bool) -> Result<(), CmdError> {
    let browser = NhBrowser::parse(browser)?;
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

    // Recipient selection MUST match the canonical write path
    // (`cmd_set` -> load_encrypt_plan -> policy::select_for_encrypt), which
    // folds in RECOVERY-kind entries BY KIND. The old hand-rolled selector here
    // filtered `!label.to_lowercase().contains("recovery")`, which dropped the
    // paper recovery key -- so every imported item was wrapped WITHOUT recovery
    // coverage, and once the user's device keys were lost the 24-word phrase
    // recovered everything EXCEPT their migrated secrets. It also silently
    // dropped any hardware key a user happened to label "Recovery YubiKey".
    // `--default-recipient` keeps the explicit single-recipient override, the
    // same escape hatch cmd_set's `--to` provides.
    let target_recipients: Vec<Recipient> = if let Some(id) = opts.default_recipient {
        let list = recipients::load().await?;
        let entry = list
            .entries
            .get(id)
            .ok_or_else(|| CmdError::NotFound(format!("recipient {id}")))?;
        vec![entry.recipient.clone()]
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
    let prf_table: Vec<PrfEntry<'_>> = prf_outputs
        .iter()
        .map(|(rp_id, salt, prf)| PrfEntry {
            rp_id,
            salt,
            prf_output: prf,
        })
        .collect();

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
    let plaintext = decrypt_named_locked(name, no_wait, &consent_guard).await?;

    let outcome = agent_add::add_to_agent(AddOptions {
        plaintext: &plaintext,
        comment: name,
        lifetime_secs,
    })?;
    drop(plaintext);

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
    audit_helper::record_with(
        ragewarden_core::audit::AuditKind::Autofill,
        name.to_string(),
        spec.describe(),
    );
    let plaintext = decrypt_named_locked(name, no_wait, &consent_guard).await?;
    backend.type_into(&plaintext, &spec)?;
    drop(plaintext);
    eprintln!(
        "Typed `{name}` into {} (via {}).",
        spec.describe(),
        backend.name()
    );
    Ok(())
}
