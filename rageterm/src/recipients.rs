use std::collections::BTreeMap;
use std::fs;
use std::io;

use chrono::{DateTime, Utc};
use ragewarden_core::sync::{
    self, create_cipher, decrypt_string, encrypt_string, fetch_vault, update_cipher, Cipher,
    Session, Vault,
};
use ragewarden_core::policy;
use ragewarden_core::registry::WireEntry;
use ragewarden_core::Recipient;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config;
use crate::http::ReqwestClient;
use crate::vault as vault_cache;

pub const RECIPIENT_LIST_NAME: &str = "Ragewarden Recipients (do not edit)";

#[derive(Debug, Error)]
pub enum RecipientListError {
    #[error("recipients io: {0}")]
    Io(#[from] io::Error),

    #[error("recipients parse: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("sync: {0}")]
    Sync(#[from] sync::SyncError),

    #[error("vault cache: {0}")]
    VaultCache(#[from] crate::vault::VaultCacheError),

    #[error("http: {0}")]
    Http(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientEntry {
    pub id: String,

    pub label: String,

    pub created: DateTime<Utc>,

    pub last_used: Option<DateTime<Utc>>,

    pub recipient: Recipient,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecipientList {
    #[serde(default = "default_version")]
    pub version: u32,

    pub entries: BTreeMap<String, RecipientEntry>,
}

fn default_version() -> u32 {
    1
}

impl RecipientList {
    pub fn iter_chronological(&self) -> impl Iterator<Item = &RecipientEntry> {
        let mut v: Vec<&RecipientEntry> = self.entries.values().collect();
        v.sort_by_key(|e| e.created);
        v.into_iter()
    }

    // Test-only since pass-import stopped selecting recipients by hand (it now
    // goes through load_encrypt_plan like cmd_set). Kept as a test helper.
    #[cfg(test)]
    pub fn recipients(&self) -> Vec<Recipient> {
        self.iter_chronological()
            .map(|e| e.recipient.clone())
            .collect()
    }
}

pub async fn load() -> Result<RecipientList, RecipientListError> {
    if let Some(open) = crate::session::load()
        .map_err(|e| RecipientListError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?
    {
        if let Some(cached) = vault_cache::load()? {
            if let Some(list) = extract_from_vault(&open.session, &cached)? {
                return Ok(list);
            }
        }

        let client = ReqwestClient::new().map_err(|e| RecipientListError::Http(e.to_string()))?;
        let vault = fetch_vault(&client, &open.server, &open.session).await?;
        vault_cache::save(&vault)?;
        Ok(extract_from_vault(&open.session, &vault)?.unwrap_or_default())
    } else {
        load_local()
    }
}

pub async fn save(list: &RecipientList) -> Result<(), RecipientListError> {
    if let Some(open) = crate::session::load()
        .map_err(|e| RecipientListError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?
    {
        let serialized = serde_json::to_string_pretty(list)?;

        let client = ReqwestClient::new().map_err(|e| RecipientListError::Http(e.to_string()))?;

        let cached = vault_cache::load()?;
        let existing = cached
            .as_ref()
            .and_then(|v| find_recipient_cipher(&open.session, v));

        let cipher_in = build_recipients_cipher(&open.session, &serialized)?;
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
        Ok(())
    } else {
        save_local(list)
    }
}

pub async fn add(entry: RecipientEntry) -> Result<(), RecipientListError> {
    // Fetch fresh before the read-modify-write. The account-wide RecipientList
    // is ONE cipher every device edits and `save` below is last-write-wins, so
    // building the new list off a stale cached copy would drop a sibling
    // device's concurrently-added recipient -- the same clobber
    // open_with_fresh_vault fixes for the registry marker. Fetching fresh also
    // refreshes the cache that `save` then reads to find the cipher id.
    if let Some((open, _client, vault)) = open_with_fresh_vault().await? {
        let mut list = extract_from_vault(&open.session, &vault)?.unwrap_or_default();
        list.entries.insert(entry.id.clone(), entry);
        save(&list).await
    } else {
        let mut list = load_local()?;
        list.entries.insert(entry.id.clone(), entry);
        save_local(&list)
    }
}

/// Open the session, build a client, and fetch a FRESH vault (saving it to the
/// cache). Returns `None` when no session is open, so callers no-op.
///
/// Fetch fresh before every registry read-modify-write. The marker is ONE
/// cipher every client edits; a remote device (ragedroid, the browser) may
/// have appended its recipient since this machine last synced, and the
/// on-disk cache is not invalidated when it does. `update_cipher` is
/// last-write-wins with no revision merge, so building the new document from
/// a stale cache and writing it back SILENTLY DELETES the sibling's entry --
/// and that device then loses access to every secret created afterward.
/// ragedroid (BitwardenVaultRepository.pushRecipientRegistry) and the wasm
/// client both sync-then-read-modify-write for exactly this reason; this is
/// rageterm joining them. Never read the registry doc from a cache a remote
/// device can stale.
async fn open_with_fresh_vault(
) -> Result<Option<(crate::session::OpenSession, ReqwestClient, Vault)>, RecipientListError> {
    let Some(open) = crate::session::load()
        .map_err(|e| RecipientListError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?
    else {
        return Ok(None);
    };
    let client = ReqwestClient::new().map_err(|e| RecipientListError::Http(e.to_string()))?;
    let vault = fetch_vault(&client, &open.server, &open.session).await?;
    vault_cache::save(&vault)?;
    Ok(Some((open, client, vault)))
}

/// Replace any prior copy of `saved` in the cache and add it back, so the local
/// vault reflects the cipher we just wrote server-side.
fn persist_saved_cipher(mut vault: Vault, saved: Cipher) -> Result<(), RecipientListError> {
    if let Some(id) = &saved.id {
        vault.ciphers.retain(|c| c.id.as_deref() != Some(id.as_str()));
    }
    vault.ciphers.push(saved);
    vault_cache::save(&vault)?;
    Ok(())
}

pub async fn publish_wire_entry_to_registry(
    entry: ragewarden_core::registry::WireEntry,
) -> Result<(), RecipientListError> {
    use ragewarden_core::registry::{self, MARKER_NAME};

    let Some((open, client, vault)) = open_with_fresh_vault().await? else {
        return Ok(());
    };

    let mut doc = registry::extract_document(&open.session, &vault)?.unwrap_or_default();

    if doc.entries.iter().any(|e| e == &entry) {
        return Ok(());
    }

    doc.entries.retain(|e| e.id != entry.id);
    doc.entries.push(entry);

    let payload = serde_json::to_string(&doc)?;
    let cipher_in = sync::build_meta_cipher(&open.session, MARKER_NAME, &payload)?;
    let existing_id = registry::marker_cipher_id(&open.session, &vault).map(str::to_owned);

    let saved = if let Some(id) = existing_id {
        update_cipher(&client, &open.server, &open.session, &id, &cipher_in).await?
    } else {
        create_cipher(&client, &open.server, &open.session, &cipher_in).await?
    };

    persist_saved_cipher(vault, saved)
}

pub async fn unpublish_from_registry(entry_id: &str) -> Result<(), RecipientListError> {
    use ragewarden_core::registry::{self, MARKER_NAME};

    let Some((open, client, vault)) = open_with_fresh_vault().await? else {
        return Ok(());
    };

    let Some(mut doc) = registry::extract_document(&open.session, &vault)? else {
        return Ok(());
    };
    let before = doc.entries.len();
    doc.entries.retain(|e| e.id != entry_id);
    if doc.entries.len() == before {
        return Ok(());
    }

    let payload = serde_json::to_string(&doc)?;
    let cipher_in = sync::build_meta_cipher(&open.session, MARKER_NAME, &payload)?;
    let Some(existing_id) = registry::marker_cipher_id(&open.session, &vault).map(str::to_owned)
    else {
        return Ok(());
    };
    let saved = update_cipher(&client, &open.server, &open.session, &existing_id, &cipher_in)
        .await?;

    persist_saved_cipher(vault, saved)
}

pub async fn publish_local_identity_to_registry() -> Result<(), RecipientListError> {
    let id_path = config::identity_path()?;
    if !id_path.exists() {
        return Ok(());
    }
    let armored = crate::idfile::read_public_key_armored(&id_path)
        .map_err(|e| RecipientListError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
    publish_wire_entry_to_registry(software_wire_entry(&armored, "Terminal")).await
}

pub fn software_wire_entry(
    armored_pubkey: &str,
    display_name: &str,
) -> ragewarden_core::registry::WireEntry {
    use ragewarden_core::registry::{kinds, WireEntry};
    WireEntry {
        id: stable_software_recipient_id(armored_pubkey),
        kind: kinds::SOFTWARE.into(),
        display_name: display_name.into(),
        device_label: format!("rageterm@{}", hostname_or_unknown()),
        created_at: chrono::Utc::now().timestamp_millis(),
        default_encrypt: true,
        piv_pubkey: None,
        piv_serial: None,
        piv_slot: None,
        keystore_pubkey: None,
        keystore_handle: None,
        fido2_credential_id: None,
        fido2_rp_id: None,
        fido2_salt: None,
        recovery_armored_pubkey: Some(armored_pubkey.to_string()),
    }
}

pub fn piv_wire_entry(
    public_key: &[u8; 32],
    serial: u32,
    slot: u8,
    display_name: &str,
) -> ragewarden_core::registry::WireEntry {
    use ragewarden_core::registry::{kinds, WireEntry};
    WireEntry {
        id: stable_piv_recipient_id(serial, slot),
        kind: kinds::YUBIKEY.into(),
        display_name: display_name.into(),
        device_label: format!("rageterm@{}", hostname_or_unknown()),
        created_at: chrono::Utc::now().timestamp_millis(),
        default_encrypt: true,
        piv_pubkey: Some(hex::encode(public_key)),
        piv_serial: Some(serial as i32),
        piv_slot: Some(slot as i32),
        keystore_pubkey: None,
        keystore_handle: None,
        fido2_credential_id: None,
        fido2_rp_id: None,
        fido2_salt: None,
        recovery_armored_pubkey: None,
    }
}

pub fn fido2_wire_entry(
    credential_id: &[u8],
    salt: &[u8; 32],
    rp_id: &str,
    display_name: &str,
) -> ragewarden_core::registry::WireEntry {
    use ragewarden_core::registry::{kinds, WireEntry};
    WireEntry {
        id: stable_fido2_recipient_id(rp_id, credential_id),
        kind: kinds::FIDO2.into(),
        display_name: display_name.into(),
        device_label: format!("rageterm@{}", hostname_or_unknown()),
        created_at: chrono::Utc::now().timestamp_millis(),
        default_encrypt: true,
        piv_pubkey: None,
        piv_serial: None,
        piv_slot: None,
        keystore_pubkey: None,
        keystore_handle: None,
        fido2_credential_id: Some(hex::encode(credential_id)),
        fido2_rp_id: Some(rp_id.to_string()),
        fido2_salt: Some(hex::encode(salt)),
        recovery_armored_pubkey: None,
    }
}

pub fn recovery_wire_entry(
    armored_pubkey: &str,
    display_name: &str,
) -> ragewarden_core::registry::WireEntry {
    use ragewarden_core::registry::{kinds, WireEntry};
    WireEntry {
        id: stable_recovery_recipient_id(armored_pubkey),
        kind: kinds::RECOVERY.into(),
        display_name: display_name.into(),
        device_label: format!("rageterm@{}", hostname_or_unknown()),
        created_at: chrono::Utc::now().timestamp_millis(),
        default_encrypt: true,
        piv_pubkey: None,
        piv_serial: None,
        piv_slot: None,
        keystore_pubkey: None,
        keystore_handle: None,
        fido2_credential_id: None,
        fido2_rp_id: None,
        fido2_salt: None,
        recovery_armored_pubkey: Some(armored_pubkey.to_string()),
    }
}

pub fn registry_id_for_enrolled_identity(
    kind: &crate::identities::IdentityKind,
) -> Option<String> {
    use crate::identities::IdentityKind;
    match kind {
        IdentityKind::YubiKeyPiv { serial, slot, .. } => {
            Some(stable_piv_recipient_id(*serial, *slot))
        }
        IdentityKind::Fido2HmacSecret {
            credential_id_b64,
            rp_id,
            ..
        } => {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
            let credential_id = B64URL.decode(credential_id_b64.as_bytes()).ok()?;
            Some(stable_fido2_recipient_id(rp_id, &credential_id))
        }
        IdentityKind::OsKeyring { armored_pubkey, .. } => {
            Some(stable_software_recipient_id(armored_pubkey.as_str()))
        }
        IdentityKind::PaperRecovery { armored_pubkey } => {
            Some(stable_recovery_recipient_id(armored_pubkey.as_str()))
        }
    }
}

fn stable_software_recipient_id(armored_pubkey: &str) -> String {
    stable_id("rageterm-software-v1", armored_pubkey.as_bytes())
}

fn stable_piv_recipient_id(serial: u32, slot: u8) -> String {
    let mut buf = Vec::with_capacity(5);
    buf.extend_from_slice(&serial.to_be_bytes());
    buf.push(slot);
    stable_id("rageterm-piv-v1", &buf)
}

fn stable_fido2_recipient_id(rp_id: &str, credential_id: &[u8]) -> String {
    let mut buf = Vec::with_capacity(rp_id.len() + 1 + credential_id.len());
    buf.extend_from_slice(rp_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(credential_id);
    stable_id("rageterm-fido2-v1", &buf)
}

fn stable_recovery_recipient_id(armored_pubkey: &str) -> String {
    stable_id("rageterm-recovery-v1", armored_pubkey.as_bytes())
}

fn stable_id(domain: &'static str, material: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update(material);
    let digest = h.finalize();
    let prefix = domain.strip_prefix("rageterm-").unwrap_or(domain);
    let prefix = prefix.strip_suffix("-v1").unwrap_or(prefix);
    format!("rageterm-{prefix}-{}", hex::encode(&digest[..16]))
}

fn hostname_or_unknown() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string())
}

/// A locally-stored [`RecipientEntry`] rendered as a registry [`WireEntry`] so
/// that it goes through the same canonical policy as the cross-device registry
/// instead of being appended unfiltered.
///
/// The id is the *stable* registry id for the key material, not the local
/// random one, so a locally-enrolled key and its registry publication collapse
/// to a single recipient rather than being wrapped twice.
pub fn local_entry_as_wire(entry: &RecipientEntry) -> WireEntry {
    use ragewarden_core::registry::kinds;

    let mut wire = WireEntry {
        id: entry.id.clone(),
        kind: "Unmapped".into(),
        display_name: entry.label.clone(),
        device_label: format!("rageterm@{}", hostname_or_unknown()),
        created_at: entry.created.timestamp_millis(),
        default_encrypt: true,
        piv_pubkey: None,
        piv_serial: None,
        piv_slot: None,
        keystore_pubkey: None,
        keystore_handle: None,
        fido2_credential_id: None,
        fido2_rp_id: None,
        fido2_salt: None,
        recovery_armored_pubkey: None,
    };

    match &entry.recipient {
        Recipient::YubiKeyPiv {
            public_key,
            serial,
            slot,
        } => {
            wire.id = stable_piv_recipient_id(*serial, *slot);
            wire.kind = kinds::YUBIKEY.into();
            wire.piv_pubkey = Some(hex::encode(public_key));
            wire.piv_serial = Some(*serial as i32);
            wire.piv_slot = Some(*slot as i32);
        }
        Recipient::Fido2HmacSecret {
            credential_id,
            salt,
            rp_id,
        } => {
            wire.id = stable_fido2_recipient_id(rp_id, credential_id);
            wire.kind = kinds::FIDO2.into();
            wire.fido2_credential_id = Some(hex::encode(credential_id));
            wire.fido2_salt = Some(hex::encode(salt));
            wire.fido2_rp_id = Some(rp_id.clone());
        }
        // NOT kinds::FIDO2 -- a WebAuthn-PRF passkey wraps into the
        // `webauthn-prf-v1` stanza, not `fido2-hmac`. Publishing it as Fido2
        // would hand every other client a recipient it wraps with the wrong
        // tag and HKDF info.
        Recipient::PasskeyPrf {
            credential_id,
            salt,
            rp_id,
            label,
        } => {
            wire.id = stable_fido2_recipient_id(rp_id, credential_id);
            wire.kind = kinds::PASSKEY_PRF.into();
            wire.display_name = label.clone();
            wire.fido2_credential_id = Some(hex::encode(credential_id));
            wire.fido2_salt = Some(hex::encode(salt));
            wire.fido2_rp_id = Some(rp_id.clone());
        }
        Recipient::SoftwarePassphrase { armored_pubkey } => {
            wire.id = stable_software_recipient_id(armored_pubkey.as_str());
            wire.kind = kinds::SOFTWARE.into();
            wire.recovery_armored_pubkey = Some(armored_pubkey.as_str().to_string());
        }
        Recipient::AndroidKeystore {
            public_key,
            key_handle,
        } => {
            wire.kind = kinds::STRONG_BOX.into();
            wire.keystore_pubkey = Some(hex::encode(public_key));
            wire.keystore_handle = Some(key_handle.clone());
        }
        Recipient::X25519 { public_key } => {
            wire.id = stable_software_recipient_id(&hex::encode(public_key));
            wire.kind = kinds::SOFTWARE.into();
            wire.recovery_armored_pubkey =
                Some(ragewarden_core::bech32::encode_age_x25519(public_key));
        }
    }

    wire
}

/// A [`policy::SkippedEntry`] resolved into something a human can act on. The
/// policy only knows ids, and an id is a hash of key material -- useless in a
/// warning -- so the name is looked back up from the entry the id came out of.
#[derive(Debug, Clone)]
pub struct SkipNote {
    pub kind: String,

    pub reason: policy::SkipReason,

    /// Display name, plus the device that enrolled it when the registry says.
    pub who: String,
}

impl SkipNote {
    pub fn describe(&self) -> String {
        format!(
            "{} [{}] -- {}",
            self.who,
            self.kind,
            skip_reason_str(self.reason)
        )
    }
}

/// What a write from this machine will wrap to, plus the named holes in it.
#[derive(Debug, Clone)]
pub struct EncryptPlan {
    pub selection: policy::Selection,

    pub skips: Vec<SkipNote>,
}

pub fn skip_reason_str(reason: policy::SkipReason) -> &'static str {
    match reason {
        policy::SkipReason::DefaultEncryptOff => "its owner turned it off for new writes",
        policy::SkipReason::UnknownKind => "this rageterm build does not know that kind",
        policy::SkipReason::MalformedKeyMaterial => "its key material is unusable",
        policy::SkipReason::NoLocalAuthenticator => {
            "its authenticator is not attached to this machine"
        }
    }
}

/// Print the coverage holes. Silent when there are none.
///
/// Call this once per command, from the command itself -- never from an accessor
/// that a write path might go through twice. `set` loads the encrypt set for the
/// write *and* for the prior revision it folds into history, and warning from
/// inside the accessor printed the same block back to back.
pub fn warn_about_skips(skips: &[SkipNote]) {
    // `DefaultEncryptOff` is left out on purpose. It is a setting its owner
    // chose, so it is not news; shouting about it in the same voice and
    // directly above a real `NoLocalAuthenticator` hole is how the warning that
    // matters gets skimmed past. `rageterm recipients` still lists every skip,
    // that one included.
    let holes: Vec<&SkipNote> = skips
        .iter()
        .filter(|s| s.reason != policy::SkipReason::DefaultEncryptOff)
        .collect();
    if holes.is_empty() {
        return;
    }
    eprintln!(
        "rageterm: {} recipient(s) will NOT be able to open what this machine writes:",
        holes.len(),
    );
    for s in &holes {
        eprintln!("  {}", s.describe());
    }
    if holes
        .iter()
        .any(|s| s.reason == policy::SkipReason::NoLocalAuthenticator)
    {
        eprintln!(
            "rageterm: their holders must open the item with another recipient of theirs, or the \
             write has to be repeated from the machine that holds the authenticator."
        );
    }
}

/// The FIDO2 authenticators *this* machine can evaluate a PRF on during a wrap.
///
/// The authority is `identities.json`, which is per-device, and deliberately
/// not the recipient list: that list round-trips through the vault, so it is
/// account-wide. Deriving this from it declared every FIDO2 key *any* terminal
/// on the account had ever enrolled to be locally tappable, `policy` therefore
/// never emitted `NoLocalAuthenticator`, and every write from a second terminal
/// died at PRF derivation time because the attached device does not hold that
/// credential.
///
/// Only `Fido2HmacSecret` qualifies: it is the sole PRF-bearing variant of
/// `IdentityKind`. A WebAuthn-PRF passkey is never enrolled through rageterm
/// (it cannot evaluate one -- see `commands::build_prf_outputs_for`), so leaving
/// it unclaimed here is correct rather than an omission.
fn local_prf_authenticators() -> Result<policy::LocalAuthenticators, RecipientListError> {
    let enrolled = crate::identities::Identities::load()
        .map_err(|e| RecipientListError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
    Ok(policy::LocalAuthenticators::from_ids(
        enrolled
            .items
            .values()
            .filter(|e| {
                matches!(
                    e.kind,
                    crate::identities::IdentityKind::Fido2HmacSecret { .. }
                )
            })
            .filter_map(|e| registry_id_for_enrolled_identity(&e.kind)),
    ))
}

fn describe_skips(
    skipped: &[policy::SkippedEntry],
    registry: &[WireEntry],
    local: &[WireEntry],
) -> Vec<SkipNote> {
    skipped
        .iter()
        .map(|s| {
            // The registry copy names it even though `merge_entries` prefers
            // the local copy for key material: a local entry's `device_label`
            // is synthesised from *this* hostname, so on a second terminal it
            // would report another machine's key as belonging to this one.
            let who = registry
                .iter()
                .find(|w| w.id == s.id)
                .map(|w| format!("{} ({})", w.display_name, w.device_label))
                .or_else(|| {
                    local
                        .iter()
                        .find(|w| w.id == s.id)
                        .map(|w| w.display_name.clone())
                })
                .unwrap_or_else(|| s.id.clone());
            SkipNote {
                kind: s.kind.clone(),
                reason: s.reason,
                who,
            }
        })
        .collect()
}

/// Runs the one canonical policy (`ragewarden_core::policy`) that ragedroid and
/// ragemanifest also run. rageterm gets to it by linking core directly; the
/// other two reach the same function through JNI and wasm respectively.
///
/// Returns the skips as well, so callers can warn about the recipients this
/// machine could not cover.
pub async fn load_encrypt_plan() -> Result<EncryptPlan, RecipientListError> {
    let local = load().await?;

    let local_entries: Vec<WireEntry> =
        local.iter_chronological().map(local_entry_as_wire).collect();

    // The one sanctioned per-client divergence: a PRF recipient can only be
    // wrapped to by a client that can evaluate its authenticator during the
    // wrap.
    let local_auth = local_prf_authenticators()?;

    let registry_entries: Vec<WireEntry> = if let Some(open) = crate::session::load()
        .map_err(|e| RecipientListError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?
    {
        let vault = match vault_cache::load()? {
            Some(v) => v,
            None => {
                let client =
                    ReqwestClient::new().map_err(|e| RecipientListError::Http(e.to_string()))?;
                let v = fetch_vault(&client, &open.server, &open.session).await?;
                vault_cache::save(&v)?;
                v
            }
        };
        ragewarden_core::registry::extract_document(&open.session, &vault)?
            .map(|doc| doc.entries)
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let mut selection = policy::select_for_encrypt(&registry_entries, &local_entries, &local_auth);

    let id_path = config::identity_path()?;
    if id_path.exists() {
        let pub_armored = crate::idfile::read_public_key_armored(&id_path).map_err(|e| {
            RecipientListError::Io(io::Error::new(io::ErrorKind::Other, e.to_string()))
        })?;
        let local_recipient = Recipient::SoftwarePassphrase {
            armored_pubkey: ragewarden_core::ArmoredAgeRecipient::from_trusted(pub_armored),
        };
        if !selection.recipients.contains(&local_recipient) {
            selection.recipients.push(local_recipient);
        }
    } else if selection.recipients.is_empty() {
        return Err(RecipientListError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "no identity.age and no recipients enrolled -- run `rageterm enroll-software-identity`",
        )));
    }

    let skips = describe_skips(&selection.skipped, &registry_entries, &local_entries);
    Ok(EncryptPlan { selection, skips })
}

/// Whether this machine still holds the private half of at least one of `set`.
///
/// The authority is per-device -- `identities.json` plus `identity.age` -- and
/// deliberately not the recipient list, which round-trips through the vault and
/// is therefore account-wide. Answering from that list is how
/// `rotate --to <another device's id>` re-wrapped an item to a key this terminal
/// cannot open and then reported success; the old wrap is gone by then.
///
/// `PaperRecovery` does not count: the registry keeps its public half, but the
/// private half is 24 words on paper, not on this disk. Neither does a
/// `mock: true` enrollment in a build with no stand-ins compiled in, where it
/// cannot decrypt at all.
pub fn any_readable_on_this_machine(set: &[Recipient]) -> Result<bool, RecipientListError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};

    use crate::identities::IdentityKind;

    let enrolled = crate::identities::Identities::load()
        .map_err(|e| RecipientListError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
    let mocks_usable = crate::hw::mock_enabled();

    let id_path = config::identity_path()?;
    let own_software: Option<String> = if id_path.exists() {
        Some(
            crate::idfile::read_public_key_armored(&id_path).map_err(|e| {
                RecipientListError::Io(io::Error::new(io::ErrorKind::Other, e.to_string()))
            })?,
        )
    } else {
        None
    };

    Ok(set.iter().any(|r| match r {
        Recipient::YubiKeyPiv { public_key, .. } => {
            let want = hex::encode(public_key);
            enrolled.items.values().any(|e| match &e.kind {
                IdentityKind::YubiKeyPiv {
                    public_key_hex,
                    mock,
                    ..
                } => (!*mock || mocks_usable) && public_key_hex.eq_ignore_ascii_case(&want),
                _ => false,
            })
        }
        Recipient::Fido2HmacSecret { credential_id, .. } => {
            enrolled.items.values().any(|e| match &e.kind {
                IdentityKind::Fido2HmacSecret {
                    credential_id_b64,
                    mock,
                    ..
                } => {
                    (!*mock || mocks_usable)
                        && B64URL
                            .decode(credential_id_b64)
                            .map(|got| got == *credential_id)
                            .unwrap_or(false)
                }
                _ => false,
            })
        }
        Recipient::SoftwarePassphrase { armored_pubkey } => {
            own_software.as_deref() == Some(armored_pubkey.as_str())
                || enrolled.items.values().any(|e| match &e.kind {
                    IdentityKind::OsKeyring {
                        armored_pubkey: keyring_pub,
                        ..
                    } => keyring_pub.as_str() == armored_pubkey.as_str(),
                    _ => false,
                })
        }
        // The registry publishes the very same key as `x25519` that the local
        // list calls a `SoftwarePassphrase`, so compare the armored form rather
        // than letting the wire shape decide the answer.
        Recipient::X25519 { public_key } => {
            own_software.as_deref()
                == Some(ragewarden_core::bech32::encode_age_x25519(public_key).as_str())
        }
        // rageterm can evaluate neither a WebAuthn PRF (see
        // `commands::build_prf_outputs_for`) nor an Android keystore, so a wrap
        // to either is never openable here.
        Recipient::PasskeyPrf { .. } | Recipient::AndroidKeystore { .. } => false,
    }))
}

pub async fn remove(id: &str) -> Result<Option<RecipientEntry>, RecipientListError> {
    // Fetch fresh before the read-modify-write, same reason as `add`: a stale
    // cached list would resurrect a sibling's just-removed recipient or drop a
    // just-added one when `save` writes it back last-write-wins.
    if let Some((open, _client, vault)) = open_with_fresh_vault().await? {
        let mut list = extract_from_vault(&open.session, &vault)?.unwrap_or_default();
        let removed = list.entries.remove(id);
        if removed.is_some() {
            save(&list).await?;
        }
        Ok(removed)
    } else {
        let mut list = load_local()?;
        let removed = list.entries.remove(id);
        if removed.is_some() {
            save_local(&list)?;
        }
        Ok(removed)
    }
}

fn build_recipients_cipher(
    session: &Session,
    serialized: &str,
) -> Result<sync::CipherIn, RecipientListError> {
    let enc_name = encrypt_string(session, RECIPIENT_LIST_NAME)?;
    let enc_notes = encrypt_string(session, serialized)?;
    Ok(sync::CipherIn {
        cipher_type: 2,
        name: enc_name,
        notes: Some(enc_notes),
        login: None,
        secure_note: Some(sync::SecureNote { note_type: 0 }),
        fields: None,
        folder_id: None,
        organization_id: None,
        favorite: false,
    })
}

fn find_recipient_cipher<'a>(session: &Session, vault: &'a Vault) -> Option<&'a Cipher> {
    vault.ciphers.iter().find(|c| {
        sync::cipher_name(session, c)
            .map(|n| n == RECIPIENT_LIST_NAME)
            .unwrap_or(false)
    })
}

fn extract_from_vault(
    session: &Session,
    vault: &Vault,
) -> Result<Option<RecipientList>, RecipientListError> {
    let Some(cipher) = find_recipient_cipher(session, vault) else {
        return Ok(None);
    };
    let Some(notes_ct) = &cipher.notes else {
        return Ok(None);
    };
    let plaintext = decrypt_string(session, notes_ct)?;
    let list: RecipientList = serde_json::from_str(&plaintext)?;
    Ok(Some(list))
}

fn load_local() -> Result<RecipientList, RecipientListError> {
    let path = config::config_dir()?.join("recipients.json");
    match fs::read(&path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(RecipientList::default()),
        Err(e) => Err(e.into()),
    }
}

fn save_local(list: &RecipientList) -> Result<(), RecipientListError> {
    let path = config::config_dir()?.join("recipients.json");
    config::ensure_config_dir()?;
    let bytes = serde_json::to_vec_pretty(list)?;
    config::write_private(&path, &bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_for(recipient: Recipient) -> RecipientEntry {
        RecipientEntry {
            id: "local-random-id".into(),
            label: "l".into(),
            created: Utc::now(),
            last_used: None,
            recipient,
        }
    }

    /// The local list used to be appended to the encrypt set unfiltered while
    /// registry entries went through a different filter. Both now go through
    /// `ragewarden_core::policy`, which requires local entries to be expressible
    /// as registry entries.
    #[test]
    fn local_entries_map_onto_registry_kinds() {
        use ragewarden_core::registry::kinds;

        let cases = [
            (
                Recipient::SoftwarePassphrase {
                    armored_pubkey: ragewarden_core::ArmoredAgeRecipient::from_trusted(
                        "age1x".into(),
                    ),
                },
                kinds::SOFTWARE,
            ),
            (
                Recipient::YubiKeyPiv {
                    public_key: [1u8; 32],
                    serial: 7,
                    slot: 0x95,
                },
                kinds::YUBIKEY,
            ),
            (
                Recipient::Fido2HmacSecret {
                    credential_id: vec![1, 2, 3],
                    salt: [0u8; 32],
                    rp_id: "ragewarden".into(),
                },
                kinds::FIDO2,
            ),
            (
                Recipient::PasskeyPrf {
                    credential_id: vec![1, 2, 3],
                    salt: [0u8; 32],
                    rp_id: "ragewarden".into(),
                    label: "p".into(),
                },
                kinds::PASSKEY_PRF,
            ),
            (
                Recipient::AndroidKeystore {
                    public_key: vec![2u8; 33],
                    key_handle: "h".into(),
                },
                kinds::STRONG_BOX,
            ),
        ];

        for (recipient, expected_kind) in cases {
            let wire = local_entry_as_wire(&entry_for(recipient.clone()));
            assert_eq!(wire.kind, expected_kind, "for {recipient:?}");
            assert_eq!(
                wire.to_recipient_if_active(),
                Some(recipient.clone()),
                "wire round trip lost {recipient:?}",
            );
        }
    }

    /// A locally-enrolled FIDO2 key is reachable from this machine, so the
    /// policy keeps it; the identical entry arriving only from the registry
    /// (some other device's passkey) is dropped with a named reason rather than
    /// silently.
    #[test]
    fn local_fido2_is_wrappable_but_a_foreign_one_is_reported() {
        let local = local_entry_as_wire(&entry_for(Recipient::Fido2HmacSecret {
            credential_id: vec![9, 9, 9],
            salt: [3u8; 32],
            rp_id: "ragewarden".into(),
        }));

        let held = policy::LocalAuthenticators::from_ids([local.id.clone()]);
        let with_key = policy::select_for_encrypt(&[], &[local.clone()], &held);
        assert_eq!(with_key.recipients.len(), 1);
        assert!(with_key.skipped.is_empty());

        let without = policy::select_for_encrypt(
            &[local],
            &[],
            &policy::LocalAuthenticators::none(),
        );
        assert!(without.recipients.is_empty());
        assert_eq!(
            without.skipped.first().map(|s| s.reason),
            Some(policy::SkipReason::NoLocalAuthenticator),
        );
    }

    /// The local copy of a key and its registry publication used to be wrapped
    /// twice because the local list keyed on a random id.
    #[test]
    fn local_entry_id_matches_the_registry_publication_id() {
        let piv = entry_for(Recipient::YubiKeyPiv {
            public_key: [5u8; 32],
            serial: 4242,
            slot: 0x95,
        });
        assert_eq!(
            local_entry_as_wire(&piv).id,
            piv_wire_entry(&[5u8; 32], 4242, 0x95, "x").id,
        );

        let sw = entry_for(Recipient::SoftwarePassphrase {
            armored_pubkey: ragewarden_core::ArmoredAgeRecipient::from_trusted("age1abc".into()),
        });
        assert_eq!(
            local_entry_as_wire(&sw).id,
            software_wire_entry("age1abc", "x").id,
        );
    }

    #[test]
    fn stable_ids_are_deterministic_and_kind_specific() {
        let s1 = stable_software_recipient_id("age1abc");
        let s2 = stable_software_recipient_id("age1abc");
        assert_eq!(s1, s2);
        assert_ne!(s1, stable_software_recipient_id("age1def"));

        let p1 = stable_piv_recipient_id(0x12345678, 0x95);
        let p2 = stable_piv_recipient_id(0x12345678, 0x95);
        assert_eq!(p1, p2);
        assert_ne!(p1, stable_piv_recipient_id(0x12345678, 0x82));

        let f1 = stable_fido2_recipient_id("ragewarden", b"cred-1");
        let f2 = stable_fido2_recipient_id("ragewarden", b"cred-1");
        assert_eq!(f1, f2);
        assert_ne!(f1, stable_fido2_recipient_id("ragewarden", b"cred-2"));

        assert_ne!(
            stable_software_recipient_id("age1abc"),
            stable_recovery_recipient_id("age1abc"),
        );
    }

    #[test]
    fn wire_entries_have_correct_kinds_and_payloads() {
        use ragewarden_core::registry::kinds;

        let sw = software_wire_entry("age1xx", "Terminal");
        assert_eq!(sw.kind, kinds::SOFTWARE);
        assert_eq!(sw.recovery_armored_pubkey.as_deref(), Some("age1xx"));

        let piv = piv_wire_entry(&[7u8; 32], 0xdead_beef, 0x95, "yk-95");
        assert_eq!(piv.kind, kinds::YUBIKEY);
        assert_eq!(piv.piv_serial, Some(0xdead_beef_u32 as i32));
        assert_eq!(piv.piv_slot, Some(0x95));
        assert_eq!(piv.piv_pubkey.as_deref(), Some(hex::encode([7u8; 32]).as_str()));

        let fido = fido2_wire_entry(b"cred", &[1u8; 32], "ragewarden", "fido");
        assert_eq!(fido.kind, kinds::FIDO2);
        assert_eq!(fido.fido2_credential_id.as_deref(), Some(hex::encode(b"cred").as_str()));
        assert_eq!(fido.fido2_rp_id.as_deref(), Some("ragewarden"));

        let rec = recovery_wire_entry("age1rec", "paper");
        assert_eq!(rec.kind, kinds::RECOVERY);
        assert_eq!(rec.recovery_armored_pubkey.as_deref(), Some("age1rec"));
    }

    #[test]
    fn registry_id_for_enrolled_identity_matches_publish_path() {
        use crate::identities::IdentityKind;

        let piv_kind = IdentityKind::YubiKeyPiv {
            public_key_hex: hex::encode([3u8; 32]),
            serial: 1234,
            slot: 0x95,
            mock: false,
        };
        let publish_id = piv_wire_entry(&[3u8; 32], 1234, 0x95, "x").id;
        assert_eq!(
            registry_id_for_enrolled_identity(&piv_kind),
            Some(publish_id),
        );

        use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
        let fido_kind = IdentityKind::Fido2HmacSecret {
            credential_id_b64: B64URL.encode(b"abc"),
            salt_hex: hex::encode([0u8; 32]),
            rp_id: "ragewarden".into(),
            mock: false,
        };
        let publish_id = fido2_wire_entry(b"abc", &[0u8; 32], "ragewarden", "x").id;
        assert_eq!(
            registry_id_for_enrolled_identity(&fido_kind),
            Some(publish_id),
        );

        let kr_kind = IdentityKind::OsKeyring {
            public_key_hex: hex::encode([0u8; 32]),
            armored_pubkey: ragewarden_core::ArmoredAgeRecipient::from_trusted("age1k".into()),
            keyring_service: "s".into(),
            keyring_user: "u".into(),
        };
        assert_eq!(
            registry_id_for_enrolled_identity(&kr_kind),
            Some(software_wire_entry("age1k", "x").id),
        );

        let rec_kind = IdentityKind::PaperRecovery {
            armored_pubkey: ragewarden_core::ArmoredAgeRecipient::from_trusted("age1r".into()),
        };
        assert_eq!(
            registry_id_for_enrolled_identity(&rec_kind),
            Some(recovery_wire_entry("age1r", "x").id),
        );
    }

    /// Machine B. The recipient list lives in the vault, so it also carries the
    /// FIDO2 key machine A enrolled; `identities.json` does not. Claiming A's
    /// key as locally tappable is what made every `set`/`rotate` from a second
    /// terminal die at PRF derivation with no policy skip to explain it.
    #[test]
    fn local_authenticators_come_from_this_machines_enrollments_only() {
        use crate::identities::{EnrolledIdentity, Identities, IdentityKind};
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};

        let _env = crate::tests_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::TempDir::new().expect("tempdir");
        let prev = std::env::var_os("RAGEWARDEN_CONFIG_DIR");
        std::env::set_var("RAGEWARDEN_CONFIG_DIR", dir.path());

        let mut ids = Identities::default();
        ids.insert(EnrolledIdentity {
            id: "ours".into(),
            kind: IdentityKind::Fido2HmacSecret {
                credential_id_b64: B64URL.encode(b"ours"),
                salt_hex: hex::encode([1u8; 32]),
                rp_id: "ragewarden".into(),
                mock: false,
            },
            label: "our key".into(),
            created: Utc::now(),
            last_used: None,
        });
        // A PIV key is asymmetric: every client can wrap to it, so it must not
        // show up in the PRF set even though it is enrolled here.
        ids.insert(EnrolledIdentity {
            id: "piv".into(),
            kind: IdentityKind::YubiKeyPiv {
                public_key_hex: hex::encode([8u8; 32]),
                serial: 11,
                slot: 0x95,
                mock: false,
            },
            label: "card".into(),
            created: Utc::now(),
            last_used: None,
        });
        let saved = ids.save();
        let auth = local_prf_authenticators();

        match prev {
            Some(p) => std::env::set_var("RAGEWARDEN_CONFIG_DIR", p),
            None => std::env::remove_var("RAGEWARDEN_CONFIG_DIR"),
        }

        saved.expect("save identities");
        let auth = auth.expect("local authenticators");
        assert_eq!(
            auth.prf_entry_ids,
            vec![stable_fido2_recipient_id("ragewarden", b"ours")],
        );

        let ours = local_entry_as_wire(&entry_for(Recipient::Fido2HmacSecret {
            credential_id: b"ours".to_vec(),
            salt: [1u8; 32],
            rp_id: "ragewarden".into(),
        }));
        let theirs = local_entry_as_wire(&entry_for(Recipient::Fido2HmacSecret {
            credential_id: b"theirs".to_vec(),
            salt: [2u8; 32],
            rp_id: "ragewarden".into(),
        }));
        let sel = policy::select_for_encrypt(&[], &[ours, theirs.clone()], &auth);
        assert_eq!(sel.recipients.len(), 1, "{sel:?}");
        assert_eq!(
            sel.skipped
                .iter()
                .map(|s| (s.id.as_str(), s.reason))
                .collect::<Vec<_>>(),
            vec![(theirs.id.as_str(), policy::SkipReason::NoLocalAuthenticator)],
        );

        let notes = describe_skips(&sel.skipped, &[], &[theirs]);
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0].describe().contains("not attached to this machine"),
            "{}",
            notes[0].describe(),
        );
    }

    #[test]
    fn round_trip_serialize_recipient_list() {
        let mut list = RecipientList::default();
        list.entries.insert(
            "abc".into(),
            RecipientEntry {
                id: "abc".into(),
                label: "test".into(),
                created: Utc::now(),
                last_used: None,
                recipient: Recipient::SoftwarePassphrase {
                    armored_pubkey: ragewarden_core::ArmoredAgeRecipient::from_trusted(
                        "age1xx".into(),
                    ),
                },
            },
        );
        let serialized = serde_json::to_string(&list).unwrap();
        let parsed: RecipientList = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed.entries.len(), 1);
    }
}
