use std::time::{SystemTime, UNIX_EPOCH};

use chrono::Utc;
use ragewarden_core::Recipient;
use ragewarden_core::history::{HistoryEntry, record_revision};
use ragewarden_core::sync::{self, Cipher, Vault};

use crate::http::ReqwestClient;
use crate::recipients;
use crate::session;
use crate::vault as vault_cache;

/// `recipients_vec` is the caller's already-loaded encrypt set. It is passed in
/// rather than loaded here because the caller needs the very same set for its
/// own write: loading it twice meant a second vault round trip, and a second
/// copy of the coverage warning printed directly under the first.
/// The history document is under the user key (core::history v2), so nothing
/// is wrapped here and no tap is needed; `recipients_vec` only labels the entry.
pub async fn record_prior_revision(cipher: &Cipher, recipients_vec: &[Recipient]) {
    if let Err(e) = try_record(cipher, recipients_vec, false).await {
        eprintln!("rageterm: failed to record cipher history ({e}); continuing");
    }
}

/// The item's last value goes into the history document before the cipher is
/// deleted, so a delete is recoverable from `history` like an update.
pub async fn record_deletion(cipher: &Cipher) -> Result<(), String> {
    try_record(cipher, &[], true).await
}

async fn try_record(
    cipher: &Cipher,
    recipients_vec: &[Recipient],
    deleted: bool,
) -> Result<(), String> {
    let open = match session::load().map_err(|e| e.to_string())? {
        Some(o) => o,
        None => return Ok(()),
    };

    let cipher_id = match cipher.id.as_deref() {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return Ok(()),
    };

    let prior_armored =
        match sync::extract_rage_blob(&open.session, cipher).map_err(|e| e.to_string())? {
            Some(s) => s,
            None => return Ok(()),
        };

    if recipients_vec.is_empty() && !deleted {
        return Ok(());
    }

    let summary = recipient_summary_labels(Some(&open.session), recipients_vec).await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_else(|_| Utc::now().timestamp_millis());
    let entry = if deleted {
        HistoryEntry::deletion(cipher_id, prior_armored, summary, now)
    } else {
        HistoryEntry::revision(cipher_id, prior_armored, summary, now)
    };

    let identities = crate::commands::build_identity_list().map_err(|e| e.to_string())?;

    let vault: Vault = vault_cache::load()
        .map_err(|e| e.to_string())?
        .unwrap_or_default();

    let client = ReqwestClient::new().map_err(|e| format!("http client: {e}"))?;

    let saved = record_revision(
        &client,
        &open.server,
        &open.session,
        &vault,
        Some(&identities),
        entry,
    )
    .await
    .map_err(|e| e.to_string())?;

    let mut updated = vault;
    updated.upsert_cipher(saved);
    vault_cache::save(&updated).map_err(|e| e.to_string())?;

    Ok(())
}

/// Human names for a recipient set, best effort: the local list first, then the
/// cross-device registry, then the bare kind.
///
/// `session` is optional because the caller may have none -- the registry lives
/// in the vault, so without a session there is simply one fewer place to look.
pub async fn recipient_summary_labels(
    session: Option<&ragewarden_core::sync::Session>,
    recipients_vec: &[Recipient],
) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(recipients_vec.len());

    let registry_entries: Vec<(Recipient, String)> = match (session, vault_cache::load()) {
        (Some(session), Ok(Some(vault))) => {
            match ragewarden_core::registry::extract_document(session, &vault) {
                Ok(Some(doc)) => doc
                    .entries
                    .into_iter()
                    .filter_map(|e| {
                        let display = e.display_name.clone();
                        e.to_recipient_if_active().map(|r| (r, display))
                    })
                    .collect(),
                _ => Vec::new(),
            }
        }
        _ => Vec::new(),
    };

    let local = recipients::load().await.unwrap_or_default();

    for r in recipients_vec {
        let label = local
            .iter_chronological()
            .find(|e| recipients_match(&e.recipient, r))
            .map(|e| e.label.clone())
            .or_else(|| {
                registry_entries
                    .iter()
                    .find(|(rr, _)| recipients_match(rr, r))
                    .map(|(_, label)| label.clone())
            })
            .unwrap_or_else(|| recipient_kind_label(r).to_string());
        out.push(label);
    }
    out
}

fn recipients_match(a: &Recipient, b: &Recipient) -> bool {
    use Recipient::*;
    match (a, b) {
        (X25519 { public_key: x }, X25519 { public_key: y }) => x == y,
        (YubiKeyPiv { public_key: x, .. }, YubiKeyPiv { public_key: y, .. }) => x == y,
        (YubiKeyPivP256 { public_key: x, .. }, YubiKeyPivP256 { public_key: y, .. }) => x == y,
        (
            Fido2HmacSecret {
                credential_id: x, ..
            },
            Fido2HmacSecret {
                credential_id: y, ..
            },
        ) => x == y,
        (
            PasskeyPrf {
                credential_id: x, ..
            },
            PasskeyPrf {
                credential_id: y, ..
            },
        ) => x == y,
        (AndroidKeystore { public_key: x, .. }, AndroidKeystore { public_key: y, .. }) => x == y,
        (SoftwarePassphrase { armored_pubkey: x }, SoftwarePassphrase { armored_pubkey: y }) => {
            x.as_str() == y.as_str()
        }
        _ => false,
    }
}

fn recipient_kind_label(r: &Recipient) -> &'static str {
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
