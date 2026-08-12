//! Client-side per-cipher revision history, kept in one age-encrypted
//! side-channel cipher because Vaultwarden exposes no history endpoint.
//! See `docs/ragewarden/core.md`.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::sync::{
    self, build_rage_cipher, cipher_name, create_cipher, extract_rage_blob, update_cipher, Cipher,
    CipherIn, CipherOut, HttpClient, Server, Session, SyncError, Vault,
};
use crate::{decrypt, encrypt_with_prf, AgeBlob, DecryptError, EncryptError, Identity, PrfTable, Recipient};

pub const MARKER_NAME: &str = "__ragewarden_history_v1__";

/// Bump on a non-back-compatible payload change.
pub const SCHEMA_VERSION: u32 = 1;

/// Retained per cipher_id; older entries drop silently on append.
pub const MAX_ENTRIES_PER_CIPHER: usize = 10;

/// `prior_payload_armored` is the payload as it existed *before* the update
/// that triggered this entry. `recipients_summary` is display-only, never
/// cryptographically authoritative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    #[serde(rename = "recordedAt")]
    pub recorded_at: i64,

    #[serde(rename = "cipherId")]
    pub cipher_id: String,

    #[serde(rename = "priorPayloadArmored")]
    pub prior_payload_armored: String,

    #[serde(rename = "recipientsSummary", default)]
    pub recipients_summary: Vec<String>,
}

/// `entries` maps `cipher_id -> revision list`, stored oldest-first;
/// [`load_history`] reverses it for callers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryDoc {
    #[serde(default = "default_schema")]
    pub schema: u32,

    #[serde(default)]
    pub entries: BTreeMap<String, Vec<HistoryEntry>>,
}

fn default_schema() -> u32 {
    SCHEMA_VERSION
}

impl Default for HistoryDoc {
    fn default() -> Self {
        Self {
            schema: SCHEMA_VERSION,
            entries: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("sync: {0}")]
    Sync(#[from] SyncError),

    #[error("encrypt: {0}")]
    Encrypt(#[from] EncryptError),

    #[error("decrypt: {0}")]
    Decrypt(#[from] DecryptError),

    #[error("parse: {0}")]
    Parse(String),

    #[error("history cipher missing rage:v1 payload")]
    MissingPayload,
}

pub fn find_history_cipher<'a>(session: &Session, vault: &'a Vault) -> Option<&'a Cipher> {
    vault.ciphers.iter().find(|c| {
        cipher_name(session, c)
            .map(|n| n == MARKER_NAME)
            .unwrap_or(false)
    })
}

/// `None` until the marker cipher has been saved once; callers use it to
/// choose POST vs PUT.
pub fn history_cipher_id<'a>(session: &Session, vault: &'a Vault) -> Option<&'a str> {
    find_history_cipher(session, vault).and_then(|c| c.id.as_deref())
}

/// Empty doc if the marker cipher does not exist yet. `identities` must
/// contain one capable of unwrapping the doc's age header.
pub fn extract_history(
    session: &Session,
    vault: &Vault,
    identities: &[Box<dyn Identity>],
) -> Result<HistoryDoc, HistoryError> {
    let Some(cipher) = find_history_cipher(session, vault) else {
        return Ok(HistoryDoc::default());
    };
    let Some(armored) = extract_rage_blob(session, cipher)? else {
        return Err(HistoryError::MissingPayload);
    };
    let blob = AgeBlob::from_bytes(armored.into_bytes());
    let plaintext = decrypt(&blob, identities)?;
    let doc: HistoryDoc = serde_json::from_slice(&plaintext)
        .map_err(|e| HistoryError::Parse(format!("history payload: {e}")))?;
    Ok(doc)
}

/// One cipher's revisions, newest first; empty when it has no history.
pub fn load_history(
    session: &Session,
    vault: &Vault,
    identities: &[Box<dyn Identity>],
    cipher_id: &str,
) -> Result<Vec<HistoryEntry>, HistoryError> {
    let doc = extract_history(session, vault, identities)?;
    let mut entries = doc.entries.get(cipher_id).cloned().unwrap_or_default();
    entries.sort_by(|a, b| b.recorded_at.cmp(&a.recorded_at));
    Ok(entries)
}

/// Pure in-place append with the per-cipher retention cap applied; for
/// callers staging many edits before persisting.
pub fn append_revision(doc: &mut HistoryDoc, entry: HistoryEntry) {
    let list = doc.entries.entry(entry.cipher_id.clone()).or_default();
    list.push(entry);
    if list.len() > MAX_ENTRIES_PER_CIPHER {
        let drop = list.len() - MAX_ENTRIES_PER_CIPHER;
        list.drain(0..drop);
    }
}

/// Age-encrypts `doc` and wraps it as a secure-note cipher with the marker
/// name. The returned [`CipherIn`] is POSTed or PUT by the caller.
pub fn build_history_cipher_in(
    session: &Session,
    doc: &HistoryDoc,
    recipients: &[Recipient],
    prf_table: PrfTable<'_>,
) -> Result<CipherIn, HistoryError> {
    let json = serde_json::to_vec(doc)
        .map_err(|e| HistoryError::Parse(format!("serialize history: {e}")))?;
    let blob = encrypt_with_prf(&json, recipients, prf_table)?;
    let armored = String::from_utf8(blob.0)
        .map_err(|e| HistoryError::Parse(format!("age armor not utf8: {e}")))?;
    Ok(build_rage_cipher(session, MARKER_NAME, &armored)?)
}

/// Reads the current doc, appends `entry` with retention applied, and
/// POST/PUTs the marker cipher. `prf_table` supplies PRF outputs for any
/// FIDO2 / WebAuthn-PRF recipient; `identities` decrypts the *existing* doc
/// (skipped on first write). Callers wanting an updated `Vault` snapshot must
/// swap the returned cipher into `vault.ciphers` themselves.
#[allow(clippy::too_many_arguments)]
pub async fn record_revision(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    vault: &Vault,
    recipients: &[Recipient],
    prf_table: PrfTable<'_>,
    identities: &[Box<dyn Identity>],
    entry: HistoryEntry,
) -> Result<CipherOut, HistoryError> {
    let existing_id = history_cipher_id(session, vault).map(str::to_owned);
    let mut doc = if existing_id.is_some() {
        extract_history(session, vault, identities)?
    } else {
        HistoryDoc::default()
    };
    append_revision(&mut doc, entry);

    let cipher_in = build_history_cipher_in(session, &doc, recipients, prf_table)?;
    let saved = if let Some(id) = existing_id {
        update_cipher(client, server, session, &id, &cipher_in).await?
    } else {
        create_cipher(client, server, session, &cipher_in).await?
    };
    Ok(saved)
}

pub use sync::RAGE_FIELD_NAME;

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{SystemTime, UNIX_EPOCH};

    use age::secrecy::ExposeSecret;
    use age::x25519;

    use crate::software_passphrase_identity;
    use crate::sync::build_meta_cipher;
    use crate::{ArmoredAgeRecipient, ArmoredAgeSecret, Recipient};

    fn fake_session() -> Session {
        Session {
            access_token: crate::BearerToken::from_trusted("stub".into()),
            refresh_token: crate::RefreshToken::from_trusted("refresh".into()),
            user_id: "00000000-0000-0000-0000-000000000000".into(),
            email: "test@example.com".into(),
            user_enc_key: vec![0x11; 32].into(),
            user_mac_key: vec![0x22; 32].into(),
            kdf_iterations: 100,
            device_id: "test-device".into(),
        }
    }

    fn make_identity_pair() -> (Vec<Recipient>, Vec<Box<dyn Identity>>) {
        let id = x25519::Identity::generate();
        let armored_pub = ArmoredAgeRecipient::from_trusted(id.to_public().to_string());
        let armored_secret =
            ArmoredAgeSecret::from_trusted(id.to_string().expose_secret().to_string());
        let sw = software_passphrase_identity(&armored_secret).expect("sw identity");
        let ids: Vec<Box<dyn Identity>> = vec![Box::new(sw)];
        let recipients = vec![Recipient::SoftwarePassphrase {
            armored_pubkey: armored_pub,
        }];
        (recipients, ids)
    }

    fn entry(cipher_id: &str, ts: i64) -> HistoryEntry {
        HistoryEntry {
            recorded_at: ts,
            cipher_id: cipher_id.to_string(),
            prior_payload_armored: format!(
                "-----BEGIN AGE ENCRYPTED FILE-----\nfake-{ts}\n-----END AGE ENCRYPTED FILE-----\n"
            ),
            recipients_summary: vec!["StrongBox: this phone".into()],
        }
    }

    #[test]
    fn extract_history_on_empty_vault_returns_default() {
        let session = fake_session();
        let vault = Vault::default();
        let (_, ids) = make_identity_pair();
        let doc = extract_history(&session, &vault, &ids).expect("extract");
        assert_eq!(doc.schema, SCHEMA_VERSION);
        assert!(doc.entries.is_empty());
    }

    #[test]
    fn append_then_load_returns_newest_first() {
        let mut doc = HistoryDoc::default();
        append_revision(&mut doc, entry("cipher-A", 100));
        append_revision(&mut doc, entry("cipher-A", 200));
        append_revision(&mut doc, entry("cipher-A", 150));
        let mut got = doc.entries["cipher-A"].clone();
        got.sort_by(|a, b| b.recorded_at.cmp(&a.recorded_at));
        let times: Vec<i64> = got.iter().map(|e| e.recorded_at).collect();
        assert_eq!(times, vec![200, 150, 100]);
    }

    #[test]
    fn retention_cap_drops_oldest_entries_per_cipher() {
        let mut doc = HistoryDoc::default();
        for i in 0..(MAX_ENTRIES_PER_CIPHER as i64 + 5) {
            append_revision(&mut doc, entry("cipher-A", i));
        }
        let list = &doc.entries["cipher-A"];
        assert_eq!(list.len(), MAX_ENTRIES_PER_CIPHER);
        assert_eq!(list.first().unwrap().recorded_at, 5);
        assert_eq!(
            list.last().unwrap().recorded_at,
            MAX_ENTRIES_PER_CIPHER as i64 + 4
        );
    }

    #[test]
    fn retention_cap_is_per_cipher_id_not_global() {
        let mut doc = HistoryDoc::default();
        for i in 0..MAX_ENTRIES_PER_CIPHER as i64 {
            append_revision(&mut doc, entry("cipher-A", i));
        }
        for i in 0..3 {
            append_revision(&mut doc, entry("cipher-B", i));
        }
        assert_eq!(doc.entries["cipher-A"].len(), MAX_ENTRIES_PER_CIPHER);
        assert_eq!(doc.entries["cipher-B"].len(), 3);
    }

    #[test]
    fn build_then_extract_round_trips_through_encrypted_cipher() {
        let session = fake_session();
        let (recipients, ids) = make_identity_pair();

        let mut doc = HistoryDoc::default();
        append_revision(&mut doc, entry("cipher-A", 1_000));
        append_revision(&mut doc, entry("cipher-A", 2_000));
        append_revision(&mut doc, entry("cipher-B", 3_000));

        let cipher_in =
            build_history_cipher_in(&session, &doc, &recipients, &[]).expect("build");
        let mut as_cipher: Cipher =
            serde_json::from_slice(&serde_json::to_vec(&cipher_in).expect("serialize"))
                .expect("CipherIn -> Cipher round-trip");
        as_cipher.id = Some("server-uuid".into());
        let vault = Vault {
            ciphers: vec![as_cipher],
            ..Vault::default()
        };

        let extracted = extract_history(&session, &vault, &ids).expect("extract");
        assert_eq!(extracted, doc);

        let a_entries = load_history(&session, &vault, &ids, "cipher-A").expect("load A");
        let times: Vec<i64> = a_entries.iter().map(|e| e.recorded_at).collect();
        assert_eq!(times, vec![2_000, 1_000]);

        let b_entries = load_history(&session, &vault, &ids, "cipher-B").expect("load B");
        assert_eq!(b_entries.len(), 1);
        assert_eq!(b_entries[0].recorded_at, 3_000);

        let none = load_history(&session, &vault, &ids, "no-such-cipher").expect("load none");
        assert!(none.is_empty());
    }

    #[test]
    fn find_history_cipher_matches_by_decrypted_name() {
        let session = fake_session();
        let other = build_meta_cipher(&session, "some-other-cipher", "{}").unwrap();
        let other_cipher: Cipher =
            serde_json::from_slice(&serde_json::to_vec(&other).unwrap()).unwrap();

        let history_in = build_meta_cipher(&session, MARKER_NAME, "doesnt-matter").unwrap();
        let mut history_cipher: Cipher =
            serde_json::from_slice(&serde_json::to_vec(&history_in).unwrap()).unwrap();
        history_cipher.id = Some("history-id".into());

        let vault = Vault {
            ciphers: vec![other_cipher, history_cipher],
            ..Vault::default()
        };
        let found = find_history_cipher(&session, &vault).expect("found");
        assert_eq!(found.id.as_deref(), Some("history-id"));
        assert_eq!(history_cipher_id(&session, &vault), Some("history-id"));
    }

    #[test]
    fn missing_rage_field_is_an_error() {
        let session = fake_session();
        let cipher_in = build_meta_cipher(&session, MARKER_NAME, "{}").unwrap();
        let mut as_cipher: Cipher =
            serde_json::from_slice(&serde_json::to_vec(&cipher_in).unwrap()).unwrap();
        as_cipher.id = Some("history-id".into());
        let vault = Vault {
            ciphers: vec![as_cipher],
            ..Vault::default()
        };
        let (_, ids) = make_identity_pair();
        let err = extract_history(&session, &vault, &ids).unwrap_err();
        assert!(matches!(err, HistoryError::MissingPayload));
    }

    #[test]
    fn extract_with_wrong_identity_yields_decrypt_error() {
        let session = fake_session();
        let (recipients, _) = make_identity_pair();

        let mut doc = HistoryDoc::default();
        append_revision(&mut doc, entry("cipher-A", 42));
        let cipher_in =
            build_history_cipher_in(&session, &doc, &recipients, &[]).expect("build");
        let mut as_cipher: Cipher =
            serde_json::from_slice(&serde_json::to_vec(&cipher_in).unwrap()).unwrap();
        as_cipher.id = Some("history-id".into());
        let vault = Vault {
            ciphers: vec![as_cipher],
            ..Vault::default()
        };

        let (_, wrong_ids) = make_identity_pair();
        let err = extract_history(&session, &vault, &wrong_ids).unwrap_err();
        assert!(matches!(err, HistoryError::Decrypt(_)));
    }

    #[test]
    fn built_cipher_has_marker_name_and_armored_payload() {
        let session = fake_session();
        let (recipients, _) = make_identity_pair();
        let doc = HistoryDoc::default();
        let cipher_in =
            build_history_cipher_in(&session, &doc, &recipients, &[]).expect("build");

        let as_cipher: Cipher =
            serde_json::from_slice(&serde_json::to_vec(&cipher_in).unwrap()).unwrap();
        let name = cipher_name(&session, &as_cipher).unwrap();
        assert_eq!(name, MARKER_NAME);

        let payload = extract_rage_blob(&session, &as_cipher).unwrap().unwrap();
        assert!(payload.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
    }

    #[test]
    fn first_write_with_now_timestamp_is_loadable() {
        let session = fake_session();
        let (recipients, ids) = make_identity_pair();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let mut doc = HistoryDoc::default();
        append_revision(
            &mut doc,
            HistoryEntry {
                recorded_at: now,
                cipher_id: "live".into(),
                prior_payload_armored: "armor".into(),
                recipients_summary: vec![],
            },
        );
        let cipher_in =
            build_history_cipher_in(&session, &doc, &recipients, &[]).expect("build");
        let mut as_cipher: Cipher =
            serde_json::from_slice(&serde_json::to_vec(&cipher_in).unwrap()).unwrap();
        as_cipher.id = Some("history-id".into());
        let vault = Vault {
            ciphers: vec![as_cipher],
            ..Vault::default()
        };
        let entries = load_history(&session, &vault, &ids, "live").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].recorded_at, now);
    }

    #[test]
    fn serialized_doc_uses_camelcase_keys() {
        let mut doc = HistoryDoc::default();
        append_revision(&mut doc, entry("cipher-A", 7));
        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"cipherId\":\"cipher-A\""), "got: {json}");
        assert!(json.contains("\"recordedAt\":7"), "got: {json}");
        assert!(
            json.contains("\"priorPayloadArmored\""),
            "got: {json}"
        );
        assert!(json.contains("\"recipientsSummary\""), "got: {json}");
    }

    #[test]
    fn marker_lookup_works_among_other_ciphers() {
        let session = fake_session();
        let blob = build_meta_cipher(&session, "noise", "{}").unwrap();
        let mut blob_cipher: Cipher =
            serde_json::from_slice(&serde_json::to_vec(&blob).unwrap()).unwrap();
        blob_cipher.id = Some("noise-id".into());

        let history_in = build_meta_cipher(&session, MARKER_NAME, "{}").unwrap();
        let mut history_cipher: Cipher =
            serde_json::from_slice(&serde_json::to_vec(&history_in).unwrap()).unwrap();
        history_cipher.id = Some("h-id".into());

        let vault = Vault {
            ciphers: vec![blob_cipher, history_cipher],
            ..Vault::default()
        };
        assert_eq!(history_cipher_id(&session, &vault), Some("h-id"));
    }

    #[test]
    fn empty_doc_round_trips() {
        let session = fake_session();
        let (recipients, ids) = make_identity_pair();
        let doc = HistoryDoc::default();
        let cipher_in =
            build_history_cipher_in(&session, &doc, &recipients, &[]).expect("build");
        let mut as_cipher: Cipher =
            serde_json::from_slice(&serde_json::to_vec(&cipher_in).unwrap()).unwrap();
        as_cipher.id = Some("history-id".into());
        let vault = Vault {
            ciphers: vec![as_cipher],
            ..Vault::default()
        };
        let extracted = extract_history(&session, &vault, &ids).unwrap();
        assert_eq!(extracted, doc);
    }

}
