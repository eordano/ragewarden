//! Client-side per-cipher revision history, one document for every client.
//!
//! Vaultwarden exposes no history endpoint, so the history lives in one
//! secure-note cipher named [`MARKER_NAME`], as JSON in its [`DOC_FIELD_NAME`]
//! custom field, under the account's user key like any other vault metadata.
//! The secrets in it are each revision's prior rage payload, which is itself
//! an age blob for that item's hardware recipients: recording or listing
//! history needs no tap, and reading an old secret needs the same tap reading
//! the item did.
//!
//! Two older formats are read and folded in on the next write, then deleted:
//! the age-encrypted document rageterm wrote under [`LEGACY_MARKER_NAME`]
//! (only when the caller passes identities that can open it) and the browser's
//! per-item documents named `LEGACY_MARKER_NAME:<cipherId>`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::sync::{
    self, CIPHER_TYPE_SECURE_NOTE, Cipher, CipherFieldIn, CipherIn, CipherOut, HttpClient,
    SecureNote, Server, Session, SyncError, Vault, cipher_name, create_cipher, decrypt_string,
    delete_cipher, encrypt_string, extract_rage_blob, update_cipher,
};
use crate::{AgeBlob, DecryptError, Identity, decrypt, parse_header_stanzas};

pub const MARKER_NAME: &str = "__ragewarden_history_v2__";

pub const DOC_FIELD_NAME: &str = "history:v2";

pub const LEGACY_MARKER_NAME: &str = "__ragewarden_history_v1__";

pub const SCHEMA_VERSION: u32 = 2;

/// Retained per cipher_id; older entries drop on append.
pub const MAX_ENTRIES_PER_CIPHER: usize = 10;

/// `prior_payload_armored` is the item's rage payload as it was before the
/// update or deletion this entry records. `recipients_summary` is the
/// writer's display labels; `stanza_tags` is read from the payload itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    #[serde(rename = "recordedAt")]
    pub recorded_at: i64,

    #[serde(rename = "cipherId")]
    pub cipher_id: String,

    #[serde(rename = "priorPayloadArmored", alias = "priorPayload")]
    pub prior_payload_armored: String,

    #[serde(rename = "recipientsSummary", default)]
    pub recipients_summary: Vec<String>,

    #[serde(rename = "stanzaTags", default, skip_serializing_if = "Vec::is_empty")]
    pub stanza_tags: Vec<String>,

    /// The item itself was deleted; `prior_payload_armored` is its last value.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deleted: bool,
}

impl HistoryEntry {
    pub fn revision(
        cipher_id: impl Into<String>,
        prior_payload_armored: impl Into<String>,
        recipients_summary: Vec<String>,
        recorded_at_ms: i64,
    ) -> Self {
        let prior_payload_armored = prior_payload_armored.into();
        Self {
            recorded_at: recorded_at_ms,
            cipher_id: cipher_id.into(),
            stanza_tags: stanza_tags(&prior_payload_armored),
            prior_payload_armored,
            recipients_summary,
            deleted: false,
        }
    }

    pub fn deletion(
        cipher_id: impl Into<String>,
        last_payload_armored: impl Into<String>,
        recipients_summary: Vec<String>,
        recorded_at_ms: i64,
    ) -> Self {
        Self {
            deleted: true,
            ..Self::revision(
                cipher_id,
                last_payload_armored,
                recipients_summary,
                recorded_at_ms,
            )
        }
    }

    fn key(&self) -> (i64, &str, &str) {
        (
            self.recorded_at,
            self.cipher_id.as_str(),
            self.prior_payload_armored.as_str(),
        )
    }
}

/// The stanza types a payload is wrapped to, in header order, without
/// unwrapping anything (age's random `*-grease` stanzas are left out); empty
/// when the payload does not parse.
pub fn stanza_tags(armored: &str) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();
    if let Ok(stanzas) = parse_header_stanzas(&AgeBlob::from_bytes(armored.as_bytes().to_vec())) {
        for s in stanzas {
            if !s.tag.ends_with("-grease") && !tags.contains(&s.tag) {
                tags.push(s.tag);
            }
        }
    }
    tags
}

/// `entries` maps `cipher_id -> revision list`, stored oldest-first;
/// [`load_history`] returns them newest-first.
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

impl HistoryDoc {
    fn contains(&self, entry: &HistoryEntry) -> bool {
        self.entries
            .get(&entry.cipher_id)
            .is_some_and(|l| l.iter().any(|e| e.key() == entry.key()))
    }

    fn merge(&mut self, entries: impl IntoIterator<Item = HistoryEntry>) {
        for e in entries {
            if !self.contains(&e) {
                append_revision(self, e);
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("sync: {0}")]
    Sync(#[from] SyncError),

    #[error("decrypt: {0}")]
    Decrypt(#[from] DecryptError),

    #[error("parse: {0}")]
    Parse(String),

    #[error("history cipher missing its {DOC_FIELD_NAME} field")]
    MissingPayload,

    #[error("the history write did not read back with every migrated entry; legacy documents kept")]
    MigrationNotConfirmed,
}

/// Append with the per-cipher retention cap applied, keeping the list sorted
/// oldest-first.
pub fn append_revision(doc: &mut HistoryDoc, mut entry: HistoryEntry) {
    if entry.stanza_tags.is_empty() {
        entry.stanza_tags = stanza_tags(&entry.prior_payload_armored);
    }
    let list = doc.entries.entry(entry.cipher_id.clone()).or_default();
    list.push(entry);
    list.sort_by_key(|e| e.recorded_at);
    if list.len() > MAX_ENTRIES_PER_CIPHER {
        let drop = list.len() - MAX_ENTRIES_PER_CIPHER;
        list.drain(0..drop);
    }
}

/// The history as stored now, plus where each part came from.
#[derive(Debug, Default)]
pub struct HistoryState {
    pub doc: HistoryDoc,
    marker_id: Option<String>,
    legacy_ids: Vec<String>,
}

fn named<'a>(
    session: &Session,
    vault: &'a Vault,
    wanted: impl Fn(&str) -> bool,
) -> Vec<&'a Cipher> {
    vault
        .ciphers
        .iter()
        .filter(|c| c.organization_id.is_none())
        .filter(|c| cipher_name(session, c).is_ok_and(|n| wanted(&n)))
        .collect()
}

fn doc_from_cipher(session: &Session, cipher: &Cipher) -> Result<HistoryDoc, HistoryError> {
    for f in cipher.fields.iter().flatten() {
        if decrypt_string(session, &f.name)? == DOC_FIELD_NAME {
            let json = f
                .value
                .as_ref()
                .map(|v| decrypt_string(session, v))
                .transpose()?
                .ok_or(HistoryError::MissingPayload)?;
            return serde_json::from_str(&json)
                .map_err(|e| HistoryError::Parse(format!("history payload: {e}")));
        }
    }
    Err(HistoryError::MissingPayload)
}

/// Reads the history and every legacy document that can be read: browser
/// per-item documents always, rageterm's age-encrypted one only when
/// `legacy_identities` opens it.
pub fn read_history(
    session: &Session,
    vault: &Vault,
    legacy_identities: Option<&[Box<dyn Identity>]>,
) -> Result<HistoryState, HistoryError> {
    let mut state = HistoryState::default();
    if let Some(marker) = named(session, vault, |n| n == MARKER_NAME)
        .into_iter()
        .next()
    {
        state.doc = doc_from_cipher(session, marker)?;
        state.marker_id = marker.id.clone();
    }

    let per_item_prefix = format!("{LEGACY_MARKER_NAME}:");
    for c in named(session, vault, |n| n.starts_with(&per_item_prefix)) {
        let Some(notes) = &c.notes else { continue };
        let entries: Vec<HistoryEntry> = serde_json::from_str(&decrypt_string(session, notes)?)
            .map_err(|e| HistoryError::Parse(format!("browser history: {e}")))?;
        state.doc.merge(entries);
        state.legacy_ids.extend(c.id.clone());
    }

    if let Some(identities) = legacy_identities {
        for c in named(session, vault, |n| n == LEGACY_MARKER_NAME) {
            let Some(armored) = extract_rage_blob(session, c)? else {
                continue;
            };
            let Ok(plaintext) = decrypt(&AgeBlob::from_bytes(armored.into_bytes()), identities)
            else {
                continue;
            };
            let old: HistoryDoc = serde_json::from_slice(&plaintext)
                .map_err(|e| HistoryError::Parse(format!("legacy history: {e}")))?;
            state.doc.merge(old.entries.into_values().flatten());
            state.legacy_ids.extend(c.id.clone());
        }
    }
    Ok(state)
}

/// One cipher's revisions, newest first; empty when it has none.
pub fn load_history(
    session: &Session,
    vault: &Vault,
    cipher_id: &str,
) -> Result<Vec<HistoryEntry>, HistoryError> {
    let mut entries = read_history(session, vault, None)?
        .doc
        .entries
        .remove(cipher_id)
        .unwrap_or_default();
    entries.reverse();
    Ok(entries)
}

fn build_history_cipher_in(session: &Session, doc: &HistoryDoc) -> Result<CipherIn, HistoryError> {
    let json =
        serde_json::to_string(doc).map_err(|e| HistoryError::Parse(format!("serialize: {e}")))?;
    Ok(CipherIn {
        cipher_type: CIPHER_TYPE_SECURE_NOTE,
        name: encrypt_string(session, MARKER_NAME)?,
        secure_note: Some(SecureNote { note_type: 0 }),
        fields: Some(vec![CipherFieldIn {
            name: encrypt_string(session, DOC_FIELD_NAME)?,
            value: Some(encrypt_string(session, &json)?),
            field_type: 1,
            ..CipherFieldIn::default()
        }]),
        ..CipherIn::default()
    })
}

/// Appends `entry` to the history and saves it, folding in any legacy
/// documents [`read_history`] could read. A legacy document is deleted only
/// after the saved history has been read back with all of its entries.
/// Callers wanting an updated `Vault` snapshot swap the returned cipher in and
/// drop the deleted legacy ones themselves (or re-sync).
pub async fn record_revision(
    client: &dyn HttpClient,
    server: &Server,
    session: &Session,
    vault: &Vault,
    legacy_identities: Option<&[Box<dyn Identity>]>,
    entry: HistoryEntry,
) -> Result<CipherOut, HistoryError> {
    let mut state = read_history(session, vault, legacy_identities)?;
    append_revision(&mut state.doc, entry);
    let cipher_in = build_history_cipher_in(session, &state.doc)?;
    let saved = match &state.marker_id {
        Some(id) => update_cipher(client, server, session, id, &cipher_in).await?,
        None => create_cipher(client, server, session, &cipher_in).await?,
    };
    if !state.legacy_ids.is_empty() {
        let stored = doc_from_cipher(session, &saved)?;
        let kept_all = state
            .doc
            .entries
            .values()
            .flatten()
            .all(|e| stored.contains(e));
        if !kept_all {
            return Err(HistoryError::MigrationNotConfirmed);
        }
        for id in &state.legacy_ids {
            delete_cipher(client, server, session, id).await?;
        }
    }
    Ok(saved)
}

pub use sync::RAGE_FIELD_NAME;

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use age::secrecy::ExposeSecret;
    use age::x25519;
    use async_trait::async_trait;

    use crate::sync::{HttpBody, HttpError, HttpResponse, build_meta_cipher, build_rage_cipher};
    use crate::{
        ArmoredAgeRecipient, ArmoredAgeSecret, Recipient, encrypt, software_passphrase_identity,
    };

    fn fake_session() -> Session {
        Session {
            access_token: crate::BearerToken::from_trusted("stub".into()),
            refresh_token: crate::RefreshToken::from_trusted("refresh".into()),
            user_id: "00000000-0000-0000-0000-000000000000".into(),
            email: "test@example.com".into(),
            user_enc_key: vec![0x11; 32].into(),
            user_mac_key: vec![0x22; 32].into(),
            kdf: crate::sync::KdfParams::pbkdf2(100),
            device_id: "test-device".into(),
        }
    }

    fn identity_pair() -> (Vec<Recipient>, Vec<Box<dyn Identity>>) {
        let id = x25519::Identity::generate();
        let pubkey = ArmoredAgeRecipient::from_trusted(id.to_public().to_string());
        let secret = ArmoredAgeSecret::from_trusted(id.to_string().expose_secret().to_string());
        let sw = software_passphrase_identity(&secret).expect("sw identity");
        (
            vec![Recipient::SoftwarePassphrase {
                armored_pubkey: pubkey,
            }],
            vec![Box::new(sw)],
        )
    }

    fn sealed(recipients: &[Recipient], secret: &str) -> String {
        String::from_utf8(encrypt(secret.as_bytes(), recipients).unwrap().0).unwrap()
    }

    fn as_server(c: CipherIn, id: &str) -> Cipher {
        let mut v = serde_json::to_value(&c).unwrap();
        v["id"] = serde_json::json!(id);
        serde_json::from_value(v).unwrap()
    }

    #[derive(Default)]
    struct MockServer {
        writes: Mutex<Vec<(String, Vec<u8>)>>,
        deletes: Mutex<Vec<String>>,
        echo_drops_entries: bool,
    }

    #[async_trait]
    impl HttpClient for MockServer {
        async fn post(
            &self,
            url: &str,
            body: HttpBody,
            h: &[(String, String)],
        ) -> Result<HttpResponse, HttpError> {
            self.put(url, body, h).await
        }
        async fn put(
            &self,
            url: &str,
            body: HttpBody,
            _: &[(String, String)],
        ) -> Result<HttpResponse, HttpError> {
            let HttpBody::Json(b) = body else {
                panic!("json body")
            };
            self.writes
                .lock()
                .unwrap()
                .push((url.to_string(), b.clone()));
            let mut v: serde_json::Value = serde_json::from_slice(&b).unwrap();
            v["id"] = serde_json::json!("hist-2");
            if self.echo_drops_entries {
                let empty =
                    encrypt_string(&fake_session(), r#"{"schema":2,"entries":{}}"#).unwrap();
                v["fields"][0]["value"] = serde_json::json!(empty);
            }
            Ok(HttpResponse {
                status: 200,
                body: serde_json::to_vec(&v).unwrap(),
            })
        }
        async fn get(&self, url: &str, _: &[(String, String)]) -> Result<HttpResponse, HttpError> {
            Err(HttpError::Transport(url.into()))
        }
        async fn delete(
            &self,
            url: &str,
            _: &[(String, String)],
        ) -> Result<HttpResponse, HttpError> {
            self.deletes.lock().unwrap().push(url.to_string());
            Ok(HttpResponse {
                status: 200,
                body: Vec::new(),
            })
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
    fn an_empty_vault_has_no_history() {
        let s = fake_session();
        assert!(load_history(&s, &Vault::default(), "c").unwrap().is_empty());
    }

    #[test]
    fn retention_is_per_cipher_and_keeps_the_newest() {
        let mut doc = HistoryDoc::default();
        for ts in 0..15 {
            append_revision(
                &mut doc,
                HistoryEntry::revision("A", format!("p{ts}"), vec![], ts),
            );
        }
        append_revision(&mut doc, HistoryEntry::revision("B", "b", vec![], 1));
        assert_eq!(doc.entries["A"].len(), MAX_ENTRIES_PER_CIPHER);
        assert_eq!(doc.entries["A"][0].recorded_at, 5);
        assert_eq!(doc.entries["B"].len(), 1);
    }

    #[test]
    fn a_revision_records_the_stanza_types_of_its_payload() {
        let (recipients, _) = identity_pair();
        let e = HistoryEntry::revision("A", sealed(&recipients, "old"), vec!["laptop".into()], 1);
        assert_eq!(e.stanza_tags, vec!["X25519".to_string()]);
    }

    #[test]
    fn a_revision_lists_the_recipient_bound_piv_and_keystore_tags() {
        let blob = crate::encrypt(
            b"x",
            &[crate::Recipient::YubiKeyPiv {
                public_key: [9u8; 32],
                serial: 1,
                slot: 0x9a,
                stanza_version: 2,
            }],
        )
        .unwrap();
        let armored = String::from_utf8(blob.0).unwrap();
        assert_eq!(stanza_tags(&armored), vec!["piv-x25519-v2".to_string()]);
    }

    #[test]
    fn recording_needs_no_identity_and_round_trips_through_the_vault() {
        let s = fake_session();
        let (recipients, ids) = identity_pair();
        let mock = MockServer::default();
        let prior = sealed(&recipients, "hunter1");
        let saved = block_on(record_revision(
            &mock,
            &server(),
            &s,
            &Vault::default(),
            None,
            HistoryEntry::revision("item-1", prior.clone(), vec!["laptop".into()], 10),
        ))
        .unwrap();
        let vault = Vault {
            ciphers: vec![saved],
            ..Vault::default()
        };
        let deletion = HistoryEntry::deletion("item-1", sealed(&recipients, "hunter2"), vec![], 20);
        let saved = block_on(record_revision(
            &mock,
            &server(),
            &s,
            &vault,
            None,
            deletion,
        ))
        .unwrap();
        let vault = Vault {
            ciphers: vec![saved],
            ..Vault::default()
        };

        let got = load_history(&s, &vault, "item-1").unwrap();
        assert_eq!(got.len(), 2);
        assert!(
            got[0].deleted && got[0].recorded_at == 20,
            "newest first, deletion recorded"
        );
        assert_eq!(got[1].prior_payload_armored, prior);
        let old = crate::decrypt(&AgeBlob::from_bytes(prior.into_bytes()), &ids).unwrap();
        assert_eq!(
            &old[..],
            b"hunter1",
            "the prior secret still needs its identity"
        );
        assert!(
            mock.writes.lock().unwrap()[1]
                .0
                .ends_with("/api/ciphers/hist-2"),
            "the second write updates the same cipher"
        );
    }

    #[test]
    fn legacy_browser_and_rageterm_documents_are_folded_in_then_deleted() {
        let s = fake_session();
        let (recipients, ids) = identity_pair();

        let browser = serde_json::json!([{
            "recordedAt": 5, "cipherId": "item-1", "priorPayload": "BROWSER-PRIOR",
            "recipientsSummary": ["passkey"]
        }]);
        let browser_cipher = as_server(
            build_meta_cipher(
                &s,
                &format!("{LEGACY_MARKER_NAME}:item-1"),
                &browser.to_string(),
            )
            .unwrap(),
            "legacy-browser",
        );

        let mut old = HistoryDoc {
            schema: 1,
            entries: BTreeMap::new(),
        };
        old.entries.insert(
            "item-2".into(),
            vec![HistoryEntry::revision("item-2", "TERM-PRIOR", vec![], 7)],
        );
        let old_blob = sealed(&recipients, &serde_json::to_string(&old).unwrap());
        let term_cipher = as_server(
            build_rage_cipher(&s, LEGACY_MARKER_NAME, &old_blob).unwrap(),
            "legacy-term",
        );

        let vault = Vault {
            ciphers: vec![browser_cipher, term_cipher],
            ..Vault::default()
        };

        let without_ids = read_history(&s, &vault, None).unwrap();
        assert_eq!(without_ids.legacy_ids, vec!["legacy-browser".to_string()]);

        let mock = MockServer::default();
        let saved = block_on(record_revision(
            &mock,
            &server(),
            &s,
            &vault,
            Some(&ids),
            HistoryEntry::revision("item-1", "NEW-PRIOR", vec![], 9),
        ))
        .unwrap();
        let mut deleted = mock.deletes.lock().unwrap().clone();
        deleted.sort();
        assert_eq!(deleted.len(), 2);
        assert!(deleted[0].ends_with("/ciphers/legacy-browser"));
        assert!(deleted[1].ends_with("/ciphers/legacy-term"));

        let merged = Vault {
            ciphers: vec![saved],
            ..Vault::default()
        };
        let one = load_history(&s, &merged, "item-1").unwrap();
        let payloads: Vec<&str> = one
            .iter()
            .map(|e| e.prior_payload_armored.as_str())
            .collect();
        assert_eq!(payloads, ["NEW-PRIOR", "BROWSER-PRIOR"]);
        assert_eq!(
            load_history(&s, &merged, "item-2").unwrap()[0].prior_payload_armored,
            "TERM-PRIOR"
        );
    }

    #[test]
    fn a_write_that_does_not_read_back_keeps_the_legacy_documents() {
        let s = fake_session();
        let browser =
            serde_json::json!([{ "recordedAt": 5, "cipherId": "item-1", "priorPayload": "P" }]);
        let vault = Vault {
            ciphers: vec![as_server(
                build_meta_cipher(
                    &s,
                    &format!("{LEGACY_MARKER_NAME}:item-1"),
                    &browser.to_string(),
                )
                .unwrap(),
                "legacy-browser",
            )],
            ..Vault::default()
        };
        let mock = MockServer {
            echo_drops_entries: true,
            ..MockServer::default()
        };
        let err = block_on(record_revision(
            &mock,
            &server(),
            &s,
            &vault,
            None,
            HistoryEntry::revision("item-1", "Q", vec![], 9),
        ))
        .unwrap_err();
        assert!(
            matches!(err, HistoryError::MigrationNotConfirmed),
            "{err:?}"
        );
        assert!(mock.deletes.lock().unwrap().is_empty());
    }

    #[test]
    fn the_doc_uses_camelcase_keys_and_reads_old_entries() {
        let mut doc = HistoryDoc::default();
        append_revision(
            &mut doc,
            HistoryEntry::revision("A", "p", vec!["x".into()], 1),
        );
        let json = serde_json::to_string(&doc).unwrap();
        assert!(
            json.contains("\"recordedAt\"") && json.contains("\"priorPayloadArmored\""),
            "{json}"
        );
        assert!(
            !json.contains("\"deleted\""),
            "a revision does not carry deleted=false"
        );
        let old: HistoryEntry =
            serde_json::from_str(r#"{"recordedAt":1,"cipherId":"A","priorPayloadArmored":"p"}"#)
                .unwrap();
        assert!(!old.deleted && old.stanza_tags.is_empty());
    }
}
