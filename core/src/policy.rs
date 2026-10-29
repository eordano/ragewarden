//! The canonical recipient-selection policy.
//!
//! Every client (rageterm, ragedroid, ragemanifest) must decide the same thing
//! from the same registry: *which recipients does a newly written secret get
//! wrapped to?* Before this module each of the three answered that question in
//! its own language with its own filter, and the three answers disagreed --
//! silently, with every client reporting success. See
//! `core/tests/recipient_policy_cross_client.rs` for the divergence matrix.
//!
//! There is exactly ONE sanctioned per-client difference, and it is named:
//! [`LocalAuthenticators`]. A PRF recipient (FIDO2 hmac-secret / WebAuthn PRF)
//! can only be wrapped to by a client that can evaluate the authenticator's PRF
//! *at wrap time*, which means physically holding the authenticator. No client
//! can wrap to a passkey that lives on someone else's device. Everything else --
//! Software, Recovery, YubiKey PIV, StrongBox -- is an asymmetric public-key
//! operation that every client can and MUST perform.

use serde::{Deserialize, Serialize};

use crate::Recipient;
use crate::registry::{WireEntry, kinds};

pub const POLICY_VERSION: u32 = 1;

/// Why a registry entry did not become an encryption recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// The owner turned this recipient off for new writes.
    DefaultEncryptOff,
    /// A registry `kind` this build does not know about.
    UnknownKind,
    /// Right kind, unusable key material (wrong length, off-curve, missing).
    MalformedKeyMaterial,
    /// A PRF recipient whose authenticator this client cannot reach.
    ///
    /// This is the one sanctioned divergence. It is *not* silent: the caller
    /// gets it back in [`Selection::skipped`] and is expected to surface it,
    /// because the holder of that authenticator will not be able to open the
    /// item unless some other recipient of theirs is also in the set.
    NoLocalAuthenticator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedEntry {
    pub id: String,
    pub kind: String,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Selection {
    pub recipients: Vec<Recipient>,
    pub skipped: Vec<SkippedEntry>,
}

impl Selection {
    pub fn is_empty(&self) -> bool {
        self.recipients.is_empty()
    }

    /// Entries dropped only because this client cannot reach the authenticator.
    /// Clients should warn about these; they are the coverage holes.
    pub fn unreachable_authenticators(&self) -> impl Iterator<Item = &SkippedEntry> {
        self.skipped
            .iter()
            .filter(|s| s.reason == SkipReason::NoLocalAuthenticator)
    }
}

/// The authenticators this client can evaluate a PRF on during a wrap.
///
/// Identified by registry entry id. A client that enrolled a FIDO2 key or a
/// passkey locally lists that entry's id here; entries belonging to other
/// devices are not listed and are skipped with
/// [`SkipReason::NoLocalAuthenticator`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAuthenticators {
    #[serde(default)]
    pub prf_entry_ids: Vec<String>,
}

impl LocalAuthenticators {
    /// A client with no reachable authenticator -- the rageterm/ragemanifest
    /// default when nothing PRF-capable is enrolled on this machine.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn from_ids<I, S>(ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            prf_entry_ids: ids.into_iter().map(Into::into).collect(),
        }
    }

    pub fn contains(&self, entry_id: &str) -> bool {
        self.prf_entry_ids.iter().any(|id| id == entry_id)
    }
}

/// True for recipient kinds whose wrap needs a live authenticator evaluation.
pub fn requires_local_authenticator(r: &Recipient) -> bool {
    matches!(
        r,
        Recipient::Fido2HmacSecret { .. } | Recipient::PasskeyPrf { .. }
    )
}

fn is_known_kind(kind: &str) -> bool {
    matches!(
        kind,
        kinds::STRONG_BOX
            | kinds::YUBIKEY
            | kinds::FIDO2
            | kinds::PASSKEY_PRF
            | kinds::RECOVERY
            | kinds::SOFTWARE
    )
}

/// Canonical merge of the cross-device registry with this device's own list.
///
/// The local copy of an entry wins over the registry copy -- the device holding
/// the key is authoritative about it -- and the result is ordered by
/// `(created_at, id)` so that every client hands the same sequence to
/// [`select_encrypt_recipients`] regardless of how it stores things.
pub fn merge_entries(registry: &[WireEntry], local: &[WireEntry]) -> Vec<WireEntry> {
    let mut out: Vec<WireEntry> = Vec::with_capacity(registry.len() + local.len());
    for e in registry.iter().chain(local.iter()) {
        match out.iter_mut().find(|x| x.id == e.id) {
            Some(slot) => *slot = e.clone(),
            None => out.push(e.clone()),
        }
    }
    out.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}

/// THE policy. Given registry entries and what this client can physically
/// reach, produce the recipient set a new secret is wrapped to.
///
/// Deterministic: the same `entries` and the same `local` always give the same
/// `Vec<Recipient>` in the same order, in every client.
pub fn select_encrypt_recipients(entries: &[WireEntry], local: &LocalAuthenticators) -> Selection {
    let mut sel = Selection::default();
    let mut seen: Vec<&str> = Vec::with_capacity(entries.len());

    for entry in entries {
        if seen.contains(&entry.id.as_str()) {
            continue;
        }
        seen.push(entry.id.as_str());

        let skip = |sel: &mut Selection, reason: SkipReason| {
            sel.skipped.push(SkippedEntry {
                id: entry.id.clone(),
                kind: entry.kind.clone(),
                reason,
            });
        };

        if !is_known_kind(entry.kind.as_str()) {
            skip(&mut sel, SkipReason::UnknownKind);
            continue;
        }
        if !entry.default_encrypt {
            skip(&mut sel, SkipReason::DefaultEncryptOff);
            continue;
        }
        let Some(recipient) = entry.to_recipient() else {
            skip(&mut sel, SkipReason::MalformedKeyMaterial);
            continue;
        };
        if requires_local_authenticator(&recipient) && !local.contains(entry.id.as_str()) {
            skip(&mut sel, SkipReason::NoLocalAuthenticator);
            continue;
        }
        if sel.recipients.contains(&recipient) {
            continue;
        }
        sel.recipients.push(recipient);
    }

    sel
}

/// Convenience wrapper: merge then select.
pub fn select_for_encrypt(
    registry: &[WireEntry],
    local_entries: &[WireEntry],
    local_auth: &LocalAuthenticators,
) -> Selection {
    select_encrypt_recipients(&merge_entries(registry, local_entries), local_auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, kind: &str, created_at: i64) -> WireEntry {
        WireEntry {
            id: id.into(),
            kind: kind.into(),
            display_name: id.into(),
            device_label: "dev".into(),
            created_at,
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
            stanza_version: None,
            attestation_public_key: None,
        }
    }

    fn software(id: &str, at: i64, pubkey: &str) -> WireEntry {
        let mut e = entry(id, kinds::SOFTWARE, at);
        e.recovery_armored_pubkey = Some(pubkey.into());
        e
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn fido2(id: &str, at: i64) -> WireEntry {
        let mut e = entry(id, kinds::FIDO2, at);
        e.fido2_credential_id = Some(hex(b"cred"));
        e.fido2_salt = Some(hex(&[9u8; 32]));
        e.fido2_rp_id = Some("ragewarden".into());
        e
    }

    #[test]
    fn software_and_recovery_are_both_selected() {
        let entries = vec![software("sw", 1, "age1sw"), {
            let mut e = entry("rec", kinds::RECOVERY, 2);
            e.recovery_armored_pubkey = Some("age1rec".into());
            e
        }];
        let sel = select_encrypt_recipients(&entries, &LocalAuthenticators::none());
        assert_eq!(sel.recipients.len(), 2, "{sel:?}");
        assert!(sel.skipped.is_empty());
    }

    #[test]
    fn prf_entry_needs_a_local_authenticator_and_says_so() {
        let entries = vec![fido2("f", 1)];

        let without = select_encrypt_recipients(&entries, &LocalAuthenticators::none());
        assert!(without.recipients.is_empty());
        assert_eq!(without.skipped.len(), 1);
        assert_eq!(without.skipped[0].reason, SkipReason::NoLocalAuthenticator);
        assert_eq!(without.unreachable_authenticators().count(), 1);

        let with = select_encrypt_recipients(&entries, &LocalAuthenticators::from_ids(["f"]));
        assert_eq!(with.recipients.len(), 1);
        assert!(with.skipped.is_empty());
    }

    #[test]
    fn default_encrypt_off_and_malformed_are_distinguishable() {
        let mut off = software("off", 1, "age1x");
        off.default_encrypt = false;

        let mut bad = entry("bad", kinds::STRONG_BOX, 2);
        bad.keystore_pubkey = Some("00".repeat(32));
        bad.keystore_handle = Some("h".into());

        let unknown = entry("weird", "SomethingElse", 3);

        let sel = select_encrypt_recipients(&[off, bad, unknown], &LocalAuthenticators::none());
        assert!(sel.recipients.is_empty());
        let reasons: Vec<SkipReason> = sel.skipped.iter().map(|s| s.reason).collect();
        assert_eq!(
            reasons,
            vec![
                SkipReason::DefaultEncryptOff,
                SkipReason::MalformedKeyMaterial,
                SkipReason::UnknownKind,
            ],
        );
    }

    #[test]
    fn merge_prefers_local_copy_and_orders_canonically() {
        let reg = vec![software("a", 20, "age1stale"), software("b", 10, "age1b")];
        let local = vec![software("a", 20, "age1fresh")];
        let merged = merge_entries(&reg, &local);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].id, "b", "ordered by created_at");
        assert_eq!(
            merged[1].recovery_armored_pubkey.as_deref(),
            Some("age1fresh")
        );
    }

    #[test]
    fn merge_order_does_not_change_the_selection() {
        let a = software("a", 5, "age1a");
        let b = software("b", 1, "age1b");
        let one = select_encrypt_recipients(
            &merge_entries(&[a.clone(), b.clone()], &[]),
            &LocalAuthenticators::none(),
        );
        let two =
            select_encrypt_recipients(&merge_entries(&[b, a], &[]), &LocalAuthenticators::none());
        assert_eq!(one, two);
    }

    #[test]
    fn duplicate_ids_are_selected_once() {
        let e = software("dup", 1, "age1dup");
        let sel = select_encrypt_recipients(&[e.clone(), e], &LocalAuthenticators::none());
        assert_eq!(sel.recipients.len(), 1);
    }
}
