use serde::{Deserialize, Serialize};

use crate::sync::{cipher_name, decrypt_string, Cipher, Session, SyncError, Vault};
use crate::{ArmoredAgeRecipient, Recipient};

pub const MARKER_NAME: &str = crate::sync::RECIPIENTS_META_CIPHER_NAME;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireDocument {
    #[serde(default = "default_schema")]
    pub schema: u32,
    pub entries: Vec<WireEntry>,
}

fn default_schema() -> u32 {
    SCHEMA_VERSION
}

impl Default for WireDocument {
    fn default() -> Self {
        Self {
            schema: SCHEMA_VERSION,
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireEntry {
    pub id: String,

    pub kind: String,

    #[serde(rename = "displayName")]
    pub display_name: String,

    #[serde(rename = "deviceLabel")]
    pub device_label: String,

    #[serde(rename = "createdAt")]
    pub created_at: i64,

    #[serde(default = "default_true", rename = "defaultEncrypt")]
    pub default_encrypt: bool,

    #[serde(rename = "pivPubkey", default, skip_serializing_if = "Option::is_none")]
    pub piv_pubkey: Option<String>,
    #[serde(rename = "pivSerial", default, skip_serializing_if = "Option::is_none")]
    pub piv_serial: Option<i32>,
    #[serde(rename = "pivSlot", default, skip_serializing_if = "Option::is_none")]
    pub piv_slot: Option<i32>,

    #[serde(rename = "keystorePubkey", default, skip_serializing_if = "Option::is_none")]
    pub keystore_pubkey: Option<String>,
    #[serde(rename = "keystoreHandle", default, skip_serializing_if = "Option::is_none")]
    pub keystore_handle: Option<String>,

    #[serde(rename = "fido2CredentialId", default, skip_serializing_if = "Option::is_none")]
    pub fido2_credential_id: Option<String>,
    #[serde(rename = "fido2RpId", default, skip_serializing_if = "Option::is_none")]
    pub fido2_rp_id: Option<String>,
    #[serde(rename = "fido2Salt", default, skip_serializing_if = "Option::is_none")]
    pub fido2_salt: Option<String>,

    #[serde(rename = "recoveryArmoredPubkey", default, skip_serializing_if = "Option::is_none")]
    pub recovery_armored_pubkey: Option<String>,
}

fn default_true() -> bool {
    true
}

pub mod kinds {
    pub const STRONG_BOX: &str = "StrongBox";
    pub const YUBIKEY: &str = "YubiKey";
    pub const FIDO2: &str = "Fido2";
    pub const RECOVERY: &str = "Recovery";
    pub const SOFTWARE: &str = "Software";

    /// A WebAuthn-PRF passkey. Distinct from [`FIDO2`] because the two wrap
    /// into *different stanza tags* (`webauthn-prf-v1` vs `fido2-hmac`) with
    /// different HKDF info strings. Without this kind a `PasskeyPrf` recipient
    /// published as `Fido2` comes back as `Fido2HmacSecret` and gets wrapped
    /// into a stanza its own authenticator will not unwrap.
    ///
    /// Older clients see an unknown kind and skip it with a named reason
    /// (`policy::SkipReason::UnknownKind`) rather than mis-wrapping it.
    pub const PASSKEY_PRF: &str = "PasskeyPrf";
}

impl WireEntry {
    pub fn strongbox_pubkey_bytes(&self) -> Option<Vec<u8>> {
        if self.kind != kinds::STRONG_BOX {
            return None;
        }
        let hex = self.keystore_pubkey.as_ref()?;
        let bytes = hex_decode(hex)?;
        if crate::stanza_format::is_valid_p256_sec1_compressed(&bytes) {
            Some(bytes)
        } else {
            None
        }
    }

    pub fn to_recipient_if_active(&self) -> Option<Recipient> {
        if !self.default_encrypt {
            return None;
        }
        self.to_recipient()
    }

    /// Key material -> recipient, ignoring `default_encrypt`. Callers that need
    /// to tell "owner turned it off" apart from "key material is unusable"
    /// (see `crate::policy`) check the flag themselves.
    pub fn to_recipient(&self) -> Option<Recipient> {
        match self.kind.as_str() {
            kinds::STRONG_BOX => {
                let pubkey = self.strongbox_pubkey_bytes()?;
                let key_handle = self.keystore_handle.clone()?;
                Some(Recipient::AndroidKeystore {
                    public_key: pubkey,
                    key_handle,
                })
            }
            kinds::YUBIKEY => {
                let hex = self.piv_pubkey.as_ref()?;
                let bytes = hex_decode(hex)?;
                let public_key: [u8; 32] = bytes.try_into().ok()?;
                let serial = self.piv_serial.unwrap_or(0).max(0) as u32;
                let slot = self.piv_slot.unwrap_or(0).max(0) as u8;
                Some(Recipient::YubiKeyPiv {
                    public_key,
                    serial,
                    slot,
                })
            }
            kinds::FIDO2 => {
                let credential_id = hex_decode(self.fido2_credential_id.as_ref()?)?;
                let salt_bytes = hex_decode(self.fido2_salt.as_ref()?)?;
                let salt: [u8; 32] = salt_bytes.try_into().ok()?;
                let rp_id = self.fido2_rp_id.clone()?;
                Some(Recipient::Fido2HmacSecret {
                    credential_id,
                    salt,
                    rp_id,
                })
            }
            kinds::PASSKEY_PRF => {
                let credential_id = hex_decode(self.fido2_credential_id.as_ref()?)?;
                let salt_bytes = hex_decode(self.fido2_salt.as_ref()?)?;
                let salt: [u8; 32] = salt_bytes.try_into().ok()?;
                let rp_id = self.fido2_rp_id.clone()?;
                Some(Recipient::PasskeyPrf {
                    credential_id,
                    salt,
                    rp_id,
                    label: self.display_name.clone(),
                })
            }
            kinds::RECOVERY | kinds::SOFTWARE => {
                let armored = self.recovery_armored_pubkey.clone()?;
                Some(Recipient::SoftwarePassphrase {
                    armored_pubkey: ArmoredAgeRecipient::from_trusted(armored),
                })
            }
            _ => None,
        }
    }
}

pub fn find_marker_cipher<'a>(session: &Session, vault: &'a Vault) -> Option<&'a Cipher> {
    vault.ciphers.iter().find(|c| {
        cipher_name(session, c)
            .map(|n| n == MARKER_NAME)
            .unwrap_or(false)
    })
}

pub fn extract_document(
    session: &Session,
    vault: &Vault,
) -> Result<Option<WireDocument>, SyncError> {
    let Some(cipher) = find_marker_cipher(session, vault) else {
        return Ok(None);
    };
    let Some(notes_ct) = &cipher.notes else {
        return Ok(None);
    };
    let plaintext = decrypt_string(session, notes_ct)?;
    let doc: WireDocument = serde_json::from_str(&plaintext)
        .map_err(|e| SyncError::Parse(format!("registry payload: {e}")))?;
    Ok(Some(doc))
}

pub fn marker_cipher_id<'a>(session: &Session, vault: &'a Vault) -> Option<&'a str> {
    find_marker_cipher(session, vault).and_then(|c| c.id.as_deref())
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P256_GENERATOR_COMPRESSED: &str =
        "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";

    const NOT_A_P256_POINT: &str =
        "020101010101010101010101010101010101010101010101010101010101010101";

    #[test]
    fn deserializes_android_kotlinx_payload() {
        let json = r#"{
            "schema": 1,
            "entries": [
                {
                    "id": "abc-123",
                    "kind": "StrongBox",
                    "displayName": "This phone",
                    "deviceLabel": "Pixel 10 Pro",
                    "createdAt": 1715000000000,
                    "defaultEncrypt": true,
                    "keystorePubkey": "020102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
                    "keystoreHandle": "ragewarden-keystore-abc"
                },
                {
                    "id": "rec-1",
                    "kind": "Recovery",
                    "displayName": "Paper recovery",
                    "deviceLabel": "Pixel 10 Pro",
                    "createdAt": 1715000001000,
                    "recoveryArmoredPubkey": "age1nukguzqzgkpd087j2ju3v54x9rdhzfq6gwms9cw35lvdwq3chpuq6xz32k"
                }
            ]
        }"#;
        let doc: WireDocument = serde_json::from_str(json).expect("parse");
        assert_eq!(doc.schema, 1);
        assert_eq!(doc.entries.len(), 2);
        let strongbox = &doc.entries[0];
        assert_eq!(strongbox.kind, kinds::STRONG_BOX);
        assert!(strongbox.default_encrypt);
        assert_eq!(strongbox.keystore_handle.as_deref(), Some("ragewarden-keystore-abc"));
        assert_eq!(strongbox.strongbox_pubkey_bytes().unwrap().len(), 33);

        let recovery = &doc.entries[1];
        assert_eq!(recovery.kind, kinds::RECOVERY);
        assert!(recovery.default_encrypt);
        assert_eq!(
            recovery.recovery_armored_pubkey.as_deref(),
            Some("age1nukguzqzgkpd087j2ju3v54x9rdhzfq6gwms9cw35lvdwq3chpuq6xz32k"),
        );
    }

    #[test]
    fn round_trip_preserves_keystore_handle() {
        let original = WireDocument {
            schema: SCHEMA_VERSION,
            entries: vec![WireEntry {
                id: "id-1".into(),
                kind: kinds::STRONG_BOX.into(),
                display_name: "This phone".into(),
                device_label: "Pixel".into(),
                created_at: 1,
                default_encrypt: true,
                piv_pubkey: None,
                piv_serial: None,
                piv_slot: None,
                keystore_pubkey: Some("02".to_string() + &"00".repeat(32)),
                keystore_handle: Some("handle-xyz".into()),
                fido2_credential_id: None,
                fido2_rp_id: None,
                fido2_salt: None,
                recovery_armored_pubkey: None,
            }],
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: WireDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
        assert!(json.contains("keystoreHandle"));
    }

    #[test]
    fn to_recipient_strongbox_yields_android_keystore() {
        let entry = WireEntry {
            id: "id-1".into(),
            kind: kinds::STRONG_BOX.into(),
            display_name: "This phone".into(),
            device_label: "Pixel".into(),
            created_at: 1,
            default_encrypt: true,
            piv_pubkey: None,
            piv_serial: None,
            piv_slot: None,
            keystore_pubkey: Some(P256_GENERATOR_COMPRESSED.to_string()),
            keystore_handle: Some("h".into()),
            fido2_credential_id: None,
            fido2_rp_id: None,
            fido2_salt: None,
            recovery_armored_pubkey: None,
        };
        match entry.to_recipient_if_active() {
            Some(Recipient::AndroidKeystore { public_key, key_handle }) => {
                assert_eq!(public_key.len(), 33);
                assert_eq!(key_handle, "h");
            }
            other => panic!("expected AndroidKeystore, got {other:?}"),
        }
    }

    fn strongbox_entry(pubkey_hex: &str) -> WireEntry {
        WireEntry {
            id: "hostile".into(),
            kind: kinds::STRONG_BOX.into(),
            display_name: "Attacker's phone".into(),
            device_label: "Pixel".into(),
            created_at: 0,
            default_encrypt: true,
            piv_pubkey: None,
            piv_serial: None,
            piv_slot: None,
            keystore_pubkey: Some(pubkey_hex.to_string()),
            keystore_handle: Some("h".into()),
            fido2_credential_id: None,
            fido2_rp_id: None,
            fido2_salt: None,
            recovery_armored_pubkey: None,
        }
    }

    #[test]
    fn strongbox_pubkey_of_right_length_but_off_curve_is_rejected() {
        let entry = strongbox_entry(NOT_A_P256_POINT);
        assert_eq!(
            hex_decode(NOT_A_P256_POINT).unwrap().len(),
            33,
            "fixture must be 33 bytes so this tests point validity, not length"
        );
        assert!(
            entry.strongbox_pubkey_bytes().is_none(),
            "a 33-byte non-point passed the registry check"
        );
        assert!(
            entry.to_recipient_if_active().is_none(),
            "a 33-byte non-point became an encryption recipient"
        );
    }

    #[test]
    fn hostile_registry_pubkey_does_not_panic_the_encrypt_path() {
        let entry = strongbox_entry(P256_GENERATOR_COMPRESSED);
        let good = entry.to_recipient_if_active().expect("valid point accepted");
        assert!(crate::encrypt(b"x", &[good]).is_ok());

        let bad = Recipient::AndroidKeystore {
            public_key: hex_decode(NOT_A_P256_POINT).unwrap(),
            key_handle: "h".into(),
        };
        let err = crate::encrypt(b"x", &[bad]).unwrap_err();
        assert!(
            matches!(err, crate::EncryptError::Recipient(_)),
            "expected a Recipient error, got {err:?}"
        );
    }

    #[test]
    fn stanza_builder_rejects_a_33_byte_non_point_instead_of_panicking() {
        let bad = hex_decode(NOT_A_P256_POINT).unwrap();
        let err = crate::stanza_format::encrypt_ragedroid_keystore_stanza(&[7u8; 16], &bad, "h")
            .unwrap_err();
        assert!(
            matches!(err, crate::stanza_format::StanzaFormatError::Shape(_)),
            "got {err:?}"
        );

        let short = vec![0x02u8; 32];
        assert!(
            crate::stanza_format::encrypt_ragedroid_keystore_stanza(&[7u8; 16], &short, "h")
                .is_err()
        );
    }

    #[test]
    fn to_recipient_software_with_armored_pubkey_yields_software_passphrase() {
        let entry = WireEntry {
            id: "rageterm-deadbeef".into(),
            kind: kinds::SOFTWARE.into(),
            display_name: "Terminal".into(),
            device_label: "rageterm@host".into(),
            created_at: 0,
            default_encrypt: true,
            piv_pubkey: None,
            piv_serial: None,
            piv_slot: None,
            keystore_pubkey: None,
            keystore_handle: None,
            fido2_credential_id: None,
            fido2_rp_id: None,
            fido2_salt: None,
            recovery_armored_pubkey: Some("age1examplerageterm".into()),
        };
        match entry.to_recipient_if_active() {
            Some(Recipient::SoftwarePassphrase { armored_pubkey }) => {
                assert_eq!(armored_pubkey.as_str(), "age1examplerageterm");
            }
            other => panic!("expected SoftwarePassphrase, got {other:?}"),
        }
    }

    #[test]
    fn to_recipient_recovery_yields_software_passphrase() {
        let entry = WireEntry {
            id: "id-2".into(),
            kind: kinds::RECOVERY.into(),
            display_name: "Paper recovery".into(),
            device_label: "Pixel".into(),
            created_at: 0,
            default_encrypt: true,
            piv_pubkey: None,
            piv_serial: None,
            piv_slot: None,
            keystore_pubkey: None,
            keystore_handle: None,
            fido2_credential_id: None,
            fido2_rp_id: None,
            fido2_salt: None,
            recovery_armored_pubkey: Some("age1example".into()),
        };
        match entry.to_recipient_if_active() {
            Some(Recipient::SoftwarePassphrase { armored_pubkey }) => {
                assert_eq!(armored_pubkey.as_str(), "age1example");
            }
            other => panic!("expected SoftwarePassphrase, got {other:?}"),
        }
    }

    #[test]
    fn to_recipient_legacy_32b_strongbox_returns_none() {
        let entry = WireEntry {
            id: "legacy".into(),
            kind: kinds::STRONG_BOX.into(),
            display_name: "Old phone".into(),
            device_label: "Pixel 9".into(),
            created_at: 0,
            default_encrypt: true,
            piv_pubkey: None,
            piv_serial: None,
            piv_slot: None,
            keystore_pubkey: Some("00".repeat(32)),
            keystore_handle: Some("legacy-handle".into()),
            fido2_credential_id: None,
            fido2_rp_id: None,
            fido2_salt: None,
            recovery_armored_pubkey: None,
        };
        assert!(entry.to_recipient_if_active().is_none());
    }

    #[test]
    fn to_recipient_default_encrypt_false_returns_none() {
        let mut entry = WireEntry {
            id: "id".into(),
            kind: kinds::RECOVERY.into(),
            display_name: "Recovery".into(),
            device_label: "Pixel".into(),
            created_at: 0,
            default_encrypt: false,
            piv_pubkey: None,
            piv_serial: None,
            piv_slot: None,
            keystore_pubkey: None,
            keystore_handle: None,
            fido2_credential_id: None,
            fido2_rp_id: None,
            fido2_salt: None,
            recovery_armored_pubkey: Some("age1example".into()),
        };
        assert!(entry.to_recipient_if_active().is_none());
        entry.default_encrypt = true;
        assert!(entry.to_recipient_if_active().is_some());
    }

    #[test]
    fn skips_legacy_32_byte_strongbox_entries() {
        let entry = WireEntry {
            id: "legacy".into(),
            kind: kinds::STRONG_BOX.into(),
            display_name: "Old phone".into(),
            device_label: "Pixel 9".into(),
            created_at: 0,
            default_encrypt: true,
            piv_pubkey: None,
            piv_serial: None,
            piv_slot: None,
            keystore_pubkey: Some("00".repeat(32)),
            keystore_handle: Some("legacy-handle".into()),
            fido2_credential_id: None,
            fido2_rp_id: None,
            fido2_salt: None,
            recovery_armored_pubkey: None,
        };
        assert!(entry.strongbox_pubkey_bytes().is_none());
    }
}
