use serde::{Deserialize, Serialize};

use crate::sync::{Cipher, Session, SyncError, Vault, cipher_name, decrypt_string};
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

    #[serde(
        rename = "keystorePubkey",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub keystore_pubkey: Option<String>,
    #[serde(
        rename = "keystoreHandle",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub keystore_handle: Option<String>,

    #[serde(
        rename = "fido2CredentialId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub fido2_credential_id: Option<String>,
    #[serde(rename = "fido2RpId", default, skip_serializing_if = "Option::is_none")]
    pub fido2_rp_id: Option<String>,
    #[serde(rename = "fido2Salt", default, skip_serializing_if = "Option::is_none")]
    pub fido2_salt: Option<String>,

    #[serde(
        rename = "recoveryArmoredPubkey",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub recovery_armored_pubkey: Option<String>,

    /// The newest ECDH stanza version every reader of this entry understands
    /// (absent = 1). Readers ship first; an entry is republished with 2 once
    /// the clients that unwrap it read `piv-x25519-v2` /
    /// `ragedroid-keystore-v2`, and only then do writers emit them.
    #[serde(
        rename = "stanzaVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub stanza_version: Option<u8>,

    /// Base64 SPKI DER of a P-256 key the device holds (a PIV slot's own key)
    /// that signs native-host unwrap proofs for this recipient.
    #[serde(
        rename = "attestationPublicKey",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub attestation_public_key: Option<String>,
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

    /// The ECDH stanza version to write for this entry: what it advertises,
    /// capped at the newest this crate writes.
    pub fn ecdh_stanza_version(&self) -> u8 {
        self.stanza_version.unwrap_or(1).clamp(1, 2)
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
                    stanza_version: self.ecdh_stanza_version(),
                })
            }
            kinds::YUBIKEY => {
                let hex = self.piv_pubkey.as_ref()?;
                let bytes = hex_decode(hex)?;
                let serial = self.piv_serial.unwrap_or(0).max(0) as u32;
                let slot = self.piv_slot.unwrap_or(0).max(0) as u8;
                if crate::stanza_format::is_valid_p256_sec1_compressed(&bytes) {
                    return Some(Recipient::YubiKeyPivP256 {
                        public_key: bytes,
                        serial,
                        slot,
                    });
                }
                let public_key: [u8; 32] = bytes.try_into().ok()?;
                Some(Recipient::YubiKeyPiv {
                    public_key,
                    serial,
                    slot,
                    stanza_version: self.ecdh_stanza_version(),
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

    fn wire(id: &str, kind: &str, display_name: &str, device_label: &str) -> WireEntry {
        WireEntry {
            id: id.into(),
            kind: kind.into(),
            display_name: display_name.into(),
            device_label: device_label.into(),
            created_at: 1,
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
        assert_eq!(
            strongbox.keystore_handle.as_deref(),
            Some("ragewarden-keystore-abc")
        );
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
                keystore_pubkey: Some("02".to_string() + &"00".repeat(32)),
                keystore_handle: Some("handle-xyz".into()),
                ..wire("id-1", kinds::STRONG_BOX, "This phone", "Pixel")
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
            keystore_pubkey: Some(P256_GENERATOR_COMPRESSED.to_string()),
            keystore_handle: Some("h".into()),
            ..wire("id-1", kinds::STRONG_BOX, "This phone", "Pixel")
        };
        match entry.to_recipient_if_active() {
            Some(Recipient::AndroidKeystore {
                public_key,
                key_handle,
                stanza_version,
            }) => {
                assert_eq!(stanza_version, 1, "absent stanzaVersion means v1");
                assert_eq!(public_key.len(), 33);
                assert_eq!(key_handle, "h");
            }
            other => panic!("expected AndroidKeystore, got {other:?}"),
        }
    }

    fn strongbox_entry(pubkey_hex: &str) -> WireEntry {
        WireEntry {
            created_at: 0,
            keystore_pubkey: Some(pubkey_hex.to_string()),
            keystore_handle: Some("h".into()),
            ..wire("hostile", kinds::STRONG_BOX, "Attacker's phone", "Pixel")
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
        let good = entry
            .to_recipient_if_active()
            .expect("valid point accepted");
        assert!(crate::encrypt(b"x", &[good]).is_ok());

        let bad = Recipient::AndroidKeystore {
            public_key: hex_decode(NOT_A_P256_POINT).unwrap(),
            key_handle: "h".into(),
            stanza_version: 1,
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
        let err = crate::stanza_format::encrypt_ragedroid_keystore_stanza(
            &[7u8; 16],
            &bad,
            "h",
            crate::stanza_format::EcdhStanzaVersion::V2,
        )
        .unwrap_err();
        assert!(
            matches!(err, crate::stanza_format::StanzaFormatError::Shape(_)),
            "got {err:?}"
        );

        let short = vec![0x02u8; 32];
        assert!(
            crate::stanza_format::encrypt_ragedroid_keystore_stanza(
                &[7u8; 16],
                &short,
                "h",
                crate::stanza_format::EcdhStanzaVersion::V2,
            )
            .is_err()
        );
    }

    #[test]
    fn to_recipient_software_with_armored_pubkey_yields_software_passphrase() {
        let entry = WireEntry {
            created_at: 0,
            recovery_armored_pubkey: Some("age1examplerageterm".into()),
            ..wire(
                "rageterm-deadbeef",
                kinds::SOFTWARE,
                "Terminal",
                "rageterm@host",
            )
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
            created_at: 0,
            recovery_armored_pubkey: Some("age1example".into()),
            ..wire("id-2", kinds::RECOVERY, "Paper recovery", "Pixel")
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
            created_at: 0,
            keystore_pubkey: Some("00".repeat(32)),
            keystore_handle: Some("legacy-handle".into()),
            ..wire("legacy", kinds::STRONG_BOX, "Old phone", "Pixel 9")
        };
        assert!(entry.to_recipient_if_active().is_none());
    }

    #[test]
    fn to_recipient_default_encrypt_false_returns_none() {
        let mut entry = WireEntry {
            created_at: 0,
            default_encrypt: false,
            recovery_armored_pubkey: Some("age1example".into()),
            ..wire("id", kinds::RECOVERY, "Recovery", "Pixel")
        };
        assert!(entry.to_recipient_if_active().is_none());
        entry.default_encrypt = true;
        assert!(entry.to_recipient_if_active().is_some());
    }

    #[test]
    fn skips_legacy_32_byte_strongbox_entries() {
        let entry = WireEntry {
            created_at: 0,
            keystore_pubkey: Some("00".repeat(32)),
            keystore_handle: Some("legacy-handle".into()),
            ..wire("legacy", kinds::STRONG_BOX, "Old phone", "Pixel 9")
        };
        assert!(entry.strongbox_pubkey_bytes().is_none());
    }
}
