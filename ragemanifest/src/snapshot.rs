use base64::{
    Engine,
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL},
};
use ragewarden_core::stanza_format::{
    PivStanzaKind, TAG_FIDO2_HMAC, TAG_PIV_P256, TAG_PIV_X25519_V2, TAG_RAGEDROID_KEYSTORE_V1,
    TAG_RAGEDROID_KEYSTORE_V2, TAG_WEBAUTHN_PRF_V1, TAG_X25519, fido2_hmac_credential_id,
    is_legacy_prf_wrap, piv_ec_p256_recipient_tag, piv_recipient_tag, piv_stanza_kind,
    piv_x25519_recipient_tag, ragedroid_keystore_key_handle, webauthn_prf_credential_id,
};
use ragewarden_core::sync::{
    Cipher, Server, Session, Vault, cipher_name, decrypt_string, extract_rage_blob,
};
use ragewarden_core::{AgeBlob, Stanza};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSnapshot {
    pub ciphers: Vec<DisplayCipher>,

    pub folders: Vec<DisplayFolder>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayCipher {
    pub id: String,

    pub name: String,

    pub username: Option<String>,

    pub site: Option<String>,

    pub kind: String,

    pub rage: bool,

    /// Whether an identity available on THIS device can open the item.
    /// Non-rage items are always openable (session key). Rage items are
    /// trial-matched against the caller's [`LocalIdentityInventory`] at
    /// snapshot time; with no inventory this is false for every rage item
    /// (fail closed). The UI must not offer a decrypt attempt when false.
    #[serde(default)]
    pub decryptable: bool,

    /// Number of recipient stanzas in the rage header (0 for non-rage items
    /// and for blobs whose header does not parse).
    #[serde(default)]
    pub recipient_count: usize,

    /// The rage header carries a pre-`wrap_salt` PRF stanza, whose body key
    /// every secret wrapped to that authenticator shares: the secret should be
    /// rotated, and re-saving the item writes the current format.
    #[serde(default)]
    pub legacy_wrap: bool,

    /// Registry/history bookkeeping items (`__...__`-style names and the legacy
    /// rageterm recipients list). The UI hides these from the item list.
    #[serde(default)]
    pub internal: bool,

    pub favorite: bool,

    pub folder_id: Option<String>,

    pub raw: Cipher,
}

/// The identities this browser profile can actually bring to bear, as known
/// by the JS glue. Every field is optional; an absent/empty inventory means
/// "nothing available" and marks every rage item undecryptable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalIdentityInventory {
    /// `age1...` recipient strings of software identities whose secret this
    /// profile can unwrap (e.g. `ragewarden:software-identity`). X25519
    /// stanzas carry only an ephemeral share -- no recipient tag -- so any
    /// entry here matches any X25519 stanza; a mismatch is only discovered
    /// at decrypt time (and surfaces as `no_matching_identity`).
    #[serde(default)]
    pub software_armored_pubkeys: Vec<String>,

    /// Credential ids (base64, standard or url-safe) of WebAuthn-PRF
    /// passkeys enrolled in this profile (`webauthn-prf-v1` stanzas).
    #[serde(default)]
    pub passkey_credential_ids_b64: Vec<String>,

    /// Credential ids (base64) of FIDO2 hmac-secret authenticators reachable
    /// from here via the native host (`fido2-hmac` stanzas).
    #[serde(default)]
    pub fido2_credential_ids_b64: Vec<String>,

    /// PIV pubkeys (32-byte X25519 or 33-byte compressed P-256), hex-encoded
    /// exactly as the registry's `pivPubkey`, for YubiKeys reachable via the
    /// native host (`piv-p256` / `piv-x25519-v2` stanzas, matched on the
    /// header's recipient tag).
    #[serde(default)]
    pub piv_pubkeys_hex: Vec<String>,

    /// Android keystore key handles (`ragedroid-keystore-v1`/`-v2` stanzas);
    /// never present in a browser profile, accepted for completeness.
    #[serde(default)]
    pub keystore_handles: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RageHeaderAssessment {
    pub recipient_count: usize,

    pub decryptable: bool,

    /// Pre-`wrap_salt` PRF stanzas in the header (`core::legacy_prf_wraps`).
    pub legacy_prf_wraps: usize,
}

/// Header-only trial match: parse the armored age header and report whether
/// any stanza names an identity in `inventory`. No stanza is unwrapped, no
/// payload touched, no hardware tapped. Unparseable blobs fail closed.
pub fn assess_rage_header(
    armored: &str,
    inventory: &LocalIdentityInventory,
) -> RageHeaderAssessment {
    let blob = AgeBlob::from_bytes(armored.as_bytes().to_vec());
    let stanzas = match ragewarden_core::parse_header_stanzas(&blob) {
        Ok(s) => s,
        Err(_) => {
            return RageHeaderAssessment {
                recipient_count: 0,
                decryptable: false,
                legacy_prf_wraps: 0,
            };
        }
    };
    let real: Vec<&Stanza> = stanzas
        .iter()
        .filter(|s| !s.tag.ends_with("-grease"))
        .collect();
    let decryptable = real.iter().any(|s| stanza_matches_local(s, inventory));
    let legacy_prf_wraps = real.iter().filter(|s| is_legacy_prf_wrap(s)).count();
    RageHeaderAssessment {
        recipient_count: real.len(),
        decryptable,
        legacy_prf_wraps,
    }
}

fn stanza_matches_local(stanza: &Stanza, inv: &LocalIdentityInventory) -> bool {
    match stanza.tag.as_str() {
        TAG_X25519 => !inv.software_armored_pubkeys.is_empty(),
        TAG_WEBAUTHN_PRF_V1 => webauthn_prf_credential_id(stanza)
            .map(|id| contains_b64(&inv.passkey_credential_ids_b64, &id))
            .unwrap_or(false),
        TAG_FIDO2_HMAC => fido2_hmac_credential_id(stanza)
            .map(|id| contains_b64(&inv.fido2_credential_ids_b64, &id))
            .unwrap_or(false),
        TAG_PIV_P256 | TAG_PIV_X25519_V2 => {
            let tag = match piv_stanza_kind(stanza) {
                Some(PivStanzaKind::P256) => piv_ec_p256_recipient_tag(stanza),
                Some(_) => piv_x25519_recipient_tag(stanza),
                None => return false,
            };
            tag.map(|tag| {
                inv.piv_pubkeys_hex
                    .iter()
                    .filter_map(|h| hex_bytes(h))
                    .any(|pk| piv_recipient_tag(&pk) == tag)
            })
            .unwrap_or(false)
        }
        TAG_RAGEDROID_KEYSTORE_V1 | TAG_RAGEDROID_KEYSTORE_V2 => {
            ragedroid_keystore_key_handle(stanza)
                .map(|handle| inv.keystore_handles.contains(&handle))
                .unwrap_or(false)
        }
        _ => false,
    }
}

fn contains_b64(haystack: &[String], needle: &[u8]) -> bool {
    haystack.iter().any(|s| {
        B64.decode(s.as_bytes())
            .ok()
            .or_else(|| B64URL.decode(s.as_bytes()).ok())
            .map(|v| v == needle)
            .unwrap_or(false)
    })
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|c| Some((hex_nibble(c[0])? << 4) | hex_nibble(c[1])?))
        .collect()
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// rageterm's `RECIPIENT_LIST_NAME`; predates the `__...__` convention.
pub const LEGACY_RECIPIENTS_CIPHER_NAME: &str = "Ragewarden Recipients (do not edit)";

/// Registry/history bookkeeping names: `__ragedroid_recipients_v1__`,
/// `__ragewarden_history_v1__:<cipher-id>`, and the legacy rageterm list.
pub fn is_internal_cipher_name(name: &str) -> bool {
    if name == LEGACY_RECIPIENTS_CIPHER_NAME {
        return true;
    }
    name.starts_with("__") && name[2..].contains("__")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayFolder {
    pub id: String,

    pub name: String,
}

/// [`build_snapshot_with_identities`] with an empty inventory: every rage
/// item comes back `decryptable: false`. Callers that can enumerate local
/// identities must use the richer entry point.
pub fn build_snapshot(session: &Session, vault: &Vault) -> VaultSnapshot {
    build_snapshot_with_identities(session, vault, &LocalIdentityInventory::default())
}

pub fn build_snapshot_with_identities(
    session: &Session,
    vault: &Vault,
    inventory: &LocalIdentityInventory,
) -> VaultSnapshot {
    let mut ciphers = Vec::with_capacity(vault.ciphers.len());
    for c in &vault.ciphers {
        let id = match &c.id {
            Some(s) => s.clone(),
            None => continue,
        };
        let name = cipher_name(session, c).unwrap_or_else(|_| "(undecryptable)".to_string());
        let rage_blob = extract_rage_blob(session, c).ok().flatten();
        let rage = rage_blob.is_some();
        let (decryptable, recipient_count, legacy_wrap) = match &rage_blob {
            Some(armored) => {
                let a = assess_rage_header(armored, inventory);
                (a.decryptable, a.recipient_count, a.legacy_prf_wraps > 0)
            }
            None => (true, 0, false),
        };
        let (username, site) = match &c.login {
            Some(l) => {
                let u = l
                    .username
                    .as_ref()
                    .and_then(|s| decrypt_string(session, s).ok());
                let s = l
                    .uris
                    .as_ref()
                    .and_then(|uris| uris.first())
                    .and_then(|first| decrypt_string(session, &first.uri).ok());
                (u, s)
            }
            None => (None, None),
        };
        let kind = match c.cipher_type {
            1 => "login",
            2 => "note",
            3 => "card",
            4 => "identity",
            5 => "ssh_key",
            _ => "other",
        };
        let internal = is_internal_cipher_name(&name);
        ciphers.push(DisplayCipher {
            id,
            name,
            username,
            site,
            kind: kind.into(),
            rage,
            decryptable,
            recipient_count,
            legacy_wrap,
            internal,
            favorite: c.favorite,
            folder_id: c.folder_id.clone(),
            raw: c.clone(),
        });
    }

    let mut folders = Vec::with_capacity(vault.folders.len());
    for f in &vault.folders {
        let name = decrypt_string(session, &f.name).unwrap_or_else(|_| "(undecryptable)".into());
        folders.push(DisplayFolder {
            id: f.id.clone(),
            name,
        });
    }

    VaultSnapshot { ciphers, folders }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireSession {
    pub api_url: String,

    pub identity_url: String,

    pub email: String,

    pub user_id: String,

    pub access_token: ragewarden_core::BearerToken,

    pub refresh_token: ragewarden_core::RefreshToken,

    pub user_enc_key_b64: String,

    pub user_mac_key_b64: String,

    pub kdf_iterations: u32,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_type: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_memory_mib: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_parallelism: Option<u32>,

    #[serde(default)]
    pub device_id: String,
}

impl WireSession {
    pub fn from_runtime(server: &Server, session: &Session) -> Self {
        Self {
            api_url: server.api_url.clone(),
            identity_url: server.identity_url.clone(),
            email: session.email.clone(),
            user_id: session.user_id.clone(),
            access_token: session.access_token.clone(),
            refresh_token: session.refresh_token.clone(),
            user_enc_key_b64: B64.encode(&session.user_enc_key),
            user_mac_key_b64: B64.encode(&session.user_mac_key),
            kdf_iterations: session.kdf.iterations,
            kdf_type: Some(session.kdf.kdf),
            kdf_memory_mib: session.kdf.memory_mib,
            kdf_parallelism: session.kdf.parallelism,
            device_id: session.device_id.clone(),
        }
    }

    pub fn into_runtime(self) -> Result<(Server, Session), String> {
        let user_enc_key = B64
            .decode(self.user_enc_key_b64.as_bytes())
            .map_err(|e| format!("user_enc_key_b64: {e}"))?;
        let user_mac_key = B64
            .decode(self.user_mac_key_b64.as_bytes())
            .map_err(|e| format!("user_mac_key_b64: {e}"))?;
        let server = Server::new(self.api_url, self.identity_url);
        let session = Session {
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            user_id: self.user_id,
            email: self.email,
            user_enc_key: user_enc_key.into(),
            user_mac_key: user_mac_key.into(),
            kdf: ragewarden_core::sync::KdfParams::from_parts(
                self.kdf_type,
                self.kdf_iterations,
                self.kdf_memory_mib,
                self.kdf_parallelism,
            ),
            device_id: self.device_id,
        };
        Ok((server, session))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ragewarden_core::{PrfEntry, Recipient, encrypt as core_encrypt, encrypt_with_prf};

    fn armor(recipients: &[Recipient]) -> String {
        let blob = core_encrypt(b"payload", recipients).expect("encrypt");
        String::from_utf8(blob.0).expect("armored blobs are utf-8")
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn x25519_stanza_matches_only_when_a_software_identity_exists() {
        let armored = armor(&[Recipient::X25519 {
            public_key: [7u8; 32],
        }]);

        let none = assess_rage_header(&armored, &LocalIdentityInventory::default());
        assert_eq!(none.recipient_count, 1);
        assert!(!none.decryptable, "no local identity must fail closed");

        let with_software = LocalIdentityInventory {
            software_armored_pubkeys: vec!["age1example".into()],
            ..Default::default()
        };
        let got = assess_rage_header(&armored, &with_software);
        assert_eq!(got.recipient_count, 1);
        assert!(got.decryptable);
    }

    #[test]
    fn piv_stanza_matches_on_recipient_tag() {
        let pubkey = [9u8; 32];
        let armored = armor(&[Recipient::YubiKeyPiv {
            public_key: pubkey,
            serial: 11541777,
            slot: 0x9a,
            stanza_version: 1,
        }]);

        let right = LocalIdentityInventory {
            piv_pubkeys_hex: vec![hex(&pubkey)],
            ..Default::default()
        };
        assert!(assess_rage_header(&armored, &right).decryptable);

        let wrong = LocalIdentityInventory {
            piv_pubkeys_hex: vec![hex(&[10u8; 32])],
            ..Default::default()
        };
        let got = assess_rage_header(&armored, &wrong);
        assert_eq!(got.recipient_count, 1);
        assert!(!got.decryptable, "another YubiKey's pubkey must not match");
    }

    #[test]
    fn v2_and_p256_piv_stanzas_match_their_registry_pubkeys() {
        let x_pub = [9u8; 32];
        let p256_generator = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        let p_pub = hex_bytes(p256_generator).unwrap();
        for (recipient, pubkey) in [
            (
                Recipient::YubiKeyPiv {
                    public_key: x_pub,
                    serial: 1,
                    slot: 0x9a,
                    stanza_version: 2,
                },
                x_pub.to_vec(),
            ),
            (
                Recipient::YubiKeyPivP256 {
                    public_key: p_pub.clone(),
                    serial: 1,
                    slot: 0x9a,
                },
                p_pub.clone(),
            ),
        ] {
            let armored = armor(&[recipient]);
            let right = LocalIdentityInventory {
                piv_pubkeys_hex: vec![hex(&pubkey)],
                ..Default::default()
            };
            assert!(assess_rage_header(&armored, &right).decryptable);
            let wrong = LocalIdentityInventory {
                piv_pubkeys_hex: vec![hex(&[10u8; 32])],
                ..Default::default()
            };
            assert!(!assess_rage_header(&armored, &wrong).decryptable);
        }
    }

    #[test]
    fn a_pre_wrap_salt_prf_stanza_is_flagged_for_rotation() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../core/tests/vectors/stanza_formats_v1_frozen.json"
        ))
        .unwrap();
        for (name, legacy) in [
            ("webauthn_prf_v1_legacy_3arg", 1),
            ("fido2_hmac_legacy_3arg", 1),
            ("webauthn_prf_v1_wrap_salt", 0),
        ] {
            let armored = v[name]["blob"].as_str().unwrap();
            let got = assess_rage_header(armored, &LocalIdentityInventory::default());
            assert_eq!(got.legacy_prf_wraps, legacy, "{name}");
        }
    }

    fn passkey_recipient(credential_id: &[u8]) -> Recipient {
        Recipient::PasskeyPrf {
            credential_id: credential_id.to_vec(),
            salt: [5u8; 32],
            rp_id: "ragewarden.decent.foundation".into(),
            label: "test passkey".into(),
        }
    }

    fn prf_for(recipient: &Recipient) -> PrfEntry<'_> {
        static PRF: [u8; 32] = [6u8; 32];
        match recipient {
            Recipient::PasskeyPrf { rp_id, salt, .. } => PrfEntry {
                rp_id,
                credential_id: &[],
                salt,
                prf_output: &PRF,
            },
            _ => unreachable!("prf_for takes a passkey recipient"),
        }
    }

    #[test]
    fn passkey_stanza_matches_on_credential_id_in_either_base64_alphabet() {
        let credential_id = [0xfbu8, 0xef, 0x01, 0x02, 0x7f];
        let recipients = [passkey_recipient(&credential_id)];
        let blob =
            encrypt_with_prf(b"payload", &recipients, &[prf_for(&recipients[0])]).expect("encrypt");
        let armored = String::from_utf8(blob.0).unwrap();

        for encoded in [
            base64::engine::general_purpose::STANDARD.encode(credential_id),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
        ] {
            let inv = LocalIdentityInventory {
                passkey_credential_ids_b64: vec![encoded],
                ..Default::default()
            };
            assert!(assess_rage_header(&armored, &inv).decryptable);
        }

        let other = LocalIdentityInventory {
            passkey_credential_ids_b64: vec![B64.encode([1u8, 2, 3])],
            ..Default::default()
        };
        assert!(!assess_rage_header(&armored, &other).decryptable);
    }

    #[test]
    fn one_matching_stanza_among_many_is_enough_and_count_covers_all() {
        let credential_id = [1u8, 2, 3, 4];
        let recipients = [
            Recipient::YubiKeyPiv {
                public_key: [9u8; 32],
                serial: 1,
                slot: 0x9a,
                stanza_version: 1,
            },
            passkey_recipient(&credential_id),
        ];
        let blob =
            encrypt_with_prf(b"payload", &recipients, &[prf_for(&recipients[1])]).expect("encrypt");
        let armored = String::from_utf8(blob.0).unwrap();

        let inv = LocalIdentityInventory {
            passkey_credential_ids_b64: vec![B64.encode(credential_id)],
            ..Default::default()
        };
        let got = assess_rage_header(&armored, &inv);
        assert_eq!(got.recipient_count, 2);
        assert!(got.decryptable);

        let stranger = LocalIdentityInventory {
            software_armored_pubkeys: vec!["age1example".into()],
            ..Default::default()
        };
        let got = assess_rage_header(&armored, &stranger);
        assert_eq!(got.recipient_count, 2);
        assert!(
            !got.decryptable,
            "a software identity must not match hardware-only stanzas"
        );
    }

    #[test]
    fn unparseable_blob_fails_closed() {
        let inv = LocalIdentityInventory {
            software_armored_pubkeys: vec!["age1example".into()],
            ..Default::default()
        };
        let got = assess_rage_header("armored age blob ----", &inv);
        assert_eq!(got.recipient_count, 0);
        assert!(!got.decryptable);
    }

    #[test]
    fn internal_names_cover_registry_history_and_legacy_list() {
        assert!(is_internal_cipher_name("__ragedroid_recipients_v1__"));
        assert!(is_internal_cipher_name(
            "__ragewarden_history_v1__:cipher-uuid"
        ));
        assert!(is_internal_cipher_name(LEGACY_RECIPIENTS_CIPHER_NAME));

        assert!(!is_internal_cipher_name("GitHub"));
        assert!(!is_internal_cipher_name(
            "__dunder prefix without closing pair"
        ));
        assert!(!is_internal_cipher_name("_single_underscore_"));
        assert!(!is_internal_cipher_name("Ragewarden Recipients"));
    }
}
