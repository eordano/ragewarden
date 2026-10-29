use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Recipient {
    X25519 {
        public_key: [u8; 32],
    },

    /// An X25519 PIV slot (YubiKey 5.7+).
    YubiKeyPiv {
        public_key: [u8; 32],

        serial: u32,

        slot: u8,

        /// 1 writes the original `piv-p256` X25519 stanza, 2 writes
        /// `piv-x25519-v2`; see `stanza_format::EcdhStanzaVersion`.
        #[serde(default = "v1", skip_serializing_if = "is_v1")]
        stanza_version: u8,
    },

    /// A P-256 PIV slot (every YubiKey 4/5), wrapped in
    /// `age-plugin-yubikey`'s `piv-p256` format.
    YubiKeyPivP256 {
        /// 33-byte SEC1-compressed point.
        public_key: Vec<u8>,

        serial: u32,

        slot: u8,
    },

    Fido2HmacSecret {
        credential_id: Vec<u8>,

        salt: [u8; 32],

        rp_id: String,
    },

    PasskeyPrf {
        credential_id: Vec<u8>,

        salt: [u8; 32],

        rp_id: String,

        label: String,
    },

    AndroidKeystore {
        public_key: Vec<u8>,

        key_handle: String,

        /// 1 writes `ragedroid-keystore-v1`, 2 writes `ragedroid-keystore-v2`.
        #[serde(default = "v1", skip_serializing_if = "is_v1")]
        stanza_version: u8,
    },

    SoftwarePassphrase {
        armored_pubkey: crate::ArmoredAgeRecipient,
    },
}

fn v1() -> u8 {
    1
}

fn is_v1(v: &u8) -> bool {
    *v == 1
}

impl Recipient {
    pub fn x25519_public_key(&self) -> Option<&[u8; 32]> {
        match self {
            Self::X25519 { public_key } | Self::YubiKeyPiv { public_key, .. } => Some(public_key),
            Self::AndroidKeystore { .. }
            | Self::YubiKeyPivP256 { .. }
            | Self::Fido2HmacSecret { .. }
            | Self::PasskeyPrf { .. }
            | Self::SoftwarePassphrase { .. } => None,
        }
    }

    pub fn p256_public_key(&self) -> Option<&[u8]> {
        match self {
            Self::AndroidKeystore { public_key, .. } | Self::YubiKeyPivP256 { public_key, .. } => {
                Some(public_key.as_slice())
            }
            _ => None,
        }
    }
}
