use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Recipient {
    X25519 {
        public_key: [u8; 32],
    },

    YubiKeyPiv {
        public_key: [u8; 32],

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
    },

    SoftwarePassphrase {
        armored_pubkey: crate::ArmoredAgeRecipient,
    },
}

impl Recipient {
    pub fn x25519_public_key(&self) -> Option<&[u8; 32]> {
        match self {
            Self::X25519 { public_key } | Self::YubiKeyPiv { public_key, .. } => Some(public_key),
            Self::AndroidKeystore { .. }
            | Self::Fido2HmacSecret { .. }
            | Self::PasskeyPrf { .. }
            | Self::SoftwarePassphrase { .. } => None,
        }
    }

    pub fn p256_public_key(&self) -> Option<&[u8]> {
        match self {
            Self::AndroidKeystore { public_key, .. } => Some(public_key.as_slice()),
            _ => None,
        }
    }
}
