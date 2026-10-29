use ragewarden_core::stanza_format::{
    TAG_FIDO2_HMAC, TAG_PIV_P256, TAG_PIV_X25519_V2, TAG_WEBAUTHN_PRF_V1, TAG_X25519,
    decrypt_webauthn_prf_with_prf, webauthn_prf_credential_id,
};
use ragewarden_core::{
    AgeBlob, DecryptError, FileKey, Identity, IdentityError, Plaintext, Stanza, decrypt,
};
use zeroize::Zeroize;

pub struct SpecificPasskeyPrfIdentity {
    pub credential_id: Vec<u8>,
    pub prf_output: [u8; 32],
}

impl Drop for SpecificPasskeyPrfIdentity {
    fn drop(&mut self) {
        self.prf_output.zeroize();
    }
}

impl Identity for SpecificPasskeyPrfIdentity {
    fn try_unwrap_stanza(&self, stanza: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        if stanza.tag != TAG_WEBAUTHN_PRF_V1 {
            return Ok(None);
        }
        let stanza_cred = match webauthn_prf_credential_id(stanza) {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };
        if stanza_cred != self.credential_id {
            return Ok(None);
        }
        match decrypt_webauthn_prf_with_prf(stanza, &self.prf_output) {
            Ok(key) => Ok(Some(key)),
            Err(e) => Err(IdentityError::Crypto(format!("webauthn-prf-v1: {e}"))),
        }
    }

    fn display(&self) -> &str {
        "passkey-prf"
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StanzaSummary {
    #[serde(rename = "prfCredentialIdsB64")]
    pub prf_credential_ids_b64: Vec<String>,
    pub x25519: usize,
    pub piv: usize,
    pub fido2: usize,
    pub other: usize,
}

pub fn summarize_stanzas(stanzas: &[Stanza]) -> StanzaSummary {
    use base64::{Engine, engine::general_purpose::STANDARD as B64};
    let mut out = StanzaSummary::default();
    for s in stanzas.iter().filter(|s| !s.tag.ends_with("-grease")) {
        match s.tag.as_str() {
            TAG_WEBAUTHN_PRF_V1 => match webauthn_prf_credential_id(s) {
                Ok(id) => out.prf_credential_ids_b64.push(B64.encode(id)),
                Err(_) => out.other += 1,
            },
            TAG_X25519 => out.x25519 += 1,
            TAG_PIV_P256 | TAG_PIV_X25519_V2 => out.piv += 1,
            TAG_FIDO2_HMAC => out.fido2 += 1,
            _ => out.other += 1,
        }
    }
    out
}

pub enum SoftwareFirst {
    Opened(Plaintext),
    AskPrf,
    TapUnavailable,
    NoIdentity,
    Failed(DecryptError),
}

pub fn decrypt_software_first(
    blob: &AgeBlob,
    software: &[Box<dyn Identity>],
    blob_has_prf_stanza: bool,
    prf_callback_available: bool,
) -> SoftwareFirst {
    if !software.is_empty() {
        match decrypt(blob, software) {
            Ok(pt) => return SoftwareFirst::Opened(pt),
            Err(DecryptError::NoMatchingIdentity) => {}
            Err(other) => return SoftwareFirst::Failed(other),
        }
    }
    if blob_has_prf_stanza {
        return if prf_callback_available {
            SoftwareFirst::AskPrf
        } else if software.is_empty() {
            SoftwareFirst::TapUnavailable
        } else {
            SoftwareFirst::Failed(DecryptError::NoMatchingIdentity)
        };
    }
    if software.is_empty() {
        SoftwareFirst::NoIdentity
    } else {
        SoftwareFirst::Failed(DecryptError::NoMatchingIdentity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use ragewarden_core::{
        ArmoredAgeRecipient, ArmoredAgeSecret, PrfEntry, Recipient, encrypt, encrypt_with_prf,
        parse_header_stanzas, software_passphrase_identity,
    };

    fn software_pair() -> (Recipient, Box<dyn Identity>) {
        let id = age::x25519::Identity::generate();
        let recipient = Recipient::SoftwarePassphrase {
            armored_pubkey: ArmoredAgeRecipient::from_trusted(id.to_public().to_string()),
        };
        let secret = ArmoredAgeSecret::from_trusted(id.to_string().expose_secret().to_string());
        (
            recipient,
            Box::new(software_passphrase_identity(&secret).unwrap()),
        )
    }

    fn passkey(cred: &[u8], salt: [u8; 32]) -> Recipient {
        Recipient::PasskeyPrf {
            credential_id: cred.to_vec(),
            salt,
            rp_id: "ext-id".into(),
            label: "test".into(),
        }
    }

    #[test]
    fn software_secret_opens_without_asking_for_a_prf_tap() {
        let (sw_r, sw_id) = software_pair();
        let prf = [7u8; 32];
        let salt = [9u8; 32];
        let table = [PrfEntry {
            rp_id: "ext-id",
            credential_id: &[],
            salt: &salt,
            prf_output: &prf,
        }];
        let blob = encrypt_with_prf(b"s3cret", &[sw_r, passkey(b"cred-a", salt)], &table).unwrap();
        match decrypt_software_first(&blob, &[sw_id], true, true) {
            SoftwareFirst::Opened(pt) => assert_eq!(&pt[..], b"s3cret"),
            _ => panic!("software identity should open the blob before any PRF tap"),
        }
    }

    #[test]
    fn prf_is_asked_only_when_software_misses() {
        let (_, sw_id) = software_pair();
        let prf = [7u8; 32];
        let salt = [9u8; 32];
        let table = [PrfEntry {
            rp_id: "ext-id",
            credential_id: &[],
            salt: &salt,
            prf_output: &prf,
        }];
        let blob = encrypt_with_prf(b"s3cret", &[passkey(b"cred-a", salt)], &table).unwrap();
        assert!(matches!(
            decrypt_software_first(&blob, &[sw_id], true, true),
            SoftwareFirst::AskPrf
        ));
        assert!(matches!(
            decrypt_software_first(&blob, &[], true, false),
            SoftwareFirst::TapUnavailable
        ));
    }

    #[test]
    fn nothing_offered_is_no_identity() {
        let (sw_r, _) = software_pair();
        let blob = encrypt(b"x", &[sw_r]).unwrap();
        assert!(matches!(
            decrypt_software_first(&blob, &[], false, false),
            SoftwareFirst::NoIdentity
        ));
    }

    #[test]
    fn specific_passkey_identity_opens_only_its_own_credential() {
        let prf = [7u8; 32];
        let salt = [9u8; 32];
        let table = [PrfEntry {
            rp_id: "ext-id",
            credential_id: &[],
            salt: &salt,
            prf_output: &prf,
        }];
        let blob = encrypt_with_prf(b"s3cret", &[passkey(b"cred-a", salt)], &table).unwrap();
        let mine: Box<dyn Identity> = Box::new(SpecificPasskeyPrfIdentity {
            credential_id: b"cred-a".to_vec(),
            prf_output: prf,
        });
        assert_eq!(&decrypt(&blob, &[mine]).unwrap()[..], b"s3cret");
        let other: Box<dyn Identity> = Box::new(SpecificPasskeyPrfIdentity {
            credential_id: b"cred-b".to_vec(),
            prf_output: prf,
        });
        assert!(matches!(
            decrypt(&blob, &[other]),
            Err(DecryptError::NoMatchingIdentity)
        ));
    }

    #[test]
    fn summary_names_prf_credentials_and_counts_the_rest() {
        let (sw_r, _) = software_pair();
        let prf = [7u8; 32];
        let salt = [9u8; 32];
        let table = [PrfEntry {
            rp_id: "ext-id",
            credential_id: &[],
            salt: &salt,
            prf_output: &prf,
        }];
        let blob = encrypt_with_prf(b"s", &[sw_r, passkey(b"cred-a", salt)], &table).unwrap();
        let s = summarize_stanzas(&parse_header_stanzas(&blob).unwrap());
        use base64::{Engine, engine::general_purpose::STANDARD as B64};
        assert_eq!(s.prf_credential_ids_b64, vec![B64.encode(b"cred-a")]);
        assert_eq!(s.x25519, 1);
    }
}
