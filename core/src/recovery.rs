use age::secrecy::ExposeSecret;
use bip39::Mnemonic;
use hkdf::Hkdf;
use rand_core::Rng;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{ArmoredAgeRecipient, ArmoredAgeSecret};

const RECOVERY_HKDF_INFO: &[u8] = b"ragewarden-recovery-v1";

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("mnemonic: {0}")]
    Mnemonic(String),

    #[error("identity: {0}")]
    Identity(String),
}

pub struct GeneratedRecovery {
    pub mnemonic: Mnemonic,

    pub armored_pubkey: ArmoredAgeRecipient,

    pub armored_secret: ArmoredAgeSecret,
}

pub fn generate() -> Result<GeneratedRecovery, RecoveryError> {
    let mut entropy = [0u8; 32];
    rand::rng().fill_bytes(&mut entropy);
    let mnemonic =
        Mnemonic::from_entropy(&entropy).map_err(|e| RecoveryError::Mnemonic(e.to_string()))?;
    let identity = derive_identity(&mnemonic)?;
    let armored_pubkey = ArmoredAgeRecipient::from_trusted(identity.to_public().to_string());
    let armored_secret = ArmoredAgeSecret::from_zeroizing(Zeroizing::new(
        identity.to_string().expose_secret().to_string(),
    ));
    Ok(GeneratedRecovery {
        mnemonic,
        armored_pubkey,
        armored_secret,
    })
}

pub fn from_mnemonic(mnemonic: &Mnemonic) -> Result<age::x25519::Identity, RecoveryError> {
    derive_identity(mnemonic)
}

pub fn from_phrase(phrase: &str) -> Result<age::x25519::Identity, RecoveryError> {
    let mnemonic: Mnemonic = phrase
        .parse()
        .map_err(|e: bip39::Error| RecoveryError::Mnemonic(e.to_string()))?;
    derive_identity(&mnemonic)
}

fn derive_identity(mnemonic: &Mnemonic) -> Result<age::x25519::Identity, RecoveryError> {
    let seed = mnemonic.to_seed("");
    let hk = Hkdf::<Sha256>::new(None, &seed);
    let mut secret_bytes = Zeroizing::new([0u8; 32]);
    hk.expand(RECOVERY_HKDF_INFO, secret_bytes.as_mut())
        .expect("32 bytes is well within HKDF expand bounds");

    let armored = crate::bech32::encode_age_secret_key(&secret_bytes);
    let id: age::x25519::Identity = armored
        .parse()
        .map_err(|e: &str| RecoveryError::Identity(e.to_string()))?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_recover_via_mnemonic_yields_same_identity() {
        let generated = generate().expect("generate");
        let recovered = from_mnemonic(&generated.mnemonic).expect("recover");

        assert_eq!(
            generated.armored_pubkey.as_str(),
            recovered.to_public().to_string()
        );
    }

    #[test]
    fn from_phrase_round_trips() {
        let generated = generate().expect("generate");
        let phrase = generated.mnemonic.to_string();
        let recovered = from_phrase(&phrase).expect("recover from phrase");
        assert_eq!(
            generated.armored_pubkey.as_str(),
            recovered.to_public().to_string()
        );
    }

    #[test]
    fn invalid_phrase_errors() {
        let res = from_phrase("not a valid bip39 phrase");
        match res {
            Ok(_) => panic!("expected error from invalid phrase"),
            Err(RecoveryError::Mnemonic(_)) => {}
            Err(other) => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn mnemonic_is_24_words() {
        let generated = generate().expect("generate");
        let phrase = generated.mnemonic.to_string();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn deterministic_derivation_locked_by_info_string() {
        let generated = generate().expect("generate");
        let a = from_mnemonic(&generated.mnemonic).unwrap();
        let b = from_mnemonic(&generated.mnemonic).unwrap();
        assert_eq!(a.to_public().to_string(), b.to_public().to_string());
    }
}
