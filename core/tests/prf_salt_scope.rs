//! The scope of one PRF evaluation. With the PRF salt fixed per recipient,
//! one captured `prf_output` unwrapped every `webauthn-prf-v1` / `fido2-hmac`
//! stanza for that recipient (bulk siphon). `prf_requests_for` draws a fresh
//! salt per write, `encrypt_with_prf` writes the evaluated salt into the
//! stanza, and every decryptor already evaluates the salt the stanza carries,
//! so each secret now needs its own authenticator evaluation.

use hmac::{Hmac, KeyInit, Mac};
use ragewarden_core::stanza_format::{
    TAG_FIDO2_HMAC, TAG_WEBAUTHN_PRF_V1, decrypt_fido2_hmac_with_prf,
    decrypt_webauthn_prf_with_prf, encrypt_fido2_hmac_with_prf, encrypt_webauthn_prf_with_prf,
    webauthn_prf_salt,
};
use ragewarden_core::{
    AgeBlob, FileKey, Identity, IdentityError, PrfEntry, Recipient, Stanza, decrypt,
    encrypt_with_prf, parse_header_stanzas, prf_requests_for,
};

const CRED: &[u8] = b"credential-1";
const RP: &str = "ragewarden";

/// A stand-in authenticator: hmac-secret is HMAC-SHA-256 under a key that
/// never leaves the device.
struct Authenticator {
    device_secret: [u8; 32],
}

impl Authenticator {
    fn evaluate(&self, salt: &[u8; 32]) -> [u8; 32] {
        let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&self.device_secret).unwrap();
        mac.update(salt);
        mac.finalize().into_bytes().into()
    }
}

fn passkey() -> Recipient {
    Recipient::PasskeyPrf {
        credential_id: CRED.to_vec(),
        salt: [0x11; 32],
        rp_id: RP.into(),
        label: "phone".into(),
    }
}

fn write(auth: &Authenticator, recipient: &Recipient, plaintext: &[u8]) -> AgeBlob {
    let requests = prf_requests_for(std::slice::from_ref(recipient));
    assert_eq!(requests.len(), 1);
    let outputs: Vec<[u8; 32]> = requests.iter().map(|r| auth.evaluate(&r.salt)).collect();
    let table: Vec<PrfEntry<'_>> = requests
        .iter()
        .zip(&outputs)
        .map(|(r, out)| PrfEntry {
            rp_id: &r.rp_id,
            credential_id: &r.credential_id,
            salt: &r.salt,
            prf_output: out,
        })
        .collect();
    encrypt_with_prf(plaintext, std::slice::from_ref(recipient), &table).unwrap()
}

fn prf_stanza(blob: &AgeBlob) -> Stanza {
    parse_header_stanzas(blob)
        .unwrap()
        .into_iter()
        .find(|s| s.tag == TAG_WEBAUTHN_PRF_V1 || s.tag == TAG_FIDO2_HMAC)
        .unwrap()
}

/// What an attacker holds after one captured evaluation: a fixed output.
struct Captured(Box<[u8; 32]>);

impl Identity for Captured {
    fn try_unwrap_stanza(&self, s: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        let r = match s.tag.as_str() {
            TAG_WEBAUTHN_PRF_V1 => decrypt_webauthn_prf_with_prf(s, &self.0),
            TAG_FIDO2_HMAC => decrypt_fido2_hmac_with_prf(s, &self.0),
            _ => return Ok(None),
        };
        r.map(Some)
            .map_err(|e| IdentityError::Crypto(e.to_string()))
    }
    fn display(&self) -> &str {
        "captured prf output"
    }
}

#[test]
fn each_write_carries_its_own_prf_salt() {
    let auth = Authenticator {
        device_secret: [0x5e; 32],
    };
    let a = write(&auth, &passkey(), b"secret A");
    let b = write(&auth, &passkey(), b"secret B");
    let (sa, sb) = (prf_stanza(&a), prf_stanza(&b));
    assert_ne!(
        webauthn_prf_salt(&sa).unwrap(),
        webauthn_prf_salt(&sb).unwrap()
    );
    assert_ne!(
        webauthn_prf_salt(&sa).unwrap(),
        [0x11; 32],
        "the enrolment salt is metadata now, not the evaluated input"
    );
}

#[test]
fn one_captured_prf_output_opens_one_secret_not_the_vault() {
    let auth = Authenticator {
        device_secret: [0x5e; 32],
    };
    let a = write(&auth, &passkey(), b"secret A");
    let b = write(&auth, &passkey(), b"secret B");

    let captured_for_a = auth.evaluate(&webauthn_prf_salt(&prf_stanza(&a)).unwrap());
    let only_a: Vec<Box<dyn Identity>> = vec![Box::new(Captured(Box::new(captured_for_a)))];
    assert_eq!(decrypt(&a, &only_a).unwrap().as_slice(), b"secret A");
    assert!(
        decrypt(&b, &only_a).is_err(),
        "secret A's evaluation must not open secret B"
    );

    let captured_for_b = auth.evaluate(&webauthn_prf_salt(&prf_stanza(&b)).unwrap());
    let only_b: Vec<Box<dyn Identity>> = vec![Box::new(Captured(Box::new(captured_for_b)))];
    assert_eq!(decrypt(&b, &only_b).unwrap().as_slice(), b"secret B");
}

#[test]
fn fido2_hmac_recipients_get_fresh_salts_too() {
    let auth = Authenticator {
        device_secret: [0x77; 32],
    };
    let r = Recipient::Fido2HmacSecret {
        credential_id: CRED.to_vec(),
        salt: [0x22; 32],
        rp_id: RP.into(),
    };
    let a = write(&auth, &r, b"a");
    let b = write(&auth, &r, b"b");
    assert_ne!(prf_stanza(&a).args[1], prf_stanza(&b).args[1]);
}

/// The per-recipient form clients wrote before still encrypts (an entry with
/// no credential id names the recipient by its enrolment salt) -- and is
/// exactly the siphonable shape, which is why clients move to
/// `prf_requests_for`.
#[test]
fn an_entry_without_a_credential_id_still_names_its_recipient_by_enrolment_salt() {
    let enrolment = [0x11u8; 32];
    let output = [0x99u8; 32];
    let table = [PrfEntry {
        rp_id: RP,
        credential_id: &[],
        salt: &enrolment,
        prf_output: &output,
    }];
    let a = encrypt_with_prf(b"a", &[passkey()], &table).unwrap();
    let b = encrypt_with_prf(b"b", &[passkey()], &table).unwrap();
    let one: Vec<Box<dyn Identity>> = vec![Box::new(Captured(Box::new(output)))];
    assert_eq!(decrypt(&a, &one).unwrap().as_slice(), b"a");
    assert_eq!(decrypt(&b, &one).unwrap().as_slice(), b"b");
}

#[test]
fn an_entry_for_another_credential_is_not_used() {
    let other_cred = b"credential-2".to_vec();
    let salt = [0x33u8; 32];
    let output = [0x44u8; 32];
    let table = [PrfEntry {
        rp_id: RP,
        credential_id: &other_cred,
        salt: &salt,
        prf_output: &output,
    }];
    assert!(encrypt_with_prf(b"x", &[passkey()], &table).is_err());
}

/// What `wrap_salt` bought on its own: two secrets no longer share a body
/// key even when the PRF output is the same.
#[test]
fn wrap_salt_removed_body_key_reuse() {
    let prf_salt = [0x11u8; 32];
    let prf_output = [0x99u8; 32];
    let same_file_key = [0x77u8; 16];

    let a = encrypt_webauthn_prf_with_prf(&same_file_key, CRED, &prf_salt, RP, &prf_output);
    let b = encrypt_webauthn_prf_with_prf(&same_file_key, CRED, &prf_salt, RP, &prf_output);
    assert_ne!(a.body, b.body);

    let f = encrypt_fido2_hmac_with_prf(&same_file_key, CRED, &prf_salt, RP, &prf_output);
    let g = encrypt_fido2_hmac_with_prf(&same_file_key, CRED, &prf_salt, RP, &prf_output);
    assert_ne!(f.body, g.body);
}
