//! Ciphertexts written by the stanza formats of 2026-10-03 (before the v2 PIV
//! and keystore stanzas and per-secret PRF salts), frozen in
//! `tests/vectors/stanza_formats_v1_frozen.json`. Every later reader must keep
//! opening them; never regenerate the file.

use ragewarden_core::stanza_format::{
    PivStanzaKind, TAG_FIDO2_HMAC, TAG_RAGEDROID_KEYSTORE_V1, TAG_WEBAUTHN_PRF_V1,
    decrypt_fido2_hmac_with_prf, decrypt_piv_x25519_with_ecdh_share,
    decrypt_ragedroid_keystore_with_ecdh_share, decrypt_webauthn_prf_with_prf, piv_stanza_kind,
    piv_x25519_ephemeral_pub, ragedroid_keystore_ephemeral_pub,
};
use ragewarden_core::{
    AgeBlob, ArmoredAgeSecret, FileKey, Identity, IdentityError, Stanza, decrypt,
    software_passphrase_identity,
};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/stanza_formats_v1_frozen.json")).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

fn blob(v: &Value, name: &str) -> AgeBlob {
    AgeBlob::from_bytes(v[name]["blob"].as_str().unwrap().as_bytes().to_vec())
}

fn plaintext(v: &Value, name: &str) -> Vec<u8> {
    v[name]["plaintext"].as_str().unwrap().as_bytes().to_vec()
}

fn software(v: &Value) -> Box<dyn Identity> {
    let secret = arr32(
        v["software_x25519"]["identity_scalar_hex"]
            .as_str()
            .unwrap(),
    );
    let armored =
        ArmoredAgeSecret::from_trusted(ragewarden_core::bech32::encode_age_secret_key(&secret));
    Box::new(software_passphrase_identity(&armored).unwrap())
}

struct PivX25519 {
    secret: [u8; 32],
}

impl Identity for PivX25519 {
    fn try_unwrap_stanza(&self, s: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        if piv_stanza_kind(s) != Some(PivStanzaKind::X25519V1) {
            return Ok(None);
        }
        let eph = piv_x25519_ephemeral_pub(s).map_err(|e| IdentityError::Crypto(e.to_string()))?;
        let secret = x25519_dalek::StaticSecret::from(self.secret);
        let own = *x25519_dalek::PublicKey::from(&secret).as_bytes();
        let share = secret.diffie_hellman(&x25519_dalek::PublicKey::from(eph));
        decrypt_piv_x25519_with_ecdh_share(s, share.as_bytes(), Some(&own))
            .map(Some)
            .map_err(|e| IdentityError::Crypto(e.to_string()))
    }
    fn display(&self) -> &str {
        "frozen piv x25519"
    }
}

struct Keystore {
    secret: [u8; 32],
}

impl Identity for Keystore {
    fn try_unwrap_stanza(&self, s: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        if s.tag != TAG_RAGEDROID_KEYSTORE_V1 {
            return Ok(None);
        }
        let eph = ragedroid_keystore_ephemeral_pub(s)
            .map_err(|e| IdentityError::Crypto(e.to_string()))?;
        let share = p256_share(&self.secret, &eph);
        decrypt_ragedroid_keystore_with_ecdh_share(s, &share, None)
            .map(Some)
            .map_err(|e| IdentityError::Crypto(e.to_string()))
    }
    fn display(&self) -> &str {
        "frozen keystore"
    }
}

fn p256_share(secret: &[u8; 32], peer_sec1: &[u8]) -> [u8; 32] {
    let sk = p256::SecretKey::from_slice(secret).unwrap();
    let pk = p256::PublicKey::from_sec1_bytes(peer_sec1).unwrap();
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    shared.raw_secret_bytes().as_slice().try_into().unwrap()
}

struct Prf {
    output: [u8; 32],
}

impl Identity for Prf {
    fn try_unwrap_stanza(&self, s: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        let r = match s.tag.as_str() {
            TAG_WEBAUTHN_PRF_V1 => decrypt_webauthn_prf_with_prf(s, &self.output),
            TAG_FIDO2_HMAC => decrypt_fido2_hmac_with_prf(s, &self.output),
            _ => return Ok(None),
        };
        r.map(Some)
            .map_err(|e| IdentityError::Crypto(e.to_string()))
    }
    fn display(&self) -> &str {
        "frozen prf"
    }
}

fn opens(v: &Value, name: &str, id: Box<dyn Identity>) {
    let got = decrypt(&blob(v, name), &[id]).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(got.as_slice(), plaintext(v, name).as_slice(), "{name}");
}

#[test]
fn software_x25519_still_opens() {
    let v = vectors();
    opens(&v, "software_x25519", software(&v));
}

#[test]
fn piv_x25519_v1_still_opens() {
    let v = vectors();
    let secret = arr32(v["piv_x25519_v1"]["recipient_secret_hex"].as_str().unwrap());
    opens(&v, "piv_x25519_v1", Box::new(PivX25519 { secret }));
    opens(
        &v,
        "piv_x25519_v1_plus_software",
        Box::new(PivX25519 { secret }),
    );
    opens(&v, "piv_x25519_v1_plus_software", software(&v));
}

#[test]
fn ragedroid_keystore_v1_still_opens() {
    let v = vectors();
    let secret = arr32(
        v["ragedroid_keystore_v1"]["recipient_secret_hex"]
            .as_str()
            .unwrap(),
    );
    opens(&v, "ragedroid_keystore_v1", Box::new(Keystore { secret }));
}

#[test]
fn prf_stanzas_with_and_without_wrap_salt_still_open() {
    let v = vectors();
    let output = arr32(v["prf"]["prf_output_hex"].as_str().unwrap());
    for name in [
        "webauthn_prf_v1_wrap_salt",
        "fido2_hmac_wrap_salt",
        "webauthn_prf_v1_legacy_3arg",
        "fido2_hmac_legacy_3arg",
    ] {
        opens(&v, name, Box::new(Prf { output }));
    }
}

#[test]
fn legacy_prf_wraps_counts_only_the_pre_wrap_salt_stanzas() {
    let v = vectors();
    for (name, legacy) in [
        ("webauthn_prf_v1_legacy_3arg", 1),
        ("fido2_hmac_legacy_3arg", 1),
        ("webauthn_prf_v1_wrap_salt", 0),
        ("fido2_hmac_wrap_salt", 0),
        ("piv_x25519_v1_plus_software", 0),
    ] {
        assert_eq!(
            ragewarden_core::legacy_prf_wraps(&blob(&v, name)).unwrap(),
            legacy,
            "{name}"
        );
    }
}

#[test]
fn rewrap_moves_a_legacy_prf_secret_to_a_fresh_per_secret_stanza() {
    let v = vectors();
    let output = arr32(v["prf"]["prf_output_hex"].as_str().unwrap());
    let old = blob(&v, "webauthn_prf_v1_legacy_3arg");
    let recipient = ragewarden_core::Recipient::PasskeyPrf {
        credential_id: unhex(v["prf"]["credential_id_hex"].as_str().unwrap()),
        salt: arr32(v["prf"]["salt_hex"].as_str().unwrap()),
        rp_id: v["prf"]["rp_id"].as_str().unwrap().to_string(),
        label: "frozen".into(),
    };
    let request = &ragewarden_core::prf_requests_for(std::slice::from_ref(&recipient))[0];
    let fresh_output = [0x31u8; 32];
    let table = [ragewarden_core::PrfEntry {
        rp_id: &request.rp_id,
        credential_id: &request.credential_id,
        salt: &request.salt,
        prf_output: &fresh_output,
    }];
    let new = ragewarden_core::rewrap(
        &old,
        &[Box::new(Prf { output })],
        std::slice::from_ref(&recipient),
        &table,
    )
    .unwrap();
    assert_eq!(ragewarden_core::legacy_prf_wraps(&new).unwrap(), 0);
    let got = decrypt(
        &new,
        &[Box::new(Prf {
            output: fresh_output,
        }) as Box<dyn Identity>],
    )
    .unwrap();
    assert_eq!(
        got.as_slice(),
        plaintext(&v, "webauthn_prf_v1_legacy_3arg").as_slice()
    );
    assert!(decrypt(&new, &[Box::new(Prf { output }) as Box<dyn Identity>]).is_err());
}
