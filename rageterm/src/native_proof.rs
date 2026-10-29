//! native-unwrap-proof-v1, the host half of ragemanifest's
//! `ext/glue/native-proof.js`: the device signs a fresh per-unwrap challenge
//! together with the stanza and what the key is for, so the browser can check
//! that this unwrap, not some earlier one, was made by a key the device holds.
//!
//! Two proof kinds. A P-256 PIV slot signs the message itself (ES256, raw
//! r||s). A FIDO2 credential signs its assertion, `authenticatorData ||
//! clientDataHash`, with clientDataHash = SHA-256(message), so the browser
//! checks that signature and the UP flag in authenticatorData.

use std::cell::RefCell;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROOF_VERSION: &str = "ragewarden-native-unwrap-v1";
pub const KIND_FIDO2_ASSERTION: &str = "fido2-assertion";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnwrapProof {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub alg: String,
    pub public_key: String,
    #[serde(
        rename = "authenticatorData",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub authenticator_data: Option<String>,
    pub signature: String,
}

/// The exact bytes `proofMessage()` builds, from the stanza as the browser
/// sent it (body still base64).
pub fn message(
    challenge: &str,
    tag: &str,
    args: &[String],
    body_b64: &str,
    action: &str,
    destination: &str,
) -> Vec<u8> {
    let body = format!("{tag}\n{}\n{body_b64}", args.join(" "));
    let body_hash = hex::encode(Sha256::digest(body.as_bytes()));
    [
        PROOF_VERSION,
        challenge,
        tag,
        &body_hash,
        action,
        destination,
    ]
    .join("\n")
    .into_bytes()
}

pub fn digest(message: &[u8]) -> [u8; 32] {
    Sha256::digest(message).into()
}

/// What a device signed for the native-host unwrap in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceSignature {
    /// A P-256 PIV slot's ES256 signature over the message, and its
    /// compressed public key.
    Piv {
        signature: [u8; 64],
        public_key: [u8; 33],
    },
    /// A FIDO2 assertion over clientDataHash = SHA-256(message), and the
    /// credential's uncompressed public key.
    Fido2 {
        authenticator_data: Vec<u8>,
        signature: [u8; 64],
        public_key: [u8; 65],
    },
}

impl DeviceSignature {
    pub fn into_proof(self) -> Result<UnwrapProof, String> {
        Ok(match self {
            DeviceSignature::Piv {
                signature,
                public_key,
            } => UnwrapProof {
                kind: None,
                alg: "ES256".into(),
                public_key: B64.encode(spki_der(&public_key)?),
                authenticator_data: None,
                signature: B64.encode(signature),
            },
            DeviceSignature::Fido2 {
                authenticator_data,
                signature,
                public_key,
            } => UnwrapProof {
                kind: Some(KIND_FIDO2_ASSERTION.into()),
                alg: "ES256".into(),
                public_key: B64.encode(spki_der(&public_key)?),
                authenticator_data: Some(B64.encode(authenticator_data)),
                signature: B64.encode(signature),
            },
        })
    }
}

/// The SPKI DER of a SEC1 P-256 point (compressed or uncompressed), the form
/// `attestationPublicKey` publishes.
pub fn spki_der(sec1: &[u8]) -> Result<Vec<u8>, String> {
    use p256::pkcs8::EncodePublicKey;
    p256::PublicKey::from_sec1_bytes(sec1)
        .map_err(|e| format!("not a P-256 point: {e}"))?
        .to_public_key_der()
        .map(|d| d.as_bytes().to_vec())
        .map_err(|e| e.to_string())
}

/// [`spki_der`], base64 as the registry carries it.
pub fn attestation_key(sec1: &[u8]) -> Option<String> {
    spki_der(sec1).ok().map(|d| B64.encode(d))
}

/// A DER ECDSA signature (what CTAP2 returns) as raw r||s.
pub fn raw_signature(der: &[u8]) -> Result<[u8; 64], String> {
    p256::ecdsa::Signature::from_der(der)
        .map(|s| s.to_bytes().into())
        .map_err(|e| format!("not a DER ECDSA signature: {e}"))
}

thread_local! {
    static PENDING: RefCell<Option<Pending>> = const { RefCell::new(None) };
}

struct Pending {
    message: Vec<u8>,
    signed: Option<DeviceSignature>,
}

/// Run an unwrap with `message` pending. The device that answers it signs the
/// message in the same session (one PIN entry; for FIDO2 the very assertion
/// that yields the hmac-secret), and the signature comes back beside the
/// result; a device that cannot sign leaves it `None`.
pub fn unwrap_with_proof<T>(
    message: Vec<u8>,
    unwrap: impl FnOnce() -> T,
) -> (T, Option<DeviceSignature>) {
    PENDING.with(|p| {
        *p.borrow_mut() = Some(Pending {
            message,
            signed: None,
        })
    });
    let out = unwrap();
    let signed = PENDING
        .with(|p| p.borrow_mut().take())
        .and_then(|p| p.signed);
    (out, signed)
}

/// The message a device should sign for the unwrap in progress, if any.
pub fn pending_message() -> Option<Vec<u8>> {
    PENDING.with(|p| p.borrow().as_ref().map(|p| p.message.clone()))
}

pub fn record(signature: DeviceSignature) {
    PENDING.with(|p| {
        if let Some(p) = p.borrow_mut().as_mut() {
            p.signed = Some(signature);
        }
    });
}

fn b64_bytes(s: &str) -> Option<Vec<u8>> {
    B64.decode(s.replace('-', "+").replace('_', "/")).ok()
}

/// `verifyUnwrapProof()` ported, over the `message()` the browser rebuilds:
/// `Ok(true)` attested, `Ok(false)` an unsigned reply with no trusted key,
/// `Err` a refusal.
#[cfg_attr(not(test), allow(dead_code))]
pub fn verify(
    proof: Option<&UnwrapProof>,
    message: &[u8],
    trusted_keys: &[String],
) -> Result<bool, String> {
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::DecodePublicKey;
    let Some(proof) = proof else {
        return if trusted_keys.is_empty() {
            Ok(false)
        } else {
            Err("this recipient publishes an attestation key and the host sent no proof".into())
        };
    };
    if proof.alg != "ES256" {
        return Err(format!("unsupported proof alg {}", proof.alg));
    }
    if !trusted_keys.contains(&proof.public_key) {
        return Err("the proof is signed by a key no registry entry publishes".into());
    }
    let spki = b64_bytes(&proof.public_key).ok_or("public_key is not base64")?;
    let key = p256::ecdsa::VerifyingKey::from_public_key_der(&spki)
        .map_err(|e| format!("public_key: {e}"))?;
    let sig_bytes = b64_bytes(&proof.signature).ok_or("signature is not base64")?;
    let sig =
        p256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|e| format!("signature: {e}"))?;
    let signed = match proof.kind.as_deref() {
        None => message.to_vec(),
        Some(KIND_FIDO2_ASSERTION) => {
            let auth = proof
                .authenticator_data
                .as_deref()
                .and_then(b64_bytes)
                .ok_or("a FIDO2 proof needs authenticatorData")?;
            if auth.len() < 37 {
                return Err("authenticatorData is shorter than 37 bytes".into());
            }
            if auth[32] & 0x01 == 0 {
                return Err("the assertion does not carry the user-presence flag".into());
            }
            [auth.as_slice(), &digest(message)].concat()
        }
        Some(other) => return Err(format!("unsupported proof kind {other}")),
    };
    key.verify(&signed, &sig)
        .map_err(|_| {
            "the touch proof does not verify for this challenge, stanza and destination".into()
        })
        .map(|()| true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The proof vector `ragemanifest/tests/unit/native-proof.test.mjs`
    /// verifies too: a fixed P-256 key (d = 0x11..11), one message, a PIV
    /// proof and a FIDO2 assertion proof over it (RFC 6979 signatures).
    fn vector_message() -> Vec<u8> {
        message(
            "dmVjdG9yLWNoYWxsZW5nZQ==",
            "piv-p256",
            &["AbCdEf".into(), "Ag".into()],
            "Ym9keQ",
            "autofill",
            "login.example.test",
        )
    }

    const VECTOR_SPKI: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAhfmF/C2RDkoJ4+WmZ5pojpPLBUr321s32bluAKC1O0ZSn3ry5dxLS3aPKhaqHZaVvRfx1hZllLyiXxlMG5XlA==";
    const VECTOR_PIV_SIG: &str =
        "vzmVzoZnX0/C5uYhrnk31YmbQDmdNjsTali1T8l/omNWh2xFrK3Q/ttJ5nG7jUSgIFUTjDVhy4eB5KKNi+Rnnw==";
    const VECTOR_FIDO_AUTH: &str = "W1FavAM2GKNCKyuyNuk48flkj12XcmOu3tnVbkWma/4BAAAAAA==";
    const VECTOR_FIDO_SIG: &str =
        "OtwPMX8PfqdbxBDNihJUth+5vXvQZtMiIDE5CedxG2zjve8Pb4+6Gh4BraxwPLuv5YpMRn2fEnEpXP0KBW0XYw==";

    fn vector_proofs() -> (UnwrapProof, UnwrapProof) {
        let piv = UnwrapProof {
            kind: None,
            alg: "ES256".into(),
            public_key: VECTOR_SPKI.into(),
            authenticator_data: None,
            signature: VECTOR_PIV_SIG.into(),
        };
        let fido = UnwrapProof {
            kind: Some(KIND_FIDO2_ASSERTION.into()),
            authenticator_data: Some(VECTOR_FIDO_AUTH.into()),
            signature: VECTOR_FIDO_SIG.into(),
            ..piv.clone()
        };
        (piv, fido)
    }

    #[test]
    fn the_cross_client_vector_verifies_and_regenerates() {
        use p256::ecdsa::{Signature, SigningKey, signature::Signer};
        use p256::elliptic_curve::sec1::ToSec1Point;
        let (piv, fido) = vector_proofs();
        let m = vector_message();
        let trusted = [VECTOR_SPKI.to_string()];
        assert_eq!(verify(Some(&piv), &m, &trusted), Ok(true));
        assert_eq!(verify(Some(&fido), &m, &trusted), Ok(true));

        let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
        let point = key.verifying_key().as_affine().to_sec1_point(false);
        assert_eq!(attestation_key(point.as_bytes()).unwrap(), VECTOR_SPKI);
        let auth = B64.decode(VECTOR_FIDO_AUTH).unwrap();
        let fido_sig: Signature = key.sign(&[auth.as_slice(), &digest(&m)].concat());
        assert_eq!(B64.encode(fido_sig.to_bytes()), VECTOR_FIDO_SIG);
        let piv_sig: Signature = key.sign(&m);
        assert_eq!(B64.encode(piv_sig.to_bytes()), VECTOR_PIV_SIG);
    }

    #[test]
    fn a_fido2_proof_needs_the_up_flag_its_own_message_and_a_published_key() {
        let (_, fido) = vector_proofs();
        let m = vector_message();
        let trusted = [VECTOR_SPKI.to_string()];
        let mut auth = B64.decode(VECTOR_FIDO_AUTH).unwrap();
        auth[32] = 0x00;
        let no_up = UnwrapProof {
            authenticator_data: Some(B64.encode(&auth)),
            ..fido.clone()
        };
        assert!(
            verify(Some(&no_up), &m, &trusted)
                .unwrap_err()
                .contains("user-presence")
        );
        let other = message(
            "dmVjdG9yLWNoYWxsZW5nZQ==",
            "piv-p256",
            &["AbCdEf".into(), "Ag".into()],
            "Ym9keQ",
            "autofill",
            "evil.example.test",
        );
        assert!(verify(Some(&fido), &other, &trusted).is_err());
        assert!(verify(Some(&fido), &m, &["c29tZW9uZSBlbHNl".into()]).is_err());
        let piv_as_fido = UnwrapProof {
            signature: VECTOR_PIV_SIG.into(),
            ..fido
        };
        assert!(verify(Some(&piv_as_fido), &m, &trusted).is_err());
    }

    #[test]
    fn the_message_matches_proof_message_in_native_proof_js() {
        let m = message(
            "Q0hBTA==",
            "piv-p256",
            &["abcd".into(), "efgh".into()],
            "Ym9keQ",
            "autofill",
            "github.com",
        );
        let body_hash = hex::encode(Sha256::digest(b"piv-p256\nabcd efgh\nYm9keQ"));
        assert_eq!(
            String::from_utf8(m).unwrap(),
            format!(
                "ragewarden-native-unwrap-v1\nQ0hBTA==\npiv-p256\n{body_hash}\nautofill\ngithub.com"
            )
        );
    }
}
