//! Pins the *scope* of a PRF evaluation -- DEFECT B, a KNOWN OPEN GAP.
//!
//! `SECURITY.md` "Known gaps" and `DESIGN.md` §0e both say the PRF salt is
//! per-recipient rather than per-secret, so "no bulk siphon" is not a
//! cryptographic property for `webauthn-prf-v1` / `fido2-hmac` recipients.
//! Nothing executable held that statement to account, so the per-stanza
//! `wrap_salt` fix could be -- and was -- read as having closed it. It did not:
//! `wrap_salt` stopped body-key reuse across secrets, which is a different
//! bug.
//!
//! These tests assert the *current* behaviour, gap included. When the gap is
//! actually closed (a per-secret PRF salt under a new stanza tag) they will
//! fail, which is the intent: the fix cannot land as a documentation edit.

use base64::{engine::general_purpose::STANDARD_NO_PAD as B64, Engine};
use ragewarden_core::stanza_format::{
    decrypt_webauthn_prf_with_prf, encrypt_fido2_hmac_with_prf, encrypt_webauthn_prf_with_prf,
    webauthn_prf_wrap_salt,
};

const CRED: &[u8] = b"credential-1";
const RP: &str = "ragewarden";

/// The PRF salt is a field of the *recipient* (`WireEntry::fido2_salt`, fixed
/// at enrollment), so `prf_output` is one constant for every secret ever
/// wrapped to that recipient.
#[test]
fn one_captured_prf_output_still_unwraps_every_secret_for_that_recipient() {
    let prf_salt = [0x11u8; 32];
    let prf_output = [0x99u8; 32];

    let fk_a = [0xAAu8; 16];
    let fk_b = [0xBBu8; 16];

    let a = encrypt_webauthn_prf_with_prf(&fk_a, CRED, &prf_salt, RP, &prf_output);
    let b = encrypt_webauthn_prf_with_prf(&fk_b, CRED, &prf_salt, RP, &prf_output);

    // The wrap salt IS fresh per stanza -- that part of the fix works.
    let ws_a = webauthn_prf_wrap_salt(&a).unwrap().unwrap();
    let ws_b = webauthn_prf_wrap_salt(&b).unwrap().unwrap();
    assert_ne!(ws_a, ws_b);

    // ...and it is PUBLIC, sitting in args[3] of the stanza the server stores.
    assert_eq!(a.args.len(), 4);
    assert_eq!(a.args[3], B64.encode(ws_a));
    assert_eq!(b.args[3], B64.encode(ws_b));

    // So a single captured `prf_output` -- one observation of one unwrap --
    // opens both, and every other stanza for this credential, with no further
    // authenticator interaction. THIS IS THE OPEN GAP.
    assert_eq!(&*decrypt_webauthn_prf_with_prf(&a, &prf_output).unwrap(), &fk_a);
    assert_eq!(&*decrypt_webauthn_prf_with_prf(&b, &prf_output).unwrap(), &fk_b);
}

/// What `wrap_salt` did buy: two secrets no longer share a body key, so the
/// ciphertexts differ even for identical file keys. Keystream reuse is gone;
/// siphon resistance is not the same property.
#[test]
fn wrap_salt_removed_body_key_reuse_which_is_a_different_property() {
    let prf_salt = [0x11u8; 32];
    let prf_output = [0x99u8; 32];
    let same_file_key = [0x77u8; 16];

    let a = encrypt_webauthn_prf_with_prf(&same_file_key, CRED, &prf_salt, RP, &prf_output);
    let b = encrypt_webauthn_prf_with_prf(&same_file_key, CRED, &prf_salt, RP, &prf_output);
    assert_ne!(a.body, b.body, "identical file keys must not produce identical bodies");

    let f = encrypt_fido2_hmac_with_prf(&same_file_key, CRED, &prf_salt, RP, &prf_output);
    let g = encrypt_fido2_hmac_with_prf(&same_file_key, CRED, &prf_salt, RP, &prf_output);
    assert_ne!(f.body, g.body);
}

/// The contrast that shows the gap is specific to PRF recipients: a per-secret
/// PRF salt would give PRF stanzas what `piv-p256` and `ragedroid-keystore-v1`
/// already have -- a fresh device operation per unwrap.
#[test]
fn a_per_secret_prf_salt_would_confine_a_capture_to_one_secret() {
    let prf_output_for_secret_a = [0x01u8; 32];
    let prf_output_for_secret_b = [0x02u8; 32];
    let salt_a = [0xA1u8; 32];
    let salt_b = [0xB2u8; 32];

    let fk_a = [0xAAu8; 16];
    let fk_b = [0xBBu8; 16];

    let a = encrypt_webauthn_prf_with_prf(&fk_a, CRED, &salt_a, RP, &prf_output_for_secret_a);
    let b = encrypt_webauthn_prf_with_prf(&fk_b, CRED, &salt_b, RP, &prf_output_for_secret_b);

    assert_eq!(&*decrypt_webauthn_prf_with_prf(&a, &prf_output_for_secret_a).unwrap(), &fk_a);
    assert!(
        decrypt_webauthn_prf_with_prf(&b, &prf_output_for_secret_a).is_err(),
        "capturing secret A's PRF output must not open secret B",
    );

    // The primitive already supports this; what is missing is (a) a stanza
    // shape that carries a per-secret salt distinctly from the recipient's
    // enrollment salt, and (b) an encrypt API that can *request* a PRF
    // evaluation instead of being handed a precomputed table. See the write-up
    // accompanying this file.
}
