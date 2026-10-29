//! Property tests: round trips over arbitrary plaintexts and recipient sets,
//! and every parser fed arbitrary input without panicking.

use age::secrecy::ExposeSecret;
use proptest::prelude::*;
#[cfg(feature = "bitwarden")]
use ragewarden_core::Type2EncString;
#[cfg(feature = "bitwarden")]
use ragewarden_core::bitwarden::decrypt_type2;
use ragewarden_core::stanza_format as sf;
use ragewarden_core::totp::TotpConfig;
use ragewarden_core::{
    AgeBlob, ArmoredAgeSecret, Identity, Recipient, Stanza, decrypt, encrypt, parse_header_stanzas,
    software_passphrase_identity,
};

fn software_pair() -> (Recipient, Box<dyn Identity>) {
    let id = age::x25519::Identity::generate();
    let public_key =
        ragewarden_core::bech32::decode_age_x25519(&id.to_public().to_string()).unwrap();
    let armored = ArmoredAgeSecret::from_trusted(id.to_string().expose_secret().to_string());
    (
        Recipient::X25519 { public_key },
        Box::new(software_passphrase_identity(&armored).unwrap()),
    )
}

fn arb_tag() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::sample::select(sf::RECIPIENT_TAGS.to_vec()).prop_map(str::to_string),
        "[a-z0-9-]{0,24}",
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn any_plaintext_opens_with_any_one_of_its_recipients(
        plaintext in prop::collection::vec(any::<u8>(), 0..4096),
        n in 1usize..4,
    ) {
        let pairs: Vec<_> = (0..n).map(|_| software_pair()).collect();
        let recipients: Vec<Recipient> = pairs.iter().map(|(r, _)| r.clone()).collect();
        let blob = encrypt(&plaintext, &recipients).unwrap();
        for (_, identity) in pairs {
            let got = decrypt(&blob, &[identity]).unwrap();
            prop_assert_eq!(got.as_slice(), plaintext.as_slice());
        }
    }

    #[test]
    fn a_non_recipient_never_opens_the_blob(plaintext in prop::collection::vec(any::<u8>(), 0..512)) {
        let (r, _) = software_pair();
        let (_, stranger) = software_pair();
        let blob = encrypt(&plaintext, &[r]).unwrap();
        prop_assert!(decrypt(&blob, &[stranger]).is_err());
    }

    #[test]
    fn stanza_parsers_reject_arbitrary_input_without_panicking(
        tag in arb_tag(),
        args in prop::collection::vec("[A-Za-z0-9+/_=.-]{0,48}", 0..6),
        body in prop::collection::vec(any::<u8>(), 0..64),
        share in any::<[u8; 32]>(),
        key33 in prop::collection::vec(any::<u8>(), 33),
    ) {
        let s = Stanza { tag, args, body };
        let _ = sf::piv_stanza_kind(&s);
        let _ = sf::piv_x25519_ephemeral_pub(&s);
        let _ = sf::piv_x25519_recipient_tag(&s);
        let _ = sf::decrypt_piv_x25519_with_ecdh_share(&s, &share, Some(&share));
        let _ = sf::decrypt_piv_x25519_with_ecdh_share(&s, &share, None);
        let _ = sf::piv_ec_p256_ephemeral_pub(&s);
        let _ = sf::piv_ec_p256_recipient_tag(&s);
        let _ = sf::decrypt_piv_ec_p256_with_ecdh_share(&s, &share, &key33);
        let _ = sf::ragedroid_keystore_key_handle(&s);
        let _ = sf::ragedroid_keystore_ephemeral_pub(&s);
        let _ = sf::decrypt_ragedroid_keystore_with_ecdh_share(&s, &share, Some(&key33));
        let _ = sf::fido2_hmac_credential_id(&s);
        let _ = sf::fido2_hmac_salt(&s);
        let _ = sf::fido2_hmac_wrap_salt(&s);
        let _ = sf::decrypt_fido2_hmac_with_prf(&s, &share);
        let _ = sf::webauthn_prf_credential_id(&s);
        let _ = sf::webauthn_prf_salt(&s);
        let _ = sf::webauthn_prf_wrap_salt(&s);
        let _ = sf::decrypt_webauthn_prf_with_prf(&s, &share);
        let _ = sf::is_legacy_prf_wrap(&s);
        let _ = sf::is_valid_p256_sec1_compressed(&key33);
    }

    #[test]
    fn arbitrary_bytes_are_never_a_panic_as_an_age_header(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let blob = AgeBlob::from_bytes(bytes);
        let _ = parse_header_stanzas(&blob);
        let _ = ragewarden_core::legacy_prf_wraps(&blob);
        prop_assert!(decrypt(&blob, &[software_pair().1]).is_err());
    }

    #[cfg(feature = "bitwarden")]
    #[test]
    fn arbitrary_encstrings_are_classified_and_refused_without_panicking(
        s in ".{0,160}",
        enc in any::<[u8; 32]>(),
        mac in any::<[u8; 32]>(),
    ) {
        prop_assert!(decrypt_type2(&s, &enc, &mac).is_err());
        let t: Type2EncString = serde_json::from_value(serde_json::Value::String(s.clone())).unwrap();
        prop_assert_eq!(t.as_str(), s.as_str());
        let _ = t.as_type2();
    }

    #[test]
    fn arbitrary_totp_input_is_never_a_panic(s in ".{0,120}") {
        let _ = TotpConfig::from_base32_secret(&s);
        let _ = TotpConfig::from_otpauth_uri(&s);
        let _ = ragewarden_core::totp::generate_for_uri_or_secret(&s);
    }
}
