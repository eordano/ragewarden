use crate::*;

#[test]
fn x25519_round_trip_software_identity() {
    let identity = age::x25519::Identity::generate();
    let public_key_bytes = pubkey_bytes_of(&identity);

    let recipients = vec![Recipient::X25519 {
        public_key: public_key_bytes,
    }];
    let plaintext = b"hunter2-but-better";
    let blob = encrypt(plaintext, &recipients).expect("encrypt should succeed");

    let s = blob.as_str().expect("armored age output is UTF-8");
    assert!(
        s.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"),
        "armor header missing"
    );
    assert!(
        s.trim_end().ends_with("-----END AGE ENCRYPTED FILE-----"),
        "armor footer missing"
    );

    use age::secrecy::ExposeSecret;
    let armored = crate::ArmoredAgeSecret::from_trusted(
        identity.to_string().expose_secret().to_string(),
    );
    let sw = software_passphrase_identity(&armored).expect("software identity build");
    let identities: Vec<Box<dyn Identity>> = vec![Box::new(sw)];

    let recovered = decrypt(&blob, &identities).expect("decrypt should succeed");
    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn no_recipients_is_an_error() {
    let err = encrypt(b"x", &[]).unwrap_err();
    assert!(matches!(err, EncryptError::NoRecipients));
}

#[test]
fn fido2_recipient_without_prf_table_errors() {
    let r = Recipient::Fido2HmacSecret {
        credential_id: vec![1, 2, 3],
        salt: [0u8; 32],
        rp_id: "ragewarden".into(),
    };
    let err = encrypt(b"x", &[r]).unwrap_err();
    assert!(matches!(
        err,
        EncryptError::NeedsPrfOutput(crate::stanza_format::TAG_FIDO2_HMAC)
    ));
}

#[test]
fn yubikey_piv_recipient_produces_a_piv_stanza() {
    let identity = age::x25519::Identity::generate();
    let pubkey = pubkey_bytes_of(&identity);

    let r = Recipient::YubiKeyPiv {
        public_key: pubkey,
        serial: 12345,
        slot: 0x95,
    };
    let blob = encrypt(b"x", &[r]).expect("encrypt");

    let s = blob.as_str().expect("armored age output is UTF-8");
    let inner_b64: String = s
        .lines()
        .filter(|l| !l.starts_with("---"))
        .collect::<Vec<_>>()
        .join("");
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let decoded = B64.decode(inner_b64.trim()).expect("armor decodes");
    let decoded_str = String::from_utf8_lossy(&decoded);
    assert!(
        decoded_str.contains("piv-p256"),
        "missing piv-p256 stanza in armored header: {decoded_str}",
    );
}

#[test]
fn wrong_identity_yields_no_match() {
    let identity_a = age::x25519::Identity::generate();
    let identity_b = age::x25519::Identity::generate();

    let recipients = vec![Recipient::X25519 {
        public_key: pubkey_bytes_of(&identity_a),
    }];
    let blob = encrypt(b"hello", &recipients).unwrap();

    use age::secrecy::ExposeSecret;
    let armored_b = crate::ArmoredAgeSecret::from_trusted(
        identity_b.to_string().expose_secret().to_string(),
    );
    let wrong = software_passphrase_identity(&armored_b).unwrap();
    let identities: Vec<Box<dyn Identity>> = vec![Box::new(wrong)];

    let err = decrypt(&blob, &identities).unwrap_err();
    assert!(matches!(err, DecryptError::NoMatchingIdentity));
}

#[test]
fn type2_round_trip() {
    use crate::bitwarden::{decrypt_type2, encrypt_type2};

    let enc_key = [0x11u8; 32];
    let mac_key = [0x22u8; 32];
    let plaintext = b"login.password=hunter2";

    let encoded = encrypt_type2(plaintext, &enc_key, &mac_key);
    assert!(encoded.starts_with("2."));
    let parts = encoded[2..].split('|').count();
    assert_eq!(parts, 3, "Type-2 string must have iv|ct|mac");

    let recovered = decrypt_type2(&encoded, &enc_key, &mac_key).unwrap();
    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn type2_mac_tamper_detected() {
    use crate::bitwarden::{decrypt_type2, encrypt_type2, Type2Error};

    let enc_key = [0x11u8; 32];
    let mac_key = [0x22u8; 32];
    let encoded = encrypt_type2(b"x", &enc_key, &mac_key);

    let mut bytes = encoded.into_bytes();
    let last_pipe = bytes.iter().rposition(|&b| b == b'|').unwrap();
    let first_pipe = bytes.iter().position(|&b| b == b'|').unwrap();
    let middle = (first_pipe + last_pipe) / 2;
    bytes[middle] = if bytes[middle] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).unwrap();

    let err = decrypt_type2(&tampered, &enc_key, &mac_key).unwrap_err();

    assert!(matches!(
        err,
        Type2Error::MacFailed | Type2Error::Malformed | Type2Error::Base64(_)
    ));
}

#[test]
fn type2_wrong_mac_key_detected() {
    use crate::bitwarden::{decrypt_type2, encrypt_type2, Type2Error};

    let enc_key = [0x11u8; 32];
    let mac_key = [0x22u8; 32];
    let other_mac = [0x33u8; 32];

    let encoded = encrypt_type2(b"x", &enc_key, &mac_key);
    let err = decrypt_type2(&encoded, &enc_key, &other_mac).unwrap_err();
    assert!(matches!(err, Type2Error::MacFailed));
}

#[test]
fn master_key_pbkdf2_known_size() {
    let mk = bitwarden::derive_master_key("hunter2", "user@example.com", 100);
    assert_eq!(mk.len(), 32);
}

#[test]
fn master_password_hash_is_base64_44_chars() {
    let mk = [0x42u8; 32];
    let h = bitwarden::master_password_hash(&mk, "hunter2");

    assert_eq!(h.len(), 44);
}

#[test]
fn stretch_master_key_halves_differ() {
    let mk = [0x42u8; 32];
    let (enc, mac) = bitwarden::stretch_master_key(&mk);
    assert_ne!(&*enc, &*mac, "enc and mac halves must differ");

    assert_eq!(enc.len(), 32);
    assert_eq!(mac.len(), 32);
}

struct MockPivIdentity {
    slot_secret: x25519_dalek::StaticSecret,
}

impl Identity for MockPivIdentity {
    fn try_unwrap_stanza(&self, stanza: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        if stanza.tag != crate::stanza_format::TAG_PIV_P256 {
            return Ok(None);
        }
        let eph_pub_bytes = crate::stanza_format::piv_p256_ephemeral_pub(stanza)
            .map_err(|e| IdentityError::Crypto(e.to_string()))?;
        let eph_pub = x25519_dalek::PublicKey::from(eph_pub_bytes);
        let share = self.slot_secret.diffie_hellman(&eph_pub);
        let fk = crate::stanza_format::decrypt_piv_p256_with_ecdh_share(stanza, share.as_bytes())
            .map_err(|e| IdentityError::Crypto(e.to_string()))?;
        Ok(Some(fk))
    }

    fn display(&self) -> &str {
        "mock-piv"
    }
}

#[test]
fn end_to_end_piv_p256_round_trip_via_identity_callback() {
    let mut seed = [0u8; 32];
    use rand_core::Rng;
    rand::rng().fill_bytes(&mut seed);
    let secret = x25519_dalek::StaticSecret::from(seed);
    let public = x25519_dalek::PublicKey::from(&secret);
    let pubkey_bytes = *public.as_bytes();

    let r = Recipient::YubiKeyPiv {
        public_key: pubkey_bytes,
        serial: 1234,
        slot: 0x95,
    };
    let plaintext = b"piv-protected-secret";
    let blob = encrypt(plaintext, &[r]).expect("encrypt to YubiKeyPiv");

    let id = MockPivIdentity {
        slot_secret: secret,
    };
    let identities: Vec<Box<dyn Identity>> = vec![Box::new(id)];
    let recovered = decrypt(&blob, &identities).expect("decrypt via mock PIV identity");
    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn end_to_end_multi_recipient_falls_through_to_matching_identity() {
    use rand_core::Rng;

    let mut seed_a = [0u8; 32];
    let mut seed_b = [0u8; 32];
    rand::rng().fill_bytes(&mut seed_a);
    rand::rng().fill_bytes(&mut seed_b);
    let pub_a =
        *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(seed_a)).as_bytes();
    let pub_b =
        *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(seed_b)).as_bytes();

    let recovery = age::x25519::Identity::generate();
    let recovery_pub = crate::ArmoredAgeRecipient::from_trusted(recovery.to_public().to_string());

    let recipients = vec![
        Recipient::YubiKeyPiv {
            public_key: pub_a,
            serial: 1,
            slot: 0x95,
        },
        Recipient::YubiKeyPiv {
            public_key: pub_b,
            serial: 2,
            slot: 0x95,
        },
        Recipient::SoftwarePassphrase {
            armored_pubkey: recovery_pub,
        },
    ];
    let plaintext = b"multi-recipient-fallthrough";
    let blob = encrypt(plaintext, &recipients).expect("encrypt to {ya, yb, recovery}");

    use age::secrecy::ExposeSecret;
    let armored = crate::ArmoredAgeSecret::from_trusted(
        recovery.to_string().expose_secret().to_string(),
    );
    let sw = software_passphrase_identity(&armored).unwrap();
    let identities: Vec<Box<dyn Identity>> = vec![Box::new(sw)];
    let recovered = decrypt(&blob, &identities).expect("decrypt via recovery identity");
    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn end_to_end_recovery_mnemonic_round_trip() {
    let gen = crate::recovery::generate().expect("generate");
    let r = Recipient::SoftwarePassphrase {
        armored_pubkey: gen.armored_pubkey.clone(),
    };
    let plaintext = b"recovery-mnemonic-round-trip";
    let blob = encrypt(plaintext, &[r]).expect("encrypt to recovery pubkey");

    let id = crate::recovery::from_mnemonic(&gen.mnemonic).expect("recover");
    use age::secrecy::ExposeSecret;
    let armored =
        crate::ArmoredAgeSecret::from_trusted(id.to_string().expose_secret().to_string());
    let sw = software_passphrase_identity(&armored).unwrap();
    let identities: Vec<Box<dyn Identity>> = vec![Box::new(sw)];
    let recovered = decrypt(&blob, &identities).expect("decrypt via recovery identity");
    assert_eq!(recovered.as_slice(), plaintext);
}

fn pubkey_bytes_of(identity: &age::x25519::Identity) -> [u8; 32] {
    let armored = identity.to_public().to_string();
    crate::bech32::decode_age_x25519(&armored).expect("age1 pubkey decodes")
}

#[test]
fn age_blob_as_str_returns_an_error_on_non_utf8_instead_of_panicking() {
    let blob = AgeBlob::from_bytes(vec![0xff, 0xfe, 0x00, 0x80]);
    let err = blob
        .as_str()
        .expect_err("non-UTF-8 bytes must not be reported as a str");
    assert_eq!(err.valid_up_to, 0);
    assert!(blob.to_string_lossy().contains('\u{fffd}'));

    let truncated = AgeBlob::from_bytes(b"-----BEGIN AGE\xc3".to_vec());
    let err = truncated.as_str().expect_err("truncated UTF-8 rejected");
    assert_eq!(err.valid_up_to, 14);

    let good = AgeBlob::from_bytes(b"-----BEGIN AGE ENCRYPTED FILE-----".to_vec());
    assert_eq!(
        good.as_str().expect("ASCII is UTF-8"),
        "-----BEGIN AGE ENCRYPTED FILE-----"
    );
}
