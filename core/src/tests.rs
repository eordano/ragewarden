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
    let armored =
        crate::ArmoredAgeSecret::from_trusted(identity.to_string().expose_secret().to_string());
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
        stanza_version: 1,
    };
    let blob = encrypt(b"x", &[r]).expect("encrypt");

    let s = blob.as_str().expect("armored age output is UTF-8");
    let inner_b64: String = s
        .lines()
        .filter(|l| !l.starts_with("---"))
        .collect::<Vec<_>>()
        .join("");
    use base64::{Engine, engine::general_purpose::STANDARD as B64};
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
    let armored_b =
        crate::ArmoredAgeSecret::from_trusted(identity_b.to_string().expose_secret().to_string());
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
    use crate::bitwarden::{Type2Error, decrypt_type2, encrypt_type2};

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
    use crate::bitwarden::{Type2Error, decrypt_type2, encrypt_type2};

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
        use crate::stanza_format::{self as sf, PivStanzaKind};
        if !matches!(
            sf::piv_stanza_kind(stanza),
            Some(PivStanzaKind::X25519V1 | PivStanzaKind::X25519V2)
        ) {
            return Ok(None);
        }
        let own = *x25519_dalek::PublicKey::from(&self.slot_secret).as_bytes();
        if sf::piv_x25519_recipient_tag(stanza).ok() != Some(sf::piv_recipient_tag(&own)) {
            return Ok(None);
        }
        let eph_pub_bytes = sf::piv_x25519_ephemeral_pub(stanza)
            .map_err(|e| IdentityError::Crypto(e.to_string()))?;
        let eph_pub = x25519_dalek::PublicKey::from(eph_pub_bytes);
        let share = self.slot_secret.diffie_hellman(&eph_pub);
        let fk = sf::decrypt_piv_x25519_with_ecdh_share(stanza, share.as_bytes(), Some(&own))
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
        stanza_version: 1,
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
            stanza_version: 1,
        },
        Recipient::YubiKeyPiv {
            public_key: pub_b,
            serial: 2,
            slot: 0x95,
            stanza_version: 1,
        },
        Recipient::SoftwarePassphrase {
            armored_pubkey: recovery_pub,
        },
    ];
    let plaintext = b"multi-recipient-fallthrough";
    let blob = encrypt(plaintext, &recipients).expect("encrypt to {ya, yb, recovery}");

    use age::secrecy::ExposeSecret;
    let armored =
        crate::ArmoredAgeSecret::from_trusted(recovery.to_string().expose_secret().to_string());
    let sw = software_passphrase_identity(&armored).unwrap();
    let identities: Vec<Box<dyn Identity>> = vec![Box::new(sw)];
    let recovered = decrypt(&blob, &identities).expect("decrypt via recovery identity");
    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn end_to_end_recovery_mnemonic_round_trip() {
    let generated = crate::recovery::generate().expect("generate");
    let r = Recipient::SoftwarePassphrase {
        armored_pubkey: generated.armored_pubkey.clone(),
    };
    let plaintext = b"recovery-mnemonic-round-trip";
    let blob = encrypt(plaintext, &[r]).expect("encrypt to recovery pubkey");

    let id = crate::recovery::from_mnemonic(&generated.mnemonic).expect("recover");
    use age::secrecy::ExposeSecret;
    let armored = crate::ArmoredAgeSecret::from_trusted(id.to_string().expose_secret().to_string());
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

struct FailingIdentity {
    tag: &'static str,
    make: fn() -> IdentityError,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl FailingIdentity {
    fn new(tag: &'static str, make: fn() -> IdentityError) -> Self {
        Self {
            tag,
            make,
            calls: Default::default(),
        }
    }
}

impl Identity for FailingIdentity {
    fn try_unwrap_stanza(&self, stanza: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        if stanza.tag != self.tag {
            return Ok(None);
        }
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err((self.make)())
    }

    fn display(&self) -> &str {
        "failing stub"
    }
}

fn two_piv_recipients() -> (Vec<Recipient>, x25519_dalek::StaticSecret) {
    let good = x25519_dalek::StaticSecret::from([0x42u8; 32]);
    let other = x25519_dalek::StaticSecret::from([0x24u8; 32]);
    let recipients = vec![
        Recipient::YubiKeyPiv {
            public_key: *x25519_dalek::PublicKey::from(&other).as_bytes(),
            serial: 1,
            slot: 0x9a,
            stanza_version: 1,
        },
        Recipient::YubiKeyPiv {
            public_key: *x25519_dalek::PublicKey::from(&good).as_bytes(),
            serial: 2,
            slot: 0x9a,
            stanza_version: 1,
        },
    ];
    (recipients, good)
}

#[test]
fn a_failing_device_does_not_stop_the_next_identity_from_opening_the_blob() {
    let (recipients, good) = two_piv_recipients();
    let blob = encrypt(b"fall through", &recipients).unwrap();
    let identities: Vec<Box<dyn Identity>> = vec![
        Box::new(FailingIdentity::new(
            crate::stanza_format::TAG_PIV_P256,
            || IdentityError::Hardware("device not present".into()),
        )),
        Box::new(MockPivIdentity { slot_secret: good }),
    ];
    let pt = decrypt(&blob, &identities).expect("second identity opens the blob");
    assert_eq!(pt.as_slice(), b"fall through");
}

#[test]
fn a_failing_device_is_reported_instead_of_no_matching_identity() {
    let (recipients, _) = two_piv_recipients();
    let blob = encrypt(b"x", &recipients).unwrap();
    let identities: Vec<Box<dyn Identity>> = vec![Box::new(FailingIdentity::new(
        crate::stanza_format::TAG_PIV_P256,
        || IdentityError::Hardware("device not present".into()),
    ))];
    match decrypt(&blob, &identities).unwrap_err() {
        DecryptError::Identity(IdentityError::Hardware(_)) => {}
        other => panic!("an absent device must surface as its own error, got {other:?}"),
    }
}

#[test]
fn a_refusing_device_outranks_a_stanza_that_did_not_parse() {
    let (recipients, _) = two_piv_recipients();
    let blob = encrypt(b"x", &recipients).unwrap();
    let identities: Vec<Box<dyn Identity>> = vec![
        Box::new(FailingIdentity::new(
            crate::stanza_format::TAG_PIV_P256,
            || IdentityError::Crypto("unparseable".into()),
        )),
        Box::new(FailingIdentity::new(
            crate::stanza_format::TAG_PIV_P256,
            || IdentityError::Auth("wrong PIN".into()),
        )),
    ];
    assert!(matches!(
        decrypt(&blob, &identities).unwrap_err(),
        DecryptError::Identity(IdentityError::Auth(_))
    ));
}

#[test]
fn a_cancellation_ends_the_decryption_without_asking_another_device() {
    let (recipients, good) = two_piv_recipients();
    let blob = encrypt(b"x", &recipients).unwrap();
    let cancel = FailingIdentity::new(crate::stanza_format::TAG_PIV_P256, || {
        IdentityError::Cancelled
    });
    let calls = cancel.calls.clone();
    let identities: Vec<Box<dyn Identity>> = vec![
        Box::new(cancel),
        Box::new(MockPivIdentity { slot_secret: good }),
    ];
    assert!(matches!(
        decrypt(&blob, &identities).unwrap_err(),
        DecryptError::Identity(IdentityError::Cancelled)
    ));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn a_failing_device_does_not_hide_a_software_recipient() {
    let sw = age::x25519::Identity::generate();
    let (mut recipients, _) = two_piv_recipients();
    recipients.push(Recipient::X25519 {
        public_key: pubkey_bytes_of(&sw),
    });
    let blob = encrypt(b"software too", &recipients).unwrap();
    use age::secrecy::ExposeSecret;
    let armored = crate::ArmoredAgeSecret::from_trusted(sw.to_string().expose_secret().to_string());
    let identities: Vec<Box<dyn Identity>> = vec![
        Box::new(FailingIdentity::new(
            crate::stanza_format::TAG_PIV_P256,
            || IdentityError::Hardware("absent".into()),
        )),
        Box::new(software_passphrase_identity(&armored).unwrap()),
    ];
    assert_eq!(
        decrypt(&blob, &identities).unwrap().as_slice(),
        b"software too"
    );
}

fn header_tags(blob: &AgeBlob) -> Vec<String> {
    crate::parse_header_stanzas(blob)
        .unwrap()
        .into_iter()
        .map(|s| s.tag)
        .filter(|t| !t.ends_with("-grease"))
        .collect()
}

#[test]
fn a_v2_piv_recipient_gets_a_recipient_bound_stanza_its_slot_opens() {
    let secret = x25519_dalek::StaticSecret::from([0x31u8; 32]);
    let r = Recipient::YubiKeyPiv {
        public_key: *x25519_dalek::PublicKey::from(&secret).as_bytes(),
        serial: 1,
        slot: 0x9d,
        stanza_version: 2,
    };
    let blob = encrypt(b"v2", &[r]).unwrap();
    assert_eq!(header_tags(&blob), vec!["piv-x25519-v2".to_string()]);
    let identities: Vec<Box<dyn Identity>> = vec![Box::new(MockPivIdentity {
        slot_secret: secret,
    })];
    assert_eq!(decrypt(&blob, &identities).unwrap().as_slice(), b"v2");
}

#[test]
fn an_unknown_stanza_version_is_refused_at_encrypt_time() {
    let r = Recipient::YubiKeyPiv {
        public_key: [9u8; 32],
        serial: 1,
        slot: 0x9d,
        stanza_version: 3,
    };
    assert!(matches!(
        encrypt(b"x", &[r]).unwrap_err(),
        EncryptError::Recipient(_)
    ));
}

struct MockP256Slot {
    secret: p256::SecretKey,
}

impl MockP256Slot {
    fn public(&self) -> Vec<u8> {
        use p256::elliptic_curve::sec1::ToSec1Point;
        self.secret
            .public_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec()
    }
}

impl Identity for MockP256Slot {
    fn try_unwrap_stanza(&self, stanza: &Stanza) -> Result<Option<FileKey>, IdentityError> {
        use crate::stanza_format::{self as sf, PivStanzaKind};
        if sf::piv_stanza_kind(stanza) != Some(PivStanzaKind::P256) {
            return Ok(None);
        }
        let own = self.public();
        if sf::piv_ec_p256_recipient_tag(stanza).ok() != Some(sf::piv_recipient_tag(&own)) {
            return Ok(None);
        }
        let eph = sf::piv_ec_p256_ephemeral_pub(stanza)
            .map_err(|e| IdentityError::Crypto(e.to_string()))?;
        let peer = p256::PublicKey::from_sec1_bytes(&eph).unwrap();
        let shared = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        let share: [u8; 32] = shared.raw_secret_bytes().as_slice().try_into().unwrap();
        sf::decrypt_piv_ec_p256_with_ecdh_share(stanza, &share, &own)
            .map(Some)
            .map_err(|e| IdentityError::Crypto(e.to_string()))
    }

    fn display(&self) -> &str {
        "mock p256 slot"
    }
}

#[test]
fn a_p256_piv_slot_is_a_recipient_in_age_plugin_yubikey_format() {
    use p256::elliptic_curve::Generate;
    let slot = MockP256Slot {
        secret: p256::SecretKey::generate_from_rng(&mut rand::rng()),
    };
    let x_secret = x25519_dalek::StaticSecret::from([0x44u8; 32]);
    let recipients = vec![
        Recipient::YubiKeyPivP256 {
            public_key: slot.public(),
            serial: 7,
            slot: 0x9a,
        },
        Recipient::YubiKeyPiv {
            public_key: *x25519_dalek::PublicKey::from(&x_secret).as_bytes(),
            serial: 8,
            slot: 0x9a,
            stanza_version: 1,
        },
    ];
    let blob = encrypt(b"p256 slot", &recipients).unwrap();
    assert_eq!(header_tags(&blob), vec!["piv-p256", "piv-p256"]);

    let p256_only: Vec<Box<dyn Identity>> = vec![Box::new(slot)];
    assert_eq!(decrypt(&blob, &p256_only).unwrap().as_slice(), b"p256 slot");
    let x25519_only: Vec<Box<dyn Identity>> = vec![Box::new(MockPivIdentity {
        slot_secret: x_secret,
    })];
    assert_eq!(
        decrypt(&blob, &x25519_only).unwrap().as_slice(),
        b"p256 slot",
        "the X25519 slot skips the P-256 stanza that shares its tag"
    );
}

#[test]
fn a_p256_piv_recipient_must_be_a_curve_point() {
    let mut off_curve = vec![0x01u8; 33];
    off_curve[0] = 0x02;
    let r = Recipient::YubiKeyPivP256 {
        public_key: off_curve,
        serial: 1,
        slot: 0x9a,
    };
    assert!(matches!(
        encrypt(b"x", &[r]).unwrap_err(),
        EncryptError::Recipient(_)
    ));
}

#[test]
fn a_v2_keystore_recipient_gets_the_v2_tag() {
    use p256::elliptic_curve::{Generate, sec1::ToSec1Point};
    let sk = p256::SecretKey::generate_from_rng(&mut rand::rng());
    let r = Recipient::AndroidKeystore {
        public_key: sk.public_key().to_sec1_point(true).as_bytes().to_vec(),
        key_handle: "alias".into(),
        stanza_version: 2,
    };
    let blob = encrypt(b"k", &[r]).unwrap();
    assert_eq!(header_tags(&blob), vec!["ragedroid-keystore-v2"]);
}

#[test]
fn recipient_json_without_stanza_version_is_v1_and_v1_serializes_as_before() {
    let json = r#"{"type":"yubi_key_piv","public_key":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"serial":5,"slot":154}"#;
    let r: Recipient = serde_json::from_str(json).unwrap();
    assert!(matches!(
        r,
        Recipient::YubiKeyPiv {
            stanza_version: 1,
            ..
        }
    ));
    assert_eq!(serde_json::to_string(&r).unwrap(), json);
}

#[test]
fn decrypt_reads_into_one_zeroizing_buffer_that_never_reallocates() {
    let sw = age::x25519::Identity::generate();
    let plaintext = vec![0x5au8; 1 << 20];
    let blob = encrypt(
        &plaintext,
        &[Recipient::X25519 {
            public_key: pubkey_bytes_of(&sw),
        }],
    )
    .unwrap();
    use age::secrecy::ExposeSecret;
    let armored = crate::ArmoredAgeSecret::from_trusted(sw.to_string().expose_secret().to_string());
    let identities: Vec<Box<dyn Identity>> =
        vec![Box::new(software_passphrase_identity(&armored).unwrap())];
    let got = decrypt(&blob, &identities).unwrap();
    assert_eq!(got.as_slice(), plaintext.as_slice());
    assert_eq!(
        got.capacity(),
        blob.as_bytes().len(),
        "a reallocation would have left an unzeroized copy of the plaintext behind"
    );
}

#[test]
fn type2_decrypt_returns_zeroizing_memory() {
    use crate::bitwarden::{decrypt_type2, encrypt_type2};
    let enc_key = [0x11u8; 32];
    let mac_key = [0x22u8; 32];
    let encoded = encrypt_type2(b"user key bytes", &enc_key, &mac_key);
    let recovered: zeroize::Zeroizing<Vec<u8>> =
        decrypt_type2(&encoded, &enc_key, &mac_key).unwrap();
    assert_eq!(recovered.as_slice(), b"user key bytes");
}
