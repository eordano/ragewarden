
use age::secrecy::ExposeSecret;
use ragewarden_core::{
    decrypt, encrypt, encrypt_with_prf, software_passphrase_identity, ArmoredAgeSecret,
    DecryptError, EncryptError, Identity, Recipient,
};

fn generate_x25519_pair() -> ([u8; 32], Box<dyn Identity>) {
    let identity = age::x25519::Identity::generate();
    let pub_armored = identity.to_public().to_string();
    let pub_bytes = ragewarden_core::bech32::decode_age_x25519(&pub_armored)
        .expect("bech32 decode of freshly generated pubkey");
    let secret_str = identity.to_string().expose_secret().to_string();
    let armored = ArmoredAgeSecret::from_trusted(secret_str);
    let id = software_passphrase_identity(&armored).expect("build software identity");
    (pub_bytes, Box::new(id))
}

#[test]
fn x25519_round_trip_two_recipients_each_decrypts_independently() {
    let (pub_a, id_a) = generate_x25519_pair();
    let (pub_b, id_b) = generate_x25519_pair();

    let recipients = vec![
        Recipient::X25519 { public_key: pub_a },
        Recipient::X25519 { public_key: pub_b },
    ];
    let plaintext = b"two-recipients-shared-secret";
    let blob = encrypt(plaintext, &recipients).expect("encrypt to two X25519 recipients");
    
    let identities_a: Vec<Box<dyn Identity>> = vec![id_a];
    let recovered_a = decrypt(&blob, &identities_a).expect("decrypt with identity A");
    assert_eq!(
        recovered_a.as_slice(),
        plaintext,
        "plaintext via identity A must round-trip exactly",
    );
    
    let identities_b: Vec<Box<dyn Identity>> = vec![id_b];
    let recovered_b = decrypt(&blob, &identities_b).expect("decrypt with identity B");
    assert_eq!(
        recovered_b.as_slice(),
        plaintext,
        "plaintext via identity B must round-trip exactly",
    );
}

#[test]
fn decrypt_with_non_matching_identity_returns_no_matching_identity() {
    
    let (pub_a, _id_a) = generate_x25519_pair();
    let (_pub_c, id_c) = generate_x25519_pair();

    let recipients = vec![Recipient::X25519 { public_key: pub_a }];
    let blob = encrypt(b"sealed-for-A", &recipients).expect("encrypt to A");

    let identities: Vec<Box<dyn Identity>> = vec![id_c];
    let err = decrypt(&blob, &identities).expect_err("decrypt with C should fail");
    assert!(
        matches!(err, DecryptError::NoMatchingIdentity),
        "expected NoMatchingIdentity, got: {err:?}",
    );
}

#[test]
fn encrypt_rejects_empty_recipients_slice() {
    
    let err = encrypt_with_prf(b"x", &[], &[]).expect_err("empty recipients must error");
    assert!(
        matches!(err, EncryptError::NoRecipients),
        "expected NoRecipients, got: {err:?}",
    );
    
    let err = encrypt(b"x", &[]).expect_err("empty recipients via encrypt() must error");
    assert!(
        matches!(err, EncryptError::NoRecipients),
        "expected NoRecipients, got: {err:?}",
    );
}

#[test]
fn jni_parse_step_rejects_malformed_recipients_json() {
    
    let bad = br#"{"not_an_array": true}"#;
    let res: Result<Vec<Recipient>, _> = serde_json::from_slice(bad);
    assert!(res.is_err(), "expected malformed JSON to error");
}

#[test]
fn jni_parse_step_accepts_well_formed_recipients_json() {
    
    let json = br#"[
        {"type":"x25519","public_key":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}
    ]"#;
    let parsed: Vec<Recipient> =
        serde_json::from_slice(json).expect("well-formed JSON must parse");
    assert_eq!(parsed.len(), 1);
    match &parsed[0] {
        Recipient::X25519 { public_key } => assert_eq!(public_key, &[0u8; 32]),
        other => panic!("expected X25519 variant, got {other:?}"),
    }
}

#[test]
fn jni_parse_step_rejects_wrong_length_pubkey() {
    
    let json = br#"[
        {"type":"x25519","public_key":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}
    ]"#;
    let res: Result<Vec<Recipient>, _> = serde_json::from_slice(json);
    assert!(
        res.is_err(),
        "expected serde to reject 31-byte public_key for [u8; 32] field",
    );
}
