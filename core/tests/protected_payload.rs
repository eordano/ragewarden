//! The protected-payload format inside a rage blob: frozen v1 blobs from
//! before v2 existed must keep opening, and v2's encoding is pinned.
//! tests/vectors/protected_payload.json is written once with
//! `RAGEWARDEN_BLESS_VECTORS=1` and never rewritten: its age blobs are the
//! frozen inputs.

use std::collections::BTreeMap;

use age::secrecy::ExposeSecret;
use ragewarden_core::protected::{
    self, PayloadError, TYPE_CARD, TYPE_LOGIN, TYPE_SECURE_NOTE, TYPE_SSH_KEY,
};
use ragewarden_core::{
    AgeBlob, ArmoredAgeSecret, Identity, Recipient, decrypt, encrypt, software_passphrase_identity,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const VECTOR_PATH: &str = "tests/vectors/protected_payload.json";

#[derive(Serialize, Deserialize)]
struct Vectors {
    /// A recovery phrase rather than an age secret key, so the repository's
    /// secret scan has nothing to flag; it derives the test identity.
    recovery_phrase: String,
    blobs: Vec<BlobVector>,
    kats: Vec<Kat>,
}

#[derive(Serialize, Deserialize)]
struct BlobVector {
    cipher_type: u8,
    armored: String,
    fields: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
struct Kat {
    cipher_type: u8,
    fields: BTreeMap<String, String>,
    sealed_hex: String,
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn zmap(m: &BTreeMap<String, String>) -> BTreeMap<String, Zeroizing<Vec<u8>>> {
    m.iter()
        .map(|(k, v)| (k.clone(), Zeroizing::new(v.as_bytes().to_vec())))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn kat_cases() -> Vec<(u8, BTreeMap<String, String>)> {
    vec![
        (TYPE_LOGIN, map(&[("password", "hunter2")])),
        (TYPE_SECURE_NOTE, map(&[("notes", "line one\nline two")])),
        (
            TYPE_LOGIN,
            map(&[("password", "hunter2"), ("notes", "recovery codes")]),
        ),
        (
            TYPE_CARD,
            map(&[("number", "4111111111111111"), ("code", "123")]),
        ),
        (
            TYPE_SSH_KEY,
            map(&[
                ("privateKey", "openssh-key-v1 test material\n"),
                ("passphrase", "pp"),
            ]),
        ),
    ]
}

fn identity(secret: &str) -> Vec<Box<dyn Identity>> {
    let sw =
        software_passphrase_identity(&ArmoredAgeSecret::from_trusted(secret.to_string())).unwrap();
    vec![Box::new(sw)]
}

#[test]
fn the_frozen_blobs_open_and_the_v2_encoding_is_pinned() {
    let on_disk = std::fs::read_to_string(VECTOR_PATH);
    if on_disk.is_err() && std::env::var_os("RAGEWARDEN_BLESS_VECTORS").is_some() {
        let generated = ragewarden_core::recovery::generate().unwrap();
        let recipients = vec![Recipient::SoftwarePassphrase {
            armored_pubkey: generated.armored_pubkey.clone(),
        }];
        let blob = |plaintext: &[u8]| {
            String::from_utf8(encrypt(plaintext, &recipients).unwrap().0).unwrap()
        };
        let v1_login = map(&[("password", "hunter2-from-a-v1-client")]);
        let v1_note = map(&[("notes", "a note written before v2")]);
        let v2_card = map(&[("number", "4111111111111111"), ("code", "123")]);
        let vectors = Vectors {
            recovery_phrase: generated.mnemonic.to_string(),
            blobs: vec![
                BlobVector {
                    cipher_type: TYPE_LOGIN,
                    armored: blob(b"hunter2-from-a-v1-client"),
                    fields: v1_login,
                },
                BlobVector {
                    cipher_type: TYPE_SECURE_NOTE,
                    armored: blob(b"a note written before v2"),
                    fields: v1_note,
                },
                BlobVector {
                    cipher_type: TYPE_CARD,
                    armored: blob(&protected::seal(TYPE_CARD, &zmap(&v2_card)).unwrap()),
                    fields: v2_card,
                },
            ],
            kats: kat_cases()
                .into_iter()
                .map(|(t, f)| Kat {
                    cipher_type: t,
                    sealed_hex: hex(&protected::seal(t, &zmap(&f)).unwrap()),
                    fields: f,
                })
                .collect(),
        };
        std::fs::write(
            VECTOR_PATH,
            serde_json::to_string_pretty(&vectors).unwrap() + "\n",
        )
        .unwrap();
        return;
    }
    let vectors: Vectors = serde_json::from_str(&on_disk.unwrap_or_else(|e| {
        panic!("{VECTOR_PATH}: {e}; write it once with RAGEWARDEN_BLESS_VECTORS=1")
    }))
    .unwrap();

    let mnemonic: bip39::Mnemonic = vectors.recovery_phrase.parse().unwrap();
    let id = ragewarden_core::recovery::from_mnemonic(&mnemonic).unwrap();
    let ids = identity(id.to_string().expose_secret());
    for b in &vectors.blobs {
        let plaintext = decrypt(&AgeBlob::from_bytes(b.armored.as_bytes().to_vec()), &ids).unwrap();
        assert_eq!(
            protected::field_names(b.cipher_type, &plaintext).unwrap(),
            b.fields.keys().cloned().collect::<Vec<_>>()
        );
        for (name, value) in &b.fields {
            assert_eq!(
                &protected::field(b.cipher_type, &plaintext, name).unwrap()[..],
                value.as_bytes()
            );
        }
        assert_eq!(
            &protected::field(b.cipher_type, &plaintext, "").unwrap()[..],
            b.fields[protected::primary_field(b.cipher_type)].as_bytes(),
            "the primary field answers an unnamed request"
        );
    }

    assert_eq!(vectors.kats.len(), kat_cases().len());
    for (kat, (t, f)) in vectors.kats.iter().zip(kat_cases()) {
        assert_eq!((kat.cipher_type, &kat.fields), (t, &f));
        assert_eq!(
            hex(&protected::seal(t, &zmap(&f)).unwrap()),
            kat.sealed_hex,
            "{f:?}"
        );
    }
    assert!(
        vectors.kats[0].sealed_hex == hex(b"hunter2"),
        "one primary field is v1: the bytes themselves"
    );
}

#[test]
fn a_field_a_v1_blob_never_held_is_missing_not_the_secret() {
    let v1 = b"hunter2";
    assert_eq!(
        protected::field(TYPE_LOGIN, v1, "notes").unwrap_err(),
        PayloadError::MissingField("notes".into())
    );
}
