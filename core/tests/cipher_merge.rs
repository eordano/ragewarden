use std::sync::Mutex;

use async_trait::async_trait;
use ragewarden_core::Type2EncString;
use ragewarden_core::bitwarden::encrypt_type2;
use ragewarden_core::sync::{
    Cipher, CipherDraft, CipherEdit, CipherIn, HttpBody, HttpClient, HttpError, HttpResponse,
    RAGE_FIELD_NAME, RAGE_MARKER_NOTE, Server, Session, build_cipher, build_rage_cipher,
    cipher_name, decrypt_cipher_string, decrypt_string, edit_preserving, encrypt_string,
    extract_rage_blob, rewrap_preserving, update_preserving,
};
use serde_json::{Value, json};

fn session() -> Session {
    Session {
        access_token: ragewarden_core::BearerToken::from_trusted("stub".into()),
        refresh_token: ragewarden_core::RefreshToken::from_trusted("refresh".into()),
        user_id: "u".into(),
        email: "a@example.com".into(),
        user_enc_key: [0x31u8; 32].to_vec().into(),
        user_mac_key: [0x32u8; 32].to_vec().into(),
        kdf: ragewarden_core::sync::KdfParams::default(),
        device_id: "d".into(),
    }
}

fn enc(s: &Session, v: &str) -> String {
    encrypt_string(s, v).unwrap().into_inner()
}

fn dec(s: &Session, v: &Value) -> String {
    decrypt_string(s, &Type2EncString::from_trusted(v.as_str().unwrap().into())).unwrap()
}

/// A login exactly as Vaultwarden's /api/sync returns it, with every field a
/// Bitwarden client can set, including ones this crate does not model.
fn full_login(s: &Session) -> Value {
    json!({
        "object": "cipherDetails",
        "id": "c-1",
        "revisionDate": "2026-09-01T00:00:00.000000Z",
        "type": 1,
        "name": enc(s, "GitHub"),
        "notes": enc(s, "recovery codes in the safe"),
        "folderId": "f-1",
        "favorite": true,
        "reprompt": 1,
        "login": {
            "username": enc(s, "octocat"),
            "password": enc(s, "hunter2"),
            "totp": enc(s, "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP"),
            "passwordRevisionDate": "2026-08-01T00:00:00.000Z",
            "autofillOnPageLoad": true,
            "fido2Credentials": [{ "credentialId": enc(s, "cred"), "rpId": enc(s, "github.com") }],
            "uris": [
                { "uri": enc(s, "https://github.com/login"), "match": 3, "uriChecksum": enc(s, "sum1") },
                { "uri": enc(s, "https://gist.github.com"), "match": null }
            ]
        },
        "fields": [
            { "name": enc(s, "recovery email"), "value": enc(s, "o@example.com"), "type": 0 },
            { "name": enc(s, "linked"), "value": null, "type": 3, "linkedId": 100 }
        ],
        "passwordHistory": [
            { "password": enc(s, "hunter1"), "lastUsedDate": "2026-07-01T00:00:00.000Z" }
        ]
    })
}

fn to_cipher(v: &Value) -> Cipher {
    serde_json::from_value(v.clone()).unwrap()
}

fn body(c: &CipherIn) -> Value {
    serde_json::to_value(c).unwrap()
}

fn rage_values(s: &Session, b: &Value) -> Vec<String> {
    b["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| dec(s, &f["name"]) == RAGE_FIELD_NAME)
        .map(|f| dec(s, &f["value"]))
        .collect()
}

#[test]
fn rewrap_keeps_every_field_of_a_login_and_only_moves_the_password_into_the_blob() {
    let s = session();
    let server = full_login(&s);
    let out = body(&rewrap_preserving(&s, &to_cipher(&server), "AGE-BLOB").unwrap());

    assert_eq!(out["type"], 1);
    assert_eq!(out["name"], server["name"]);
    assert_eq!(out["notes"], server["notes"]);
    assert_eq!(out["folderId"], "f-1");
    assert_eq!(out["favorite"], true);
    assert_eq!(out["reprompt"], 1);
    assert_eq!(out["passwordHistory"], server["passwordHistory"]);

    let login = &out["login"];
    assert_eq!(dec(&s, &login["Username"]), "octocat");
    assert_eq!(login["Totp"], server["login"]["totp"]);
    assert!(
        login.get("Password").is_none(),
        "the protected secret must leave the Type-2 password"
    );
    assert_eq!(
        login["fido2Credentials"],
        server["login"]["fido2Credentials"]
    );
    assert_eq!(
        login["passwordRevisionDate"],
        server["login"]["passwordRevisionDate"]
    );
    assert_eq!(login["autofillOnPageLoad"], true);
    let uris = login["Uris"].as_array().unwrap();
    assert_eq!(uris.len(), 2);
    assert_eq!(uris[0]["Uri"], server["login"]["uris"][0]["uri"]);
    assert_eq!(uris[0]["Match"], 3);
    assert_eq!(
        uris[0]["uriChecksum"],
        server["login"]["uris"][0]["uriChecksum"]
    );
    assert_eq!(uris[1]["Uri"], server["login"]["uris"][1]["uri"]);

    let fields = out["fields"].as_array().unwrap();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0]["name"], server["fields"][0]["name"]);
    assert_eq!(fields[0]["value"], server["fields"][0]["value"]);
    assert_eq!(fields[1]["linkedId"], 100);
    assert_eq!(rage_values(&s, &out), vec!["AGE-BLOB".to_string()]);
}

#[test]
fn rotating_a_protected_item_replaces_its_blob_in_place() {
    let s = session();
    let first = body(&build_rage_cipher(&s, "ssh", "OLD").unwrap());
    let mut server = first.clone();
    server["id"] = json!("c-2");
    let rotated = body(&rewrap_preserving(&s, &to_cipher(&server), "NEW").unwrap());

    assert_eq!(rage_values(&s, &rotated), vec!["NEW".to_string()]);
    assert_eq!(rotated["type"], 2);
    assert_eq!(dec(&s, &rotated["notes"]), RAGE_MARKER_NOTE);
    assert_eq!(rotated["name"], first["name"]);
}

#[test]
fn duplicate_rage_fields_collapse_to_one() {
    let s = session();
    let mut server = full_login(&s);
    server["fields"] = json!([
        { "name": enc(&s, RAGE_FIELD_NAME), "value": enc(&s, "A"), "type": 1 },
        { "name": enc(&s, RAGE_FIELD_NAME), "value": enc(&s, "B"), "type": 1 }
    ]);
    let out = body(&rewrap_preserving(&s, &to_cipher(&server), "C").unwrap());
    assert_eq!(rage_values(&s, &out), vec!["C".to_string()]);
}

#[test]
fn card_identity_and_ssh_payloads_survive_a_rewrap() {
    let s = session();
    for (ty, key, payload) in [
        (
            3,
            "card",
            json!({ "cardholderName": enc(&s, "O C"), "number": enc(&s, "4111"), "code": enc(&s, "123") }),
        ),
        (
            4,
            "identity",
            json!({ "firstName": enc(&s, "Octo"), "ssn": enc(&s, "000"), "passportNumber": enc(&s, "P1") }),
        ),
        (
            5,
            "sshKey",
            json!({ "publicKey": enc(&s, "ssh-ed25519 AAA"), "fingerprint": enc(&s, "SHA256:x") }),
        ),
    ] {
        let mut server =
            json!({ "id": "c-3", "type": ty, "name": enc(&s, "x"), "favorite": false });
        server[key] = payload.clone();
        let out = body(&rewrap_preserving(&s, &to_cipher(&server), "BLOB").unwrap());
        assert_eq!(out["type"], ty);
        let got = &out[key];
        for (k, v) in payload.as_object().unwrap() {
            let pascal = format!("{}{}", k[..1].to_uppercase(), &k[1..]);
            assert_eq!(&got[&pascal], v, "{key}.{k} lost");
        }
        assert_eq!(rage_values(&s, &out), vec!["BLOB".to_string()]);
    }
}

#[test]
fn an_item_with_its_own_cipher_key_is_read_and_rewrapped_under_that_key() {
    let s = session();
    let item_key = [0x55u8; 64];
    let (ie, im): ([u8; 32], [u8; 32]) = (
        item_key[..32].try_into().unwrap(),
        item_key[32..].try_into().unwrap(),
    );
    let wrapped = encrypt_type2(&item_key, &[0x31; 32], &[0x32; 32]);
    let server = json!({
        "id": "c-4",
        "type": 1,
        "key": wrapped,
        "name": encrypt_type2(b"Bank", &ie, &im),
        "login": { "username": encrypt_type2(b"me", &ie, &im) },
    });
    let cipher = to_cipher(&server);
    assert_eq!(cipher_name(&s, &cipher).unwrap(), "Bank");

    let out = rewrap_preserving(&s, &cipher, "BLOB").unwrap();
    assert_eq!(out.key.as_ref().map(|k| k.as_str()), Some(wrapped.as_str()));
    let mut echoed = body(&out);
    echoed["id"] = json!("c-4");
    let echoed = to_cipher(&echoed);
    assert_eq!(
        extract_rage_blob(&s, &echoed).unwrap().as_deref(),
        Some("BLOB")
    );
    assert_eq!(
        decrypt_cipher_string(
            &s,
            &echoed,
            echoed.login.as_ref().unwrap().username.as_ref().unwrap()
        )
        .unwrap(),
        "me"
    );
    assert!(
        decrypt_string(
            &s,
            &echoed.fields.as_ref().unwrap()[0].value.clone().unwrap()
        )
        .is_err(),
        "the rage field must be under the item key, not the user key"
    );
}

#[test]
fn a_new_protected_note_has_the_same_shape_as_before() {
    let s = session();
    let out = body(&build_rage_cipher(&s, "n", "BLOB").unwrap());
    let mut keys: Vec<&str> = out
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        ["favorite", "fields", "name", "notes", "secureNote", "type"]
    );
    assert_eq!(out["type"], 2);
    assert_eq!(out["favorite"], false);
    assert_eq!(dec(&s, &out["notes"]), RAGE_MARKER_NOTE);
    assert_eq!(rage_values(&s, &out), vec!["BLOB".to_string()]);
}

#[test]
fn a_new_protected_login_keeps_username_uris_totp_and_notes() {
    let s = session();
    let draft = CipherDraft {
        login: true,
        name: "Shop".into(),
        notes: Some("n".into()),
        username: Some("me".into()),
        uris: vec!["https://shop.example".into()],
        totp: Some("JBSWY3DP".into()),
        folder_id: Some("f".into()),
        favorite: true,
        ..CipherDraft::default()
    };
    let out = body(&build_cipher(&s, &draft, Some("BLOB")).unwrap());
    assert_eq!(out["type"], 1);
    assert_eq!(dec(&s, &out["login"]["Username"]), "me");
    assert_eq!(
        dec(&s, &out["login"]["Uris"][0]["Uri"]),
        "https://shop.example"
    );
    assert_eq!(dec(&s, &out["login"]["Totp"]), "JBSWY3DP");
    assert!(out["login"].get("Password").is_none());
    assert_eq!(dec(&s, &out["notes"]), "n");
    assert_eq!(out["folderId"], "f");
    assert_eq!(out["favorite"], true);
    assert_eq!(rage_values(&s, &out), vec!["BLOB".to_string()]);

    let bad = CipherDraft {
        password: Some("pw".into()),
        ..draft
    };
    assert!(build_cipher(&s, &bad, Some("BLOB")).is_err());
}

#[test]
fn editing_keeps_what_the_edit_does_not_name() {
    let s = session();
    let server = full_login(&s);
    let edit = CipherEdit {
        name: Some("GitHub (work)".into()),
        uris: Some(vec![
            "https://gist.github.com".into(),
            "https://github.com/new".into(),
        ]),
        clear_folder: true,
        ..CipherEdit::default()
    };
    let out = body(&edit_preserving(&s, &to_cipher(&server), None, &edit).unwrap());
    assert_eq!(dec(&s, &out["name"]), "GitHub (work)");
    assert!(out.get("folderId").is_none());
    assert_eq!(out["login"]["Password"], server["login"]["password"]);
    assert_eq!(out["login"]["Username"], server["login"]["username"]);
    let uris = out["login"]["Uris"].as_array().unwrap();
    assert_eq!(uris.len(), 2);
    assert_eq!(
        uris[0]["Uri"], server["login"]["uris"][1]["uri"],
        "a kept URI keeps its ciphertext"
    );
    assert_eq!(dec(&s, &uris[1]["Uri"]), "https://github.com/new");
    assert_eq!(
        out["fields"],
        json!([
            { "name": server["fields"][0]["name"], "value": server["fields"][0]["value"], "type": 0 },
            { "name": server["fields"][1]["name"], "value": null, "type": 3, "linkedId": 100 }
        ])
    );
}

#[test]
fn giving_a_secure_note_a_username_makes_it_a_login() {
    let s = session();
    let note = body(&build_rage_cipher(&s, "n", "BLOB").unwrap());
    let edit = CipherEdit {
        username: Some("me".into()),
        ..CipherEdit::default()
    };
    let out = body(&edit_preserving(&s, &to_cipher(&note), None, &edit).unwrap());
    assert_eq!(out["type"], 1);
    assert!(out.get("secureNote").is_none());
    assert_eq!(dec(&s, &out["login"]["Username"]), "me");
    assert_eq!(rage_values(&s, &out), vec!["BLOB".to_string()]);
}

#[test]
fn changing_a_plain_password_files_the_old_one_in_history() {
    let s = session();
    let server = full_login(&s);
    let edit = CipherEdit {
        password: Some("hunter3".into()),
        ..CipherEdit::default()
    };
    let out = body(&edit_preserving(&s, &to_cipher(&server), None, &edit).unwrap());
    assert_eq!(dec(&s, &out["login"]["Password"]), "hunter3");
    let hist = out["passwordHistory"].as_array().unwrap();
    assert_eq!(hist.len(), 2);
    assert_eq!(dec(&s, &hist[0]["password"]), "hunter2");
    assert_eq!(hist[1], server["passwordHistory"][0]);

    let same = CipherEdit {
        password: Some("hunter2".into()),
        ..CipherEdit::default()
    };
    let out = body(&edit_preserving(&s, &to_cipher(&server), None, &same).unwrap());
    assert_eq!(out["passwordHistory"].as_array().unwrap().len(), 1);

    assert!(edit_preserving(&s, &to_cipher(&server), Some("BLOB"), &edit).is_err());
}

#[test]
fn a_cached_cipher_round_trips_fields_the_crate_does_not_model() {
    let s = session();
    let c = to_cipher(&full_login(&s));
    let back: Cipher = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
    let out = body(&CipherIn::from_existing(&back));
    assert!(out["login"].get("fido2Credentials").is_some());
    assert_eq!(
        out["login"]["Uris"][0]["uriChecksum"],
        body(&CipherIn::from_existing(&c))["login"]["Uris"][0]["uriChecksum"]
    );
    assert_eq!(out["fields"][1]["linkedId"], 100);
    let reparsed: CipherIn = serde_json::from_value(out.clone()).unwrap();
    assert_eq!(body(&reparsed), out);
}

struct Mock {
    get_body: Vec<u8>,
    put: Mutex<Option<(String, Vec<u8>)>>,
}

#[async_trait]
impl HttpClient for Mock {
    async fn post(
        &self,
        url: &str,
        _: HttpBody,
        _: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        Err(HttpError::Transport(format!("unexpected POST {url}")))
    }
    async fn put(
        &self,
        url: &str,
        body: HttpBody,
        _: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        let HttpBody::Json(b) = body else {
            panic!("form PUT")
        };
        *self.put.lock().unwrap() = Some((url.to_string(), b.clone()));
        let mut echoed: Value = serde_json::from_slice(&b).unwrap();
        echoed["id"] = json!("c-1");
        Ok(HttpResponse {
            status: 200,
            body: serde_json::to_vec(&echoed).unwrap(),
        })
    }
    async fn get(&self, url: &str, _: &[(String, String)]) -> Result<HttpResponse, HttpError> {
        assert!(url.ends_with("/api/ciphers/c-1"), "{url}");
        Ok(HttpResponse {
            status: 200,
            body: self.get_body.clone(),
        })
    }
    async fn delete(&self, url: &str, _: &[(String, String)]) -> Result<HttpResponse, HttpError> {
        Err(HttpError::Transport(format!("unexpected DELETE {url}")))
    }
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut fut = Box::pin(fut);
    match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("the mock HttpClient is always ready"),
    }
}

#[test]
fn update_preserving_merges_against_the_servers_current_copy() {
    let s = session();
    let server = full_login(&s);
    let mock = Mock {
        get_body: serde_json::to_vec(&server).unwrap(),
        put: Mutex::new(None),
    };
    let saved = block_on(update_preserving(
        &mock,
        &Server::self_hosted("https://vault.example.test"),
        &s,
        "c-1",
        Some("BLOB"),
        &CipherEdit::default(),
    ))
    .unwrap();

    let (url, sent) = mock.put.lock().unwrap().clone().unwrap();
    assert!(url.ends_with("/api/ciphers/c-1"));
    let sent: Value = serde_json::from_slice(&sent).unwrap();
    assert_eq!(sent["login"]["Username"], server["login"]["username"]);
    assert_eq!(
        sent["login"]["Uris"][1]["Uri"],
        server["login"]["uris"][1]["uri"]
    );
    assert_eq!(sent["login"]["Totp"], server["login"]["totp"]);
    assert_eq!(sent["notes"], server["notes"]);
    assert_eq!(sent["folderId"], "f-1");
    assert_eq!(sent["favorite"], true);
    assert_eq!(
        extract_rage_blob(&s, &saved).unwrap().as_deref(),
        Some("BLOB")
    );
}

#[test]
fn an_update_built_from_nothing_cannot_flatten_the_server_cipher() {
    use ragewarden_core::sync::{
        build_meta_cipher, build_rage_cipher_in_folder, overlay_preserving,
    };
    let s = session();
    let server = full_login(&s);
    let incoming = build_rage_cipher_in_folder(&s, "GitHub", "BLOB", Some("f-2")).unwrap();
    let out = body(&overlay_preserving(&s, &to_cipher(&server), &incoming).unwrap());

    assert_eq!(out["type"], 1);
    assert_eq!(out["folderId"], "f-2");
    assert_eq!(
        out["favorite"], true,
        "a from-scratch body's favourite=false is not an edit"
    );
    assert_eq!(
        out["notes"], server["notes"],
        "the default marker note is not an edit"
    );
    assert_eq!(out["login"]["Username"], server["login"]["username"]);
    assert_eq!(
        out["login"]["Uris"][0]["Uri"],
        server["login"]["uris"][0]["uri"]
    );
    assert!(out["login"].get("Password").is_none());
    assert_eq!(rage_values(&s, &out), vec!["BLOB".to_string()]);

    let no_folder = build_rage_cipher_in_folder(&s, "GitHub", "BLOB", None).unwrap();
    let out = body(&overlay_preserving(&s, &to_cipher(&server), &no_folder).unwrap());
    assert_eq!(out["folderId"], "f-1", "only set_folder clears a folder");

    let meta = json!({ "id": "m", "type": 2, "name": enc(&s, "__marker__"), "notes": enc(&s, "{}"), "secureNote": { "type": 0 } });
    let out = body(
        &overlay_preserving(
            &s,
            &to_cipher(&meta),
            &build_meta_cipher(&s, "__marker__", "{\"v\":2}").unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(dec(&s, &out["notes"]), "{\"v\":2}");
}

mod typed_blocks {
    use super::*;
    use ragewarden_core::sync::{outer_field, protected_field_names, protects_field};
    use std::collections::BTreeMap;

    fn strings(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn server_copy(c: &CipherIn, id: &str) -> Cipher {
        let mut v = body(c);
        v["id"] = json!(id);
        to_cipher(&v)
    }

    #[test]
    fn a_card_draft_is_a_type_3_cipher_with_its_protected_fields_only_in_the_blob() {
        let s = session();
        let draft = CipherDraft {
            name: "Visa".into(),
            card: Some(strings(&[
                ("cardholderName", "O C"),
                ("brand", "Visa"),
                ("number", "4111111111111111"),
                ("expMonth", "12"),
                ("expYear", "2030"),
                ("code", "123"),
            ])),
            protected_fields: vec!["number".into(), "code".into()],
            ..CipherDraft::default()
        };
        let built = build_cipher(&s, &draft, Some("BLOB")).unwrap();
        let out = body(&built);
        assert_eq!(out["type"], 3);
        assert!(out.get("secureNote").is_none());
        assert_eq!(dec(&s, &out["card"]["CardholderName"]), "O C");
        assert_eq!(dec(&s, &out["card"]["ExpYear"]), "2030");
        assert!(
            out["card"].get("Number").is_none(),
            "a protected number stays out of Type-2"
        );
        assert!(out["card"].get("Code").is_none());

        let c = server_copy(&built, "card-1");
        assert_eq!(protected_field_names(&s, &c).unwrap(), ["number", "code"]);
        assert!(protects_field(&s, &c, "code").unwrap());
        assert!(!protects_field(&s, &c, "brand").unwrap());
        assert_eq!(
            outer_field(&s, &c, "brand").unwrap().as_deref(),
            Some("Visa")
        );
        assert_eq!(outer_field(&s, &c, "number").unwrap(), None);

        let rotated = body(&rewrap_preserving(&s, &c, "BLOB2").unwrap());
        assert_eq!(
            rotated["card"], out["card"],
            "a rotation keeps the card block"
        );
        let again = to_cipher(&{
            let mut v = rotated.clone();
            v["id"] = json!("card-1");
            v
        });
        assert_eq!(
            protected_field_names(&s, &again).unwrap(),
            ["number", "code"]
        );
    }

    #[test]
    fn identity_and_ssh_key_drafts_build_their_types() {
        let s = session();
        let identity = CipherDraft {
            name: "Me".into(),
            identity: Some(strings(&[
                ("title", "Dr"),
                ("firstName", "Octo"),
                ("company", "GitHub"),
                ("licenseNumber", "L-1"),
                ("ssn", "000-00-0000"),
                ("passportNumber", "P1"),
            ])),
            protected_fields: vec![
                "ssn".into(),
                "passportNumber".into(),
                "licenseNumber".into(),
            ],
            ..CipherDraft::default()
        };
        let out = body(&build_cipher(&s, &identity, Some("B")).unwrap());
        assert_eq!(out["type"], 4);
        assert_eq!(dec(&s, &out["identity"]["Title"]), "Dr");
        assert_eq!(dec(&s, &out["identity"]["Company"]), "GitHub");
        for gone in ["Ssn", "PassportNumber", "LicenseNumber"] {
            assert!(out["identity"].get(gone).is_none(), "{gone}");
        }

        let ssh = CipherDraft {
            name: "deploy".into(),
            ssh_key: Some(strings(&[
                ("privateKey", "openssh-key-v1 test material"),
                ("publicKey", "ssh-ed25519 AAAA"),
                ("keyFingerprint", "SHA256:abc"),
            ])),
            protected_fields: vec!["privateKey".into(), "passphrase".into()],
            ..CipherDraft::default()
        };
        let built = build_cipher(&s, &ssh, Some("B")).unwrap();
        let out = body(&built);
        assert_eq!(out["type"], 5);
        assert_eq!(dec(&s, &out["sshKey"]["PublicKey"]), "ssh-ed25519 AAAA");
        assert_eq!(dec(&s, &out["sshKey"]["KeyFingerprint"]), "SHA256:abc");
        assert_eq!(
            dec(&s, &out["sshKey"]["PrivateKey"]),
            RAGE_MARKER_NOTE,
            "Bitwarden needs every SSH key field; the protected one holds the marker"
        );
        let c = server_copy(&built, "ssh-1");
        assert!(protects_field(&s, &c, "passphrase").unwrap());
        assert!(
            protects_field(&s, &c, "").unwrap(),
            "the primary field of an SSH key is its private key"
        );
    }

    #[test]
    fn a_draft_names_one_kind_and_only_known_block_fields() {
        let s = session();
        let two = CipherDraft {
            card: Some(strings(&[("number", "1")])),
            ssh_key: Some(strings(&[("publicKey", "k")])),
            ..CipherDraft::default()
        };
        assert!(build_cipher(&s, &two, None).is_err());
        let login_and_card = CipherDraft {
            login: true,
            card: Some(strings(&[("number", "1")])),
            ..CipherDraft::default()
        };
        assert!(build_cipher(&s, &login_and_card, None).is_err());
        let unknown = CipherDraft {
            card: Some(strings(&[("pin", "1")])),
            ..CipherDraft::default()
        };
        assert!(build_cipher(&s, &unknown, None).is_err());
        let protected_without_blob = CipherDraft {
            protected_fields: vec!["notes".into()],
            ..CipherDraft::default()
        };
        assert!(build_cipher(&s, &protected_without_blob, None).is_err());
    }

    #[test]
    fn editing_a_block_keeps_the_rest_and_unknown_keys_and_a_note_can_become_a_card() {
        let s = session();
        let server = json!({
            "id": "card-2", "type": 3, "name": enc(&s, "Amex"),
            "card": {
                "cardholderName": enc(&s, "A"), "brand": enc(&s, "Amex"),
                "expMonth": enc(&s, "1"), "futureField": "kept-as-is"
            }
        });
        let edit = CipherEdit {
            card: Some(strings(&[("brand", ""), ("expMonth", "2")])),
            ..CipherEdit::default()
        };
        let out = body(&edit_preserving(&s, &to_cipher(&server), None, &edit).unwrap());
        assert_eq!(
            out["card"]["CardholderName"],
            server["card"]["cardholderName"]
        );
        assert!(
            out["card"].get("Brand").is_none(),
            "an empty value clears a field"
        );
        assert_eq!(dec(&s, &out["card"]["ExpMonth"]), "2");
        assert_eq!(out["card"]["futureField"], "kept-as-is");

        let note = body(&build_rage_cipher(&s, "old card as note", "BLOB").unwrap());
        let edit = CipherEdit {
            card: Some(strings(&[("cardholderName", "O")])),
            ..CipherEdit::default()
        };
        let converted = body(&edit_preserving(&s, &to_cipher(&note), None, &edit).unwrap());
        assert_eq!(converted["type"], 3);
        assert!(converted.get("secureNote").is_none());
        assert_eq!(rage_values(&s, &converted), vec!["BLOB".to_string()]);

        let login = full_login(&s);
        let edit = CipherEdit {
            identity: Some(strings(&[("firstName", "x")])),
            ..CipherEdit::default()
        };
        assert!(edit_preserving(&s, &to_cipher(&login), None, &edit).is_err());
    }

    #[test]
    fn protecting_more_fields_of_a_login_moves_them_out_of_type_2() {
        let s = session();
        let server = full_login(&s);
        let edit = CipherEdit {
            protected_fields: Some(vec![
                "password".into(),
                "notes".into(),
                "recovery email".into(),
            ]),
            ..CipherEdit::default()
        };
        let built = edit_preserving(&s, &to_cipher(&server), Some("V2BLOB"), &edit).unwrap();
        let out = body(&built);
        assert!(out["login"].get("Password").is_none());
        assert_eq!(dec(&s, &out["notes"]), RAGE_MARKER_NOTE);
        let names: Vec<String> = out["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| dec(&s, &f["name"]))
            .collect();
        assert!(!names.contains(&"recovery email".to_string()), "{names:?}");
        assert!(names.contains(&"linked".to_string()));
        let c = to_cipher(&{
            let mut v = out.clone();
            v["id"] = json!("c-1");
            v
        });
        assert_eq!(
            protected_field_names(&s, &c).unwrap(),
            ["password", "notes", "recovery email"]
        );
        assert!(protects_field(&s, &c, "recovery email").unwrap());
        assert!(!protects_field(&s, &c, "username").unwrap());

        let back_to_v1 = CipherEdit {
            protected_fields: Some(vec!["password".into()]),
            ..CipherEdit::default()
        };
        let out = body(&edit_preserving(&s, &c, Some("V1BLOB"), &back_to_v1).unwrap());
        let markers = out["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| dec(&s, &f["name"]) == "rage:fields")
            .count();
        assert_eq!(markers, 0, "a primary-only blob carries no marker");
    }

    #[test]
    fn an_item_without_a_marker_protects_its_primary_field() {
        let s = session();
        let login = to_cipher(&{
            let mut v = body(&rewrap_preserving(&s, &to_cipher(&full_login(&s)), "B").unwrap());
            v["id"] = json!("c-1");
            v
        });
        assert_eq!(protected_field_names(&s, &login).unwrap(), ["password"]);
        assert!(protects_field(&s, &login, "").unwrap());
        assert_eq!(
            outer_field(&s, &login, "username").unwrap().as_deref(),
            Some("octocat")
        );
        assert_eq!(
            outer_field(&s, &login, "recovery email")
                .unwrap()
                .as_deref(),
            Some("o@example.com")
        );

        let note = to_cipher(&{
            let mut v = body(&build_rage_cipher(&s, "n", "B").unwrap());
            v["id"] = json!("n-1");
            v
        });
        assert!(
            protects_field(&s, &note, "password").unwrap(),
            "a note's password is its body"
        );
        let plain = to_cipher(&full_login(&s));
        assert!(protected_field_names(&s, &plain).unwrap().is_empty());
    }
}
