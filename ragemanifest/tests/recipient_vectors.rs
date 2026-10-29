//! The browser's recipient selection, run through its real route (registry
//! document in a synced vault -> policy -> JSON for the JS side), against the
//! vectors core pins in core/tests/vectors/recipient_policy_v1.json.

use ragemanifest::recipient_select::select_encrypt_recipients;
use ragewarden_core::registry::MARKER_NAME;
use ragewarden_core::sync::{Cipher, KdfParams, Session, Vault, build_meta_cipher};
use serde_json::Value;

const VECTORS: &str = include_str!("../../core/tests/vectors/recipient_policy_v1.json");

fn session() -> Session {
    Session {
        access_token: ragewarden_core::BearerToken::from_trusted("t".into()),
        refresh_token: ragewarden_core::RefreshToken::from_trusted("r".into()),
        user_id: "u".into(),
        email: "a@example.com".into(),
        user_enc_key: vec![0x11; 32].into(),
        user_mac_key: vec![0x22; 32].into(),
        kdf: KdfParams::default(),
        device_id: "d".into(),
    }
}

fn vault_with_registry(session: &Session, registry: &Value) -> Vault {
    let body = build_meta_cipher(session, MARKER_NAME, &registry.to_string()).unwrap();
    let mut cipher: Cipher = serde_json::from_value(serde_json::to_value(&body).unwrap()).unwrap();
    cipher.id = Some("registry".into());
    Vault {
        ciphers: vec![cipher],
        ..Vault::default()
    }
}

fn check(registry_key: &str, local: Option<Vec<&str>>, expected_key: &str) {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let s = session();
    let vault = vault_with_registry(&s, &vectors[registry_key]);
    let selection = select_encrypt_recipients(
        &s,
        &vault,
        local.map(|ids| ids.into_iter().map(String::from).collect()),
    )
    .unwrap();
    let wire: Value = serde_json::from_str(&serde_json::to_string(&selection).unwrap()).unwrap();
    assert_eq!(wire, vectors[expected_key], "{expected_key}");
}

#[test]
fn no_local_authenticator() {
    check("registry", None, "no_local_authenticator");
}

#[test]
fn holding_the_fido2_key() {
    check("registry", Some(vec!["e-fido2"]), "holds_fido2");
}

#[test]
fn browser_passkey_registry_without_the_passkey() {
    check(
        "browser_passkey_registry",
        None,
        "browser_passkey_no_local_authenticator",
    );
}

#[test]
fn browser_passkey_registry_holding_the_passkey() {
    check(
        "browser_passkey_registry",
        Some(vec!["e-browser-passkey"]),
        "browser_passkey_holds_prf",
    );
}
