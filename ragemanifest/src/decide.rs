use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ragewarden_core::stanza_format::{
    TAG_FIDO2_HMAC, TAG_PIV_P256, TAG_PIV_X25519_V2, TAG_WEBAUTHN_PRF_V1,
    webauthn_prf_credential_id, webauthn_prf_salt,
};
use ragewarden_core::{ArmoredAgeRecipient, Recipient, Stanza};
use serde::Deserialize;

pub type PrfPair = (Vec<u8>, [u8; 32]);

pub fn native_unwrappable(stanzas: Vec<Stanza>) -> Vec<Stanza> {
    stanzas
        .into_iter()
        .filter(|s| [TAG_PIV_P256, TAG_PIV_X25519_V2, TAG_FIDO2_HMAC].contains(&s.tag.as_str()))
        .collect()
}

pub fn webauthn_prf_pairs(stanzas: &[Stanza]) -> Result<Vec<PrfPair>, String> {
    let mut out = Vec::new();
    for s in stanzas.iter().filter(|s| s.tag == TAG_WEBAUTHN_PRF_V1) {
        let cred = webauthn_prf_credential_id(s)
            .map_err(|e| format!("webauthn-prf credential_id: {e}"))?;
        let salt = webauthn_prf_salt(s).map_err(|e| format!("webauthn-prf salt: {e}"))?;
        out.push((cred, salt));
    }
    Ok(out)
}

pub fn check_stanza_reference(
    index: Option<f64>,
    echoed: Option<&Stanza>,
    offered: &[Stanza],
) -> Result<(), String> {
    let index = match index {
        None => None,
        Some(n) if n.fract() != 0.0 || n < 0.0 || n >= offered.len() as f64 => {
            return Err(
                "native callback returned a stanzaIndex outside the set of stanzas it was \
                 handed"
                    .into(),
            );
        }
        Some(n) => Some(n as usize),
    };
    let Some(echoed) = echoed else {
        return Ok(());
    };
    match index {
        Some(i) if offered[i] != *echoed => Err(
            "native callback returned a stanza that disagrees with the stanzaIndex it also \
             returned"
                .into(),
        ),
        _ if !offered.contains(echoed) => {
            Err("native callback returned a stanza that was not in the set it was handed".into())
        }
        _ => Ok(()),
    }
}

pub fn parse_field_map(json: &str) -> Result<Vec<(String, String)>, String> {
    let map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(json).map_err(|e| format!("parse fields: {e}"))?;
    map.into_iter()
        .map(|(k, v)| match v.as_str() {
            Some(s) => Ok((k, s.to_string())),
            None => Err(format!("field `{k}` not a string")),
        })
        .collect()
}

#[derive(Deserialize)]
struct WireRecipient {
    kind: String,
    #[serde(default)]
    armored_pubkey: Option<String>,
    #[serde(default)]
    public_key_b64: Option<String>,
    #[serde(default)]
    credential_id_b64: Option<String>,
    #[serde(default)]
    salt_b64: Option<String>,
    #[serde(default)]
    rp_id: Option<String>,
    #[serde(default)]
    label: Option<String>,
}

fn decode_b64(what: &str, v: Option<String>, kind: &str) -> Result<Vec<u8>, String> {
    let v = v.ok_or_else(|| format!("{kind} recipient needs {what}"))?;
    B64.decode(v.as_bytes()).map_err(|e| format!("{what}: {e}"))
}

fn wire_to_recipient(r: WireRecipient) -> Result<Recipient, String> {
    match r.kind.as_str() {
        "software" => Ok(Recipient::SoftwarePassphrase {
            armored_pubkey: ArmoredAgeRecipient::from_trusted(
                r.armored_pubkey
                    .ok_or("software recipient needs armored_pubkey")?,
            ),
        }),
        "x25519" => {
            let pk = decode_b64("public_key_b64", r.public_key_b64, "x25519")?;
            let public_key: [u8; 32] = pk
                .try_into()
                .map_err(|v: Vec<u8>| format!("x25519 pubkey wrong length: {}", v.len()))?;
            Ok(Recipient::X25519 { public_key })
        }
        "passkey_prf" => {
            let credential_id =
                decode_b64("credential_id_b64", r.credential_id_b64, "passkey_prf")?;
            let rp_id = r.rp_id.ok_or("passkey_prf recipient needs rp_id")?;
            let salt_vec = decode_b64("salt_b64", r.salt_b64, "passkey_prf")?;
            let salt: [u8; 32] = salt_vec
                .try_into()
                .map_err(|v: Vec<u8>| format!("salt_b64 must be 32 bytes, got {}", v.len()))?;
            Ok(Recipient::PasskeyPrf {
                credential_id,
                salt,
                rp_id,
                label: r.label.unwrap_or_else(|| "passkey".to_string()),
            })
        }
        other => Err(format!("unsupported recipient kind: {other}")),
    }
}

/// The canonical serde shape first, then the popup's flat wire shape.
pub fn parse_recipients(json: &str) -> Result<Vec<Recipient>, String> {
    let out = match serde_json::from_str::<Vec<Recipient>>(json) {
        Ok(canonical) => canonical,
        Err(_) => serde_json::from_str::<Vec<WireRecipient>>(json)
            .map_err(|e| format!("parse recipients: {e}"))?
            .into_iter()
            .map(wire_to_recipient)
            .collect::<Result<_, _>>()?,
    };
    if out.is_empty() {
        return Err("recipients list empty".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stanza(tag: &str, args: &[&str]) -> Stanza {
        Stanza {
            tag: tag.to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
            body: vec![1, 2, 3],
        }
    }

    #[test]
    fn only_piv_and_fido2_stanzas_go_to_the_native_host() {
        let all = vec![
            stanza(TAG_PIV_P256, &["a"]),
            stanza(TAG_WEBAUTHN_PRF_V1, &["b"]),
            stanza(TAG_FIDO2_HMAC, &["c"]),
            stanza("X25519", &["d"]),
            stanza(TAG_PIV_X25519_V2, &["e"]),
            stanza("ragedroid-keystore-v2", &["f"]),
        ];
        let tags: Vec<_> = native_unwrappable(all).into_iter().map(|s| s.tag).collect();
        assert_eq!(
            tags,
            vec![
                TAG_PIV_P256.to_string(),
                TAG_FIDO2_HMAC.to_string(),
                TAG_PIV_X25519_V2.to_string()
            ]
        );
    }

    #[test]
    fn a_stanza_reference_must_point_into_the_offered_set() {
        let offered = vec![stanza(TAG_PIV_P256, &["a"]), stanza(TAG_FIDO2_HMAC, &["b"])];
        assert!(check_stanza_reference(None, None, &offered).is_ok());
        assert!(check_stanza_reference(Some(1.0), Some(&offered[1]), &offered).is_ok());
        assert!(check_stanza_reference(None, Some(&offered[0]), &offered).is_ok());
        for bad in [2.0, -1.0, 0.5] {
            assert!(
                check_stanza_reference(Some(bad), None, &offered)
                    .unwrap_err()
                    .contains("outside the set")
            );
        }
        assert!(
            check_stanza_reference(Some(0.0), Some(&offered[1]), &offered)
                .unwrap_err()
                .contains("disagrees")
        );
        let foreign = stanza(TAG_PIV_P256, &["zzz"]);
        assert!(
            check_stanza_reference(None, Some(&foreign), &offered)
                .unwrap_err()
                .contains("not in the set")
        );
    }

    #[test]
    fn field_maps_are_string_to_string() {
        assert_eq!(
            parse_field_map(r#"{"name":"n","rage":"s"}"#).unwrap().len(),
            2
        );
        assert!(
            parse_field_map(r#"{"name":1}"#)
                .unwrap_err()
                .contains("`name` not a string")
        );
    }

    #[test]
    fn wire_recipients_parse_and_refuse_malformed_entries() {
        let salt = B64.encode([7u8; 32]);
        let cred = B64.encode([9u8; 16]);
        let ok = format!(
            r#"[{{"kind":"passkey_prf","credential_id_b64":"{cred}","salt_b64":"{salt}","rp_id":"example.test"}},
               {{"kind":"x25519","public_key_b64":"{}"}}]"#,
            B64.encode([3u8; 32])
        );
        let r = parse_recipients(&ok).unwrap();
        assert!(matches!(&r[0], Recipient::PasskeyPrf { label, .. } if label == "passkey"));
        assert!(matches!(r[1], Recipient::X25519 { .. }));
        assert!(parse_recipients("[]").unwrap_err().contains("empty"));
        assert!(parse_recipients(&format!(
            r#"[{{"kind":"passkey_prf","credential_id_b64":"{cred}","salt_b64":"AAAA","rp_id":"x"}}]"#
        ))
        .unwrap_err()
        .contains("32 bytes"));
        assert!(
            parse_recipients(r#"[{"kind":"x25519","public_key_b64":"AAAA"}]"#)
                .unwrap_err()
                .contains("wrong length")
        );
        assert!(
            parse_recipients(r#"[{"kind":"telepathy"}]"#)
                .unwrap_err()
                .contains("unsupported recipient kind")
        );
    }
}
