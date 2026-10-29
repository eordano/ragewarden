//! Pins core's audit vocabulary into tests/vectors/audit_vocabulary_v1.json,
//! the list the browser and Android logs must write from (their own tests read
//! it). Regenerate deliberately with
//! `RAGEWARDEN_BLESS_VECTORS=1 cargo test -p ragewarden-core --test audit_vocabulary`.

use ragewarden_core::audit::{AuditKind, AuditResult};

const VECTOR_PATH: &str = "tests/vectors/audit_vocabulary_v1.json";

fn name<T: serde::Serialize>(v: T) -> String {
    serde_json::to_value(v)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn the_vocabulary_matches_the_checked_in_vectors() {
    let legacy: serde_json::Map<String, serde_json::Value> = AuditKind::LEGACY_NAMES
        .iter()
        .map(|(old, kind)| (old.to_string(), serde_json::Value::String(name(kind))))
        .collect();
    let kinds: Vec<String> = AuditKind::ALL.iter().map(name).collect();
    let results = [AuditResult::Ok, AuditResult::Declined, AuditResult::Failed].map(name);
    let actual = serde_json::json!({
        "vocabulary_version": 1,
        "kinds": kinds,
        "legacy_names": legacy,
        "results": results,
    });
    let rendered = serde_json::to_string_pretty(&actual).unwrap() + "\n";
    if std::env::var_os("RAGEWARDEN_BLESS_VECTORS").is_some() {
        std::fs::write(VECTOR_PATH, &rendered).unwrap();
        return;
    }
    let on_disk = std::fs::read_to_string(VECTOR_PATH)
        .unwrap_or_else(|e| panic!("{VECTOR_PATH} missing ({e}); bless it"));
    assert_eq!(on_disk, rendered, "{VECTOR_PATH} is stale");
}

#[test]
fn every_kind_and_legacy_name_round_trips() {
    for kind in AuditKind::ALL {
        let back: AuditKind = serde_json::from_value(serde_json::to_value(kind).unwrap()).unwrap();
        assert_eq!(back, *kind);
    }
    for (old, kind) in AuditKind::LEGACY_NAMES {
        let back: AuditKind =
            serde_json::from_value(serde_json::Value::String(old.to_string())).unwrap();
        assert_eq!(back, *kind, "{old}");
    }
}
