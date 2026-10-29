//! Cross-client recipient-policy conformance.
//!
//! DEFECT A: rageterm, ragedroid and ragemanifest each reimplemented "which
//! recipients does a new secret get wrapped to?" in a different language, and
//! the three answers disagreed. An item written on Android could be
//! cryptographically unopenable in the browser, and vice versa, with both
//! clients reporting success. A 265-test green suite never noticed, because
//! every one of those tests only ever exercised one language's filter.
//!
//! This file is the guard. It
//!   1. reproduces the three legacy filters verbatim and asserts they diverge,
//!      so the test provably would have caught the bug;
//!   2. asserts the canonical `policy::select_encrypt_recipients` gives every
//!      client the same recipient set for the same registry, no matter which
//!      route the client takes into core, with exactly one sanctioned and
//!      *reported* difference (`SkipReason::NoLocalAuthenticator`);
//!   3. pins the wire encoding of that set into `tests/vectors/`, which each
//!      client's own route reads back and must reproduce: ragedroid's JNI
//!      `select_encrypt_recipients` (`ragedroid/jni`, plus Kotlin's
//!      `RecipientPolicyConformanceTest`) and the browser's
//!      `recipient_select::select_encrypt_recipients`
//!      (`ragemanifest/tests/recipient_vectors.rs`), so a client that adds its
//!      own filter or drifts in serialization fails a test instead of
//!      producing an unopenable item.

use std::collections::BTreeSet;

use ragewarden_core::Recipient;
use ragewarden_core::policy::{self, LocalAuthenticators, Selection, SkipReason};
use ragewarden_core::registry::{WireDocument, WireEntry, kinds};

const VECTOR_PATH: &str = "tests/vectors/recipient_policy_v1.json";

const P256_GENERATOR_COMPRESSED: &str =
    "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn blank(id: &str, kind: &str, created_at: i64) -> WireEntry {
    WireEntry {
        id: id.into(),
        kind: kind.into(),
        display_name: id.into(),
        device_label: "fixture".into(),
        created_at,
        default_encrypt: true,
        piv_pubkey: None,
        piv_serial: None,
        piv_slot: None,
        keystore_pubkey: None,
        keystore_handle: None,
        fido2_credential_id: None,
        fido2_rp_id: None,
        fido2_salt: None,
        recovery_armored_pubkey: None,
        stanza_version: None,
        attestation_public_key: None,
    }
}

/// One registry containing every kind a real user can end up with: a terminal
/// software key, a paper recovery key, a YubiKey, an Android StrongBox key, an
/// `hmac-secret` authenticator, plus a disabled entry and a malformed one.
///
/// `e-fido2` used to be described here as "a browser passkey". It is not, and
/// the mislabel was load-bearing: `kinds::FIDO2` decodes to
/// `Recipient::Fido2HmacSecret`, which wraps into the `fido2-hmac` stanza. That
/// is right for an Android passkey or a security key with `hmac-secret`
/// (ragedroid's `RecipientPolicy.kt` publishes exactly this), and wrong for a
/// browser's WebAuthn-PRF passkey, which wraps into `webauthn-prf-v1` with a
/// different HKDF info. The browser case lives in
/// [`browser_passkey_registry`] under `kinds::PASSKEY_PRF`; it is a separate
/// fixture rather than an eighth entry here because the Kotlin conformance test
/// pins the exact skip list this registry produces.
fn fixture_registry() -> Vec<WireEntry> {
    let mut software = blank("e-software", kinds::SOFTWARE, 1_000);
    software.recovery_armored_pubkey =
        Some("age1nukguzqzgkpd087j2ju3v54x9rdhzfq6gwms9cw35lvdwq3chpuq6xz32k".into());

    let mut recovery = blank("e-recovery", kinds::RECOVERY, 2_000);
    recovery.recovery_armored_pubkey =
        Some("age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj".into());

    let mut yubikey = blank("e-yubikey", kinds::YUBIKEY, 3_000);
    yubikey.piv_pubkey = Some(hex(&[0x11u8; 32]));
    yubikey.piv_serial = Some(0x0012_3456);
    yubikey.piv_slot = Some(0x95);

    let mut strongbox = blank("e-strongbox", kinds::STRONG_BOX, 4_000);
    strongbox.keystore_pubkey = Some(P256_GENERATOR_COMPRESSED.into());
    strongbox.keystore_handle = Some("ragewarden-keystore-fixture".into());

    let mut passkey = blank("e-fido2", kinds::FIDO2, 5_000);
    passkey.fido2_credential_id = Some(hex(b"fixture-credential"));
    passkey.fido2_salt = Some(hex(&[0x22u8; 32]));
    passkey.fido2_rp_id = Some("ragewarden".into());

    let mut disabled = blank("e-disabled", kinds::SOFTWARE, 6_000);
    disabled.default_encrypt = false;
    disabled.recovery_armored_pubkey = Some("age1disabledxxxxxxxxxxxxxxxxxxxxx".into());

    let mut malformed = blank("e-malformed", kinds::STRONG_BOX, 7_000);
    malformed.keystore_pubkey = Some("00".repeat(32));
    malformed.keystore_handle = Some("legacy".into());

    vec![
        software, recovery, yubikey, strongbox, passkey, disabled, malformed,
    ]
}

/// The two PRF kinds side by side, which is the only place they can be told
/// apart: everything else about them is identical on the wire (same `fido2*`
/// fields, same shape) and only `kind` decides which stanza tag the recipient
/// wraps into.
///
/// Kept deliberately small and separate from [`fixture_registry`]. The Kotlin
/// conformance test pins `fixture_registry`'s skip list and recipient count
/// exactly, so adding an eighth entry there would fail a test in a language
/// this crate cannot rebuild; a new top-level vector field is invisible to it
/// (`Json { ignoreUnknownKeys = true }`, and it looks fields up by name).
fn browser_passkey_registry() -> Vec<WireEntry> {
    let mut hmac_secret = blank("e-fido2", kinds::FIDO2, 5_000);
    hmac_secret.fido2_credential_id = Some(hex(b"fixture-credential"));
    hmac_secret.fido2_salt = Some(hex(&[0x22u8; 32]));
    hmac_secret.fido2_rp_id = Some("ragewarden".into());

    let mut prf = blank("e-browser-passkey", kinds::PASSKEY_PRF, 8_000);
    prf.display_name = "Browser passkey".into();
    prf.device_label = "Browser extension".into();
    prf.fido2_credential_id = Some(hex(b"browser-credential"));
    prf.fido2_salt = Some(hex(&[0x33u8; 32]));
    prf.fido2_rp_id = Some("ragewarden".into());

    vec![hmac_secret, prf]
}

/// The defect this fixture exists for: ragemanifest published its WebAuthn-PRF
/// passkey under `kind: "Fido2"`, so every client -- including the browser that
/// owns the key -- read it back as a `Fido2HmacSecret` recipient and wrapped it
/// into the `fido2-hmac` stanza. ragemanifest has no `fido2-hmac` code at all
/// (`src/wasm/sync.rs` filters to `TAG_WEBAUTHN_PRF_V1`), so an item wrapped to
/// that entry was permanently unopenable in the browser that enrolled it.
///
/// The wire kind is the *whole* difference, so this pins it from both ends.
#[test]
fn browser_passkey_prf_is_a_different_recipient_than_fido2_hmac() {
    let registry = browser_passkey_registry();

    let hmac = registry[0].to_recipient().expect("Fido2 decodes");
    assert!(
        matches!(hmac, Recipient::Fido2HmacSecret { .. }),
        "kind=Fido2 must stay fido2-hmac; ragedroid depends on it: {hmac:?}",
    );

    let prf = registry[1].to_recipient().expect("PasskeyPrf decodes");
    let Recipient::PasskeyPrf { ref label, .. } = prf else {
        panic!("kind=PasskeyPrf must decode to Recipient::PasskeyPrf, got {prf:?}");
    };
    assert_eq!(
        label, "Browser passkey",
        "the PRF label is the entry's displayName; a client shows it to the user",
    );

    let mut mistagged = registry[1].clone();
    mistagged.kind = kinds::FIDO2.into();
    assert!(
        matches!(
            mistagged.to_recipient(),
            Some(Recipient::Fido2HmacSecret { .. }),
        ),
        "the mistag is silent at the registry layer, which is why it survived",
    );

    assert_ne!(
        fingerprint(&[prf]),
        fingerprint(&[mistagged.to_recipient().unwrap()]),
    );
}

/// Fail-closed, without a key: naming ONE PRF entry as locally reachable must
/// not reach the other. The two entries differ only by kind and credential id,
/// which is exactly the shape a "close enough, wrap it anyway" bug takes.
#[test]
fn holding_one_prf_authenticator_never_reaches_the_other() {
    let registry = browser_passkey_registry();

    let nothing_local = policy::select_for_encrypt(&registry, &[], &LocalAuthenticators::none());
    assert!(
        nothing_local.recipients.is_empty(),
        "no authenticator here, so neither PRF entry may be wrapped to: {:?}",
        nothing_local.recipients,
    );
    let mut holes: Vec<&str> = nothing_local
        .unreachable_authenticators()
        .map(|s| s.id.as_str())
        .collect();
    holes.sort_unstable();
    assert_eq!(
        holes,
        vec!["e-browser-passkey", "e-fido2"],
        "both coverage holes must be reported, not just the one that decodes",
    );

    let browser = policy::select_for_encrypt(
        &registry,
        &[],
        &LocalAuthenticators::from_ids(["e-browser-passkey"]),
    );
    assert_eq!(
        fingerprint(&browser.recipients).len(),
        1,
        "{:?}",
        browser.recipients,
    );
    assert!(matches!(
        browser.recipients[0],
        Recipient::PasskeyPrf { .. }
    ));
    assert_eq!(
        browser
            .unreachable_authenticators()
            .map(|s| s.id.as_str())
            .collect::<Vec<_>>(),
        vec!["e-fido2"],
    );
}

/// A stable, language-independent fingerprint of a recipient set. Two clients
/// agree iff these sets are equal.
fn fingerprint(recipients: &[Recipient]) -> BTreeSet<String> {
    recipients
        .iter()
        .map(|r| match r {
            Recipient::X25519 { public_key } => format!("x25519:{}", hex(public_key)),
            Recipient::YubiKeyPiv {
                public_key,
                serial,
                slot,
                ..
            } => format!("piv:{}:{serial}:{slot}", hex(public_key)),
            Recipient::YubiKeyPivP256 {
                public_key,
                serial,
                slot,
            } => format!("piv:{}:{serial}:{slot}", hex(public_key)),
            Recipient::Fido2HmacSecret {
                credential_id,
                salt,
                rp_id,
            } => format!("fido2:{}:{}:{rp_id}", hex(credential_id), hex(salt)),
            Recipient::PasskeyPrf {
                credential_id,
                salt,
                rp_id,
                label,
            } => format!(
                "passkey:{}:{}:{rp_id}:{label}",
                hex(credential_id),
                hex(salt)
            ),
            Recipient::AndroidKeystore {
                public_key,
                key_handle,
                ..
            } => format!("keystore:{}:{key_handle}", hex(public_key)),
            Recipient::SoftwarePassphrase { armored_pubkey } => {
                format!("software:{}", armored_pubkey.as_str())
            }
        })
        .collect()
}

/// rageterm `recipients.rs::load_active_recipients_for_encrypt`: registry
/// entries via `to_recipient_if_active`, then `encryptable_from_this_device`
/// dropped every PRF kind.
fn legacy_rageterm(entries: &[WireEntry]) -> Vec<Recipient> {
    entries
        .iter()
        .filter_map(|e| e.to_recipient_if_active())
        .filter(|r| {
            !matches!(
                r,
                Recipient::Fido2HmacSecret { .. } | Recipient::PasskeyPrf { .. }
            )
        })
        .collect()
}

/// ragemanifest `ext/glue/vault.js::buildEncryptRecipients`: kept only Software
/// and Recovery, and never looked at `defaultEncrypt`.
fn legacy_ragemanifest(entries: &[WireEntry]) -> Vec<Recipient> {
    entries
        .iter()
        .filter(|e| e.kind == kinds::SOFTWARE || e.kind == kinds::RECOVERY)
        .filter_map(|e| e.recovery_armored_pubkey.clone())
        .map(|armored| Recipient::SoftwarePassphrase {
            armored_pubkey: ragewarden_core::ArmoredAgeRecipient::from_trusted(armored),
        })
        .collect()
}

/// ragedroid `BitwardenVaultRepository.kt::collectActiveRecipients`: honoured
/// `defaultEncrypt`, handled YubiKey / StrongBox / Recovery / Fido2, and threw
/// Software away (`RecipientKind.Software -> Unit`).
fn legacy_ragedroid(entries: &[WireEntry]) -> Vec<Recipient> {
    entries
        .iter()
        .filter(|e| e.default_encrypt)
        .filter(|e| e.kind != kinds::SOFTWARE)
        .filter_map(|e| e.to_recipient())
        .collect()
}

#[test]
fn the_three_legacy_filters_disagreed_on_one_registry() {
    let entries = fixture_registry();

    let term = fingerprint(&legacy_rageterm(&entries));
    let manifest = fingerprint(&legacy_ragemanifest(&entries));
    let droid = fingerprint(&legacy_ragedroid(&entries));

    assert_ne!(term, manifest, "fixture no longer exercises the divergence");
    assert_ne!(term, droid);
    assert_ne!(manifest, droid);

    let sw = "software:age1nukguzqzgkpd087j2ju3v54x9rdhzfq6gwms9cw35lvdwq3chpuq6xz32k";
    assert!(
        !droid.iter().any(|f| f == sw),
        "ragedroid used to drop Software recipients, so a phone-written item \
         was unopenable by the terminal's software key",
    );
    assert!(
        !manifest.iter().any(|f| f.starts_with("keystore:")),
        "ragemanifest used to drop StrongBox, so a browser-written item was \
         unopenable on the phone",
    );
    assert!(
        !manifest.iter().any(|f| f.starts_with("piv:")),
        "ragemanifest used to drop YubiKey PIV",
    );
    assert!(
        manifest.iter().any(|f| f.contains("age1disabled")),
        "ragemanifest used to ignore defaultEncrypt=false",
    );
    assert!(
        !term.iter().any(|f| f.contains("age1disabled")),
        "rageterm honoured defaultEncrypt=false",
    );
}

/// The point of the fix: one registry, one answer, for everybody -- reached by
/// three genuinely different routes and three different local capabilities.
///
/// The routes are not cosmetic. They are the shapes the three clients actually
/// hand to core, and each one has its own way of quietly changing the answer:
///   * **rageterm** links core directly and passes its *own* copy of the
///     software entry as `local_entries`, so the merge path runs and could
///     double-wrap or shadow an entry;
///   * **ragemanifest** crosses the wasm boundary, so the entries have been
///     through `JSON.stringify` / `serde_json` before the policy sees them and
///     a serde attribute could drop a field;
///   * **ragedroid** comes in over JNI, where the entries are collected from a
///     Kotlin map and arrive in unspecified order, so an order-dependent
///     policy would show up here.
///
/// They also differ in what they can physically reach: only the browser holds
/// the WebAuthn passkey. That is the ONE divergence the policy sanctions, and
/// this test pins that it is the only one -- an earlier version of this test
/// called the policy three times with identical arguments, which of course
/// could never fail.
#[test]
fn policy_is_deterministic_across_order_json_hops_and_local_copies_except_the_reachable_prf() {
    let registry = fixture_registry();

    let mut terminal_local = blank("e-software", kinds::SOFTWARE, 1_000);
    terminal_local.device_label = "rageterm-laptop".into();
    terminal_local.recovery_armored_pubkey =
        Some("age1nukguzqzgkpd087j2ju3v54x9rdhzfq6gwms9cw35lvdwq3chpuq6xz32k".into());
    let rageterm = policy::select_for_encrypt(
        &registry,
        std::slice::from_ref(&terminal_local),
        &LocalAuthenticators::none(),
    );

    let serialized = serde_json::to_string(&WireDocument {
        schema: ragewarden_core::registry::SCHEMA_VERSION,
        entries: registry.clone(),
    })
    .unwrap();
    let hopped: WireDocument = serde_json::from_str(&serialized).unwrap();
    let ragemanifest = policy::select_for_encrypt(
        &hopped.entries,
        &[],
        &LocalAuthenticators::from_ids(["e-fido2"]),
    );

    let mut jni_order = registry.clone();
    jni_order.reverse();
    let ragedroid = policy::select_for_encrypt(
        &jni_order,
        &[],
        &LocalAuthenticators::from_ids(["e-strongbox"]),
    );

    let term = fingerprint(&rageterm.recipients);
    let manifest = fingerprint(&ragemanifest.recipients);
    let droid = fingerprint(&ragedroid.recipients);

    assert_eq!(term, droid, "route/order changed the recipient set");
    assert_eq!(
        rageterm.recipients, ragedroid.recipients,
        "recipient ORDER diverged; clients must wrap in the same sequence",
    );

    let extra: Vec<&String> = manifest.difference(&term).collect();
    assert_eq!(
        extra.len(),
        1,
        "expected exactly the PRF recipient to differ; {manifest:?} vs {term:?}",
    );
    assert!(extra[0].starts_with("fido2:"), "{}", extra[0]);
    assert!(
        term.difference(&manifest).next().is_none(),
        "reaching an authenticator must never REMOVE a recipient",
    );

    for (name, sel) in [("rageterm", &rageterm), ("ragedroid", &ragedroid)] {
        let unreachable: Vec<&str> = sel
            .unreachable_authenticators()
            .map(|s| s.id.as_str())
            .collect();
        assert_eq!(
            unreachable,
            vec!["e-fido2"],
            "{name} must report the coverage hole it just created",
        );
    }
    assert_eq!(
        ragemanifest.unreachable_authenticators().count(),
        0,
        "the client holding the passkey has no coverage hole to report",
    );

    assert_eq!(
        term.len(),
        4,
        "software + recovery + yubikey + strongbox, {term:?}",
    );
    assert!(term.iter().any(|x| x.starts_with("software:age1nukg")));
    assert!(term.iter().any(|x| x.starts_with("software:age1zvky")));
    assert!(term.iter().any(|x| x.starts_with("piv:")));
    assert!(term.iter().any(|x| x.starts_with("keystore:")));
}

/// The one sanctioned difference, and it is loud.
#[test]
fn the_only_divergence_is_a_named_reported_exception() {
    let entries = fixture_registry();

    let no_authenticator = policy::select_for_encrypt(&entries, &[], &LocalAuthenticators::none());
    let holds_passkey =
        policy::select_for_encrypt(&entries, &[], &LocalAuthenticators::from_ids(["e-fido2"]));

    let a = fingerprint(&no_authenticator.recipients);
    let b = fingerprint(&holds_passkey.recipients);

    let only_extra: Vec<&String> = b.difference(&a).collect();
    assert_eq!(only_extra.len(), 1);
    assert!(only_extra[0].starts_with("fido2:"));
    assert!(
        a.difference(&b).next().is_none(),
        "holding an authenticator must never remove a recipient",
    );

    let unreachable: Vec<&str> = no_authenticator
        .unreachable_authenticators()
        .map(|s| s.id.as_str())
        .collect();
    assert_eq!(unreachable, vec!["e-fido2"]);
    assert_eq!(holds_passkey.unreachable_authenticators().count(), 0);
}

#[test]
fn every_skip_carries_a_reason() {
    let sel = policy::select_for_encrypt(&fixture_registry(), &[], &LocalAuthenticators::none());
    let mut by_id: Vec<(&str, SkipReason)> = sel
        .skipped
        .iter()
        .map(|s| (s.id.as_str(), s.reason))
        .collect();
    by_id.sort_by_key(|(id, _)| *id);
    assert_eq!(
        by_id,
        vec![
            ("e-disabled", SkipReason::DefaultEncryptOff),
            ("e-fido2", SkipReason::NoLocalAuthenticator),
            ("e-malformed", SkipReason::MalformedKeyMaterial),
        ],
    );
}

/// The registry round-trips through JSON between languages; the policy must be
/// stable across that hop, since ragedroid and ragemanifest feed it the parsed
/// document rather than the Rust struct.
#[test]
fn policy_is_stable_across_a_json_round_trip_of_the_registry() {
    let doc = WireDocument {
        schema: ragewarden_core::registry::SCHEMA_VERSION,
        entries: fixture_registry(),
    };
    let json = serde_json::to_string(&doc).unwrap();
    let parsed: WireDocument = serde_json::from_str(&json).unwrap();

    let direct = policy::select_for_encrypt(&doc.entries, &[], &LocalAuthenticators::none());
    let hopped = policy::select_for_encrypt(&parsed.entries, &[], &LocalAuthenticators::none());
    assert_eq!(direct, hopped);
}

/// Pins the exact bytes the other two languages must produce/consume. Regenerate
/// deliberately with `RAGEWARDEN_BLESS_VECTORS=1 cargo test -p ragewarden-core`.
#[test]
fn wire_vectors_match_the_checked_in_file() {
    let entries = fixture_registry();
    let doc = WireDocument {
        schema: ragewarden_core::registry::SCHEMA_VERSION,
        entries: entries.clone(),
    };

    let browser = browser_passkey_registry();
    let browser_doc = WireDocument {
        schema: ragewarden_core::registry::SCHEMA_VERSION,
        entries: browser.clone(),
    };

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Vectors {
        policy_version: u32,
        registry: WireDocument,
        no_local_authenticator: Selection,
        holds_fido2: Selection,
        browser_passkey_registry: WireDocument,
        browser_passkey_no_local_authenticator: Selection,
        browser_passkey_holds_prf: Selection,
    }

    let actual = Vectors {
        policy_version: policy::POLICY_VERSION,
        registry: doc,
        no_local_authenticator: policy::select_for_encrypt(
            &entries,
            &[],
            &LocalAuthenticators::none(),
        ),
        holds_fido2: policy::select_for_encrypt(
            &entries,
            &[],
            &LocalAuthenticators::from_ids(["e-fido2"]),
        ),
        browser_passkey_registry: browser_doc,
        browser_passkey_no_local_authenticator: policy::select_for_encrypt(
            &browser,
            &[],
            &LocalAuthenticators::none(),
        ),
        browser_passkey_holds_prf: policy::select_for_encrypt(
            &browser,
            &[],
            &LocalAuthenticators::from_ids(["e-browser-passkey"]),
        ),
    };

    let rendered = serde_json::to_string_pretty(&actual).unwrap() + "\n";

    if std::env::var_os("RAGEWARDEN_BLESS_VECTORS").is_some() {
        std::fs::create_dir_all("tests/vectors").unwrap();
        std::fs::write(VECTOR_PATH, &rendered).unwrap();
        return;
    }

    let on_disk = std::fs::read_to_string(VECTOR_PATH).unwrap_or_else(|e| {
        panic!("{VECTOR_PATH} missing ({e}); regenerate with RAGEWARDEN_BLESS_VECTORS=1")
    });
    let parsed: Vectors = serde_json::from_str(&on_disk)
        .unwrap_or_else(|e| panic!("{VECTOR_PATH} does not parse: {e}"));
    assert_eq!(
        parsed, actual,
        "{VECTOR_PATH} is stale; the ragedroid and ragemanifest conformance tests read it",
    );
}
