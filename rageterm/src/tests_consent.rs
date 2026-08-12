//! What the consent gate has to guarantee, stated as "no plaintext came out".
//!
//! Every assertion here is about the *absence* of plaintext, not about a
//! message on stderr. The bug these cover printed "this needs a hardware tap"
//! and then returned the secret anyway, so a test that checks the printing
//! would have passed against the broken code.

use tempfile::TempDir;

use ragewarden_core::{decrypt, encrypt, AgeBlob, DecryptError, Plaintext, Recipient};

use crate::commands::{self, CmdError};
use crate::consent::{self, HardwareState, IdentityPolicy};
use crate::identities::{EnrolledIdentity, Identities, IdentityKind};
use crate::tests_lock::ENV_LOCK;

const PIV_SERIAL: u32 = 0x0a0b0c0d;
const PIV_SLOT: u8 = 0x9d;

/// Holds `ENV_LOCK` for its lifetime, points the config dir at a fresh
/// temporary directory, and leaves the test terminal answering "there is no
/// terminal" unless a test says otherwise.
struct Isolated {
    _guard: std::sync::MutexGuard<'static, ()>,
    _dir: TempDir,
    prev_config: Option<std::ffi::OsString>,
}

impl Drop for Isolated {
    fn drop(&mut self) {
        consent::set_test_tty_answer(None);
        match self.prev_config.take() {
            Some(p) => std::env::set_var("RAGEWARDEN_CONFIG_DIR", p),
            None => std::env::remove_var("RAGEWARDEN_CONFIG_DIR"),
        }
    }
}

fn isolated() -> Isolated {
    let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new().expect("tempdir");
    let prev_config = std::env::var_os("RAGEWARDEN_CONFIG_DIR");
    std::env::set_var("RAGEWARDEN_CONFIG_DIR", dir.path());
    consent::set_test_tty_answer(None);
    Isolated {
        _guard: guard,
        _dir: dir,
        prev_config,
    }
}

fn enroll_software_key() -> Recipient {
    commands::cmd_enroll_software_identity().expect("enroll software identity");
    let id = crate::idfile::read(&crate::config::identity_path().unwrap()).expect("read identity");
    Recipient::SoftwarePassphrase {
        armored_pubkey: ragewarden_core::ArmoredAgeRecipient::from_trusted(
            id.to_public().to_string(),
        ),
    }
}

/// An identity record that claims to be a real YubiKey (`mock: false`). Nothing
/// in the record can decrypt on its own: unwrapping it reaches `real_ecdh`,
/// which needs PC/SC, a reader and the card. That is the point -- this is the
/// "device enrolled, device not here" case.
fn enroll_real_piv(label: &str) -> Recipient {
    let secret = x25519_dalek::StaticSecret::from([42u8; 32]);
    let public_key = *x25519_dalek::PublicKey::from(&secret).as_bytes();

    let mut ids = Identities::load().expect("identities");
    ids.insert(EnrolledIdentity {
        id: "real-piv".into(),
        kind: IdentityKind::YubiKeyPiv {
            public_key_hex: hex::encode(public_key),
            serial: PIV_SERIAL,
            slot: PIV_SLOT,
            mock: false,
        },
        label: label.into(),
        created: chrono::Utc::now(),
        last_used: None,
    });
    ids.save().expect("save identities");

    Recipient::YubiKeyPiv {
        public_key,
        serial: PIV_SERIAL,
        slot: PIV_SLOT,
    }
}

fn enroll_mock_piv(label: &str) {
    let secret = x25519_dalek::StaticSecret::from([43u8; 32]);
    let public_key = *x25519_dalek::PublicKey::from(&secret).as_bytes();

    let mut ids = Identities::load().expect("identities");
    ids.insert(EnrolledIdentity {
        id: "mock-piv".into(),
        kind: IdentityKind::YubiKeyPiv {
            public_key_hex: hex::encode(public_key),
            serial: 1,
            slot: 0x95,
            mock: true,
        },
        label: crate::hw::mock_label(label),
        created: chrono::Utc::now(),
        last_used: None,
    });
    ids.save().expect("save identities");
}

fn store_item(name: &str, plaintext: &[u8], recipients: &[Recipient]) {
    let blob = encrypt(plaintext, recipients).expect("encrypt");
    let armored = String::from_utf8(blob.0).expect("armored utf-8");
    let store_path = crate::config::store_path().unwrap();
    crate::config::ensure_config_dir().unwrap();
    let mut store = crate::store::Store::load(&store_path).unwrap();
    store.upsert(name, armored, chrono::Utc::now());
    store.save(&store_path).unwrap();
}

fn stored_blob(name: &str) -> AgeBlob {
    let store_path = crate::config::store_path().unwrap();
    let store = crate::store::Store::load(&store_path).unwrap();
    AgeBlob::from_bytes(store.get(name).expect("item").rage_blob.clone().into_bytes())
}

/// Fails the test if `result` carries plaintext, without printing the plaintext.
fn expect_no_plaintext(result: Result<Plaintext, CmdError>, what: &str) -> CmdError {
    match result {
        Ok(pt) => panic!("{what}: {} bytes of plaintext were produced", pt.len()),
        Err(e) => e,
    }
}

/// The defect, stated directly: a blob wrapped to an enrolled YubiKey must not
/// come out of `decrypt_named` when the YubiKey is not there -- not even though
/// the same blob is also wrapped to the software key sitting in the config
/// directory, and not even with `--yes` and no terminal.
#[test]
fn a_secret_the_device_protects_is_not_revealed_when_the_device_is_absent() {
    let _iso = isolated();
    let software = enroll_software_key();
    let piv = enroll_real_piv("YubiKey #0a0b0c0d slot 0x9d");
    const SECRET: &[u8] = b"plaintext-that-must-not-appear";
    store_item("db-password", SECRET, &[software, piv]);

    // Control: the software key really can open this blob, so the refusal below
    // is the gate doing its job and not a fixture that never decrypted.
    let everything = commands::build_identity_list().expect("identity list");
    let control = decrypt(&stored_blob("db-password"), &everything).expect("software key opens it");
    assert_eq!(control.as_slice(), SECRET);
    drop(control);

    assert_eq!(consent::hardware_state().unwrap(), HardwareState::Real);

    let guard = consent::require("Print", "db-password", "stdout", true).expect("guard");
    let err = expect_no_plaintext(
        commands::decrypt_named("db-password", &guard),
        "device absent",
    );

    assert!(
        !err.to_string()
            .contains(std::str::from_utf8(SECRET).unwrap()),
        "the error text leaked the secret: {err}"
    );
    assert!(
        !guard.software_authorized(),
        "the software path must not even be offered for a device-protected blob"
    );
}

/// `--yes` on a vault with a real device enrolled cannot produce plaintext
/// unattended, even for an item the device does not protect. A typed `y` can --
/// which is what proves the fixture is readable and the refusal was the gate.
#[test]
fn yes_cannot_read_a_software_only_secret_on_a_hardware_enrolled_vault() {
    let _iso = isolated();
    let software = enroll_software_key();
    enroll_real_piv("YubiKey #0a0b0c0d slot 0x9d");
    const SECRET: &[u8] = b"legacy-item-not-rotated-yet";
    store_item("legacy", SECRET, &[software]);

    consent::set_test_tty_answer(None);
    let guard = consent::require("Print", "legacy", "stdout", true).expect("guard");
    let err = expect_no_plaintext(
        commands::decrypt_named("legacy", &guard),
        "--yes with no terminal",
    );
    assert!(
        err.to_string().contains("no terminal"),
        "expected the no-consent-surface refusal, got: {err}"
    );
    assert!(!guard.software_authorized());

    consent::set_test_tty_answer(Some("n"));
    let guard = consent::require("Print", "legacy", "stdout", true).expect("guard");
    let err = expect_no_plaintext(commands::decrypt_named("legacy", &guard), "answered n");
    assert!(matches!(err, CmdError::Cancelled), "got {err}");

    consent::set_test_tty_answer(Some("y"));
    let guard = consent::require("Print", "legacy", "stdout", true).expect("guard");
    let pt = commands::decrypt_named("legacy", &guard).expect("typed confirmation");
    assert_eq!(pt.as_slice(), SECRET);
    assert!(guard.software_authorized());
}

/// The TUI overlay's `[Enter]` stands in for the y/N prompt and for nothing
/// else: it cannot open an item the device protects either.
#[test]
fn the_tui_confirmation_does_not_stand_in_for_a_tap() {
    let _iso = isolated();
    let software = enroll_software_key();
    let piv = enroll_real_piv("YubiKey #0a0b0c0d slot 0x9d");
    store_item("ssh-key", b"id_ed25519-body", &[software, piv]);

    let guard = consent::require_after_confirm("Copy", "ssh-key", "clipboard").expect("guard");
    expect_no_plaintext(
        commands::decrypt_named("ssh-key", &guard),
        "TUI confirm, device absent",
    );
    assert!(!guard.software_authorized());
}

/// With nothing but software keys enrolled, `--yes` keeps working for scripts --
/// the gate did not just become "always refuse".
#[test]
fn without_a_device_the_scriptable_yes_path_still_works() {
    let _iso = isolated();
    let software = enroll_software_key();
    const SECRET: &[u8] = b"ci-token";
    store_item("ci-token", SECRET, &[software]);

    assert_eq!(consent::hardware_state().unwrap(), HardwareState::None);
    consent::set_test_tty_answer(None);
    let guard = consent::require("Print", "ci-token", "stdout", true).expect("guard");
    let pt = commands::decrypt_named("ci-token", &guard).expect("software-only vault");
    assert_eq!(pt.as_slice(), SECRET);
    assert!(guard.software_authorized());
}

/// Without `--yes` and without a terminal there is no gate to satisfy, so a
/// software-only vault refuses too. (Unchanged behaviour; asserted so a future
/// edit cannot quietly open it.)
#[test]
fn a_software_only_vault_still_refuses_without_yes_and_without_a_terminal() {
    let _iso = isolated();
    let software = enroll_software_key();
    store_item("ci-token", b"ci-token", &[software]);

    consent::set_test_tty_answer(None);
    let guard = consent::require("Print", "ci-token", "stdout", false).expect("guard");
    expect_no_plaintext(
        commands::decrypt_named("ci-token", &guard),
        "no --yes, no terminal",
    );
}

/// The hardware-only identity list is the mechanism the gate rests on: if a key
/// that lives on disk ever got into it, the first pass would "succeed" with no
/// device involved and every test above would still pass.
#[test]
fn the_hardware_only_list_holds_no_key_that_lives_on_disk() {
    let _iso = isolated();
    let software = enroll_software_key();
    enroll_real_piv("real yk");
    enroll_mock_piv("mock yk");

    let hardware = commands::build_identity_list_for(IdentityPolicy::HardwareOnly).expect("list");
    let labels: Vec<&str> = hardware.iter().map(|i| i.display()).collect();
    assert_eq!(
        labels,
        vec!["real yk"],
        "only the real device may be in the hardware-only list"
    );

    let everything = commands::build_identity_list().expect("list");
    assert!(
        everything.len() > hardware.len(),
        "the software key and the stand-in must exist, just not in the gated list"
    );

    // And the list it produces cannot open a blob wrapped to the software key.
    store_item("sw-only", b"sw-only-secret", &[software]);
    assert!(
        matches!(
            decrypt(&stored_blob("sw-only"), &hardware),
            Err(DecryptError::NoMatchingIdentity)
        ),
        "the hardware-only list must not open a software-wrapped blob"
    );
}

/// One consent, one credential. A guard taken for a throwaway item cannot be
/// pointed at a different one.
#[test]
fn a_guard_only_opens_the_item_it_was_taken_for() {
    let _iso = isolated();
    let software = enroll_software_key();
    store_item("decoy", b"decoy-value", &[software.clone()]);
    store_item("real-secret", b"the-real-secret", &[software]);

    consent::set_test_tty_answer(None);
    let guard = consent::require("Print", "decoy", "stdout", true).expect("guard");
    let err = expect_no_plaintext(
        commands::decrypt_named("real-secret", &guard),
        "guard taken for another item",
    );
    assert!(err.to_string().contains("consent taken for"), "got {err}");
}

/// A `mock: true` enrollment is a file in the config directory. It must not
/// raise the vault to `Real`, and it must not appear in the gated list -- a
/// stand-in there would be the software path wearing a YubiKey's name.
#[test]
fn a_stand_in_never_counts_as_the_device() {
    let _iso = isolated();
    enroll_software_key();
    enroll_mock_piv("mock yk");

    assert_eq!(consent::hardware_state().unwrap(), HardwareState::MockOnly);
    let hardware = commands::build_identity_list_for(IdentityPolicy::HardwareOnly).expect("list");
    assert!(
        hardware.is_empty(),
        "a stand-in must not appear in the hardware-only list"
    );
}
