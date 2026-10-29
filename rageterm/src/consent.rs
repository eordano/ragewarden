//! Consent gate for every command that turns a stored blob into plaintext.
//!
//! The gate is not a message and not a flag: it is *which identities are handed
//! to `ragewarden_core::decrypt`*. `require` only builds the guard; the guard is
//! the only thing `commands::decrypt_named` accepts, and `decrypt_named` asks it
//! what may be offered the header. So no rageterm command reaches plaintext
//! without the rules below. A process that reads the config directory itself is
//! outside this gate: `identity.age` is passphrase-encrypted when enrolled at a
//! terminal, and a bare one is only as private as its file permissions.
//!
//! 1. A blob that names an enrolled *real* device in its header is unwrapped by
//!    that device or not at all. `decrypt_named` runs a hardware-only pass
//!    first; the software / keyring / paper keys are not in that list, so the
//!    file key can only come off the device. If the device is absent the pass
//!    fails and the error is returned -- it never falls through to the software
//!    keys, because falling through is exactly what made `get` weaker after
//!    enrolling a YubiKey than before it.
//!
//! 2. A blob that names no enrolled device is software-protected, whatever is
//!    plugged in. Claiming a tap there would be a lie, so the y/N prompt is the
//!    gate and it says so. `--yes` may skip that prompt only when no real device
//!    is enrolled at all; with a real device enrolled `--yes` is refused and the
//!    confirmation must be typed, so no `rageterm` invocation on a
//!    hardware-enrolled vault can produce plaintext unattended.
//!
//! `--yes` therefore cannot skip a tap in any branch: on the hardware path it is
//! never consulted, and on the software path it is either honest about there
//! being no device or refused outright.
//!
//! The prompt is read from the controlling terminal, never from stdin: with the
//! old stdin read, `printf 'y\n' | rageterm copy x` answered its own prompt.

use std::sync::atomic::{AtomicBool, Ordering};

use std::io::{self};
#[cfg(not(test))]
use std::io::{BufRead, IsTerminal, Write};

use thiserror::Error;

use crate::ceremony::{self, Ceremony, CeremonyGuard};
use crate::identities::{Identities, IdentityKind};

#[derive(Debug, Error)]
pub enum ConsentError {
    #[error("cancelled")]
    Cancelled,

    #[error(
        "refusing to {action}: this secret names no enrolled device in its \
         header, so it is software-protected and a typed confirmation is the \
         only gate there is -- and there is no terminal to type it on. Protect \
         the item with a device (`rageterm enroll-yubikey` / `enroll-fido2`, \
         then `rageterm reencrypt <item>`) so the tap is the consent, or run this \
         from a terminal."
    )]
    NoConsentSurface { action: String },

    #[error(
        "refusing to {action} with `--yes`: a real hardware identity is \
         enrolled, but this secret names no device in its header, so nothing \
         physical can authorize it. `--yes` will not turn a hardware-protected \
         vault into an unattended software read. Confirm at the terminal, or \
         run `rageterm reencrypt {item}` so the device actually protects it."
    )]
    YesRefusedOnHardwareVault { action: String, item: String },

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("identities: {0}")]
    Identities(String),
}

/// Which identities `commands::build_identity_list_for` may return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityPolicy {
    /// Only identities backed by a real, physically present device. The
    /// software key file, the OS keyring key, paper recovery and every mock
    /// stand-in are excluded, so a file key obtained under this policy came off
    /// a device.
    HardwareOnly,
    /// Everything enrolled. Only reachable after `ConsentGuard::authorize_software`
    /// has succeeded.
    SoftwareAllowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SoftwareGate {
    /// A y/N answer has to be typed on the controlling terminal.
    Prompt,
    /// `--yes` was given and no real device is enrolled: the prompt is skipped
    /// and the fact that no tap happened is printed.
    YesFlag,
    /// The caller already took an explicit, interactive confirmation of its own
    /// (the TUI overlay's `[Enter]`). Stands in for the prompt, never for a tap.
    AlreadyConfirmed,
}

/// Held for the duration of the delivery so the ceremony text stays current,
/// and carries the decision about what may decrypt. Constructible only by this
/// module: `commands::decrypt_named` takes one by reference, so no caller can
/// reach plaintext without coming through `require` / `require_after_confirm`.
pub struct ConsentGuard {
    _ceremony: CeremonyGuard,
    ceremony_text: String,
    action: String,
    item: String,
    hardware: HardwareState,
    gate: SoftwareGate,
    software_granted: AtomicBool,
}

impl ConsentGuard {
    pub fn hardware(&self) -> HardwareState {
        self.hardware
    }

    /// The credential this consent was taken for. `decrypt_named` refuses to
    /// decrypt anything else with it, so a guard obtained for a cheap item
    /// cannot be reused to open an expensive one.
    pub fn item(&self) -> &str {
        &self.item
    }

    /// True once, and only once, the software-only path has been authorized for
    /// this delivery. Read by the tests that assert the software keys were never
    /// even offered a device-protected header.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn software_authorized(&self) -> bool {
        self.software_granted.load(Ordering::SeqCst)
    }

    /// Must succeed before any non-device identity is offered the header.
    ///
    /// Reached only when the hardware-only pass reported that no enrolled
    /// device is named in this blob, so the honest description is "software
    /// only" and that is what gets printed.
    pub fn authorize_software(&self) -> Result<(), ConsentError> {
        if self.software_granted.load(Ordering::SeqCst) {
            return Ok(());
        }

        let why = match self.hardware {
            HardwareState::Real => {
                "a device is enrolled, but this secret names none of its keys in \
                 its header, so no tap can authorize it"
            }
            HardwareState::None => "no hardware identity enrolled",
            HardwareState::MockOnly => {
                "the only enrolled \"hardware\" identities are software stand-ins"
            }
        };

        match self.gate {
            SoftwareGate::YesFlag if self.hardware == HardwareState::Real => {
                return Err(ConsentError::YesRefusedOnHardwareVault {
                    action: format!("{} `{}`", self.action, self.item),
                    item: self.item.clone(),
                });
            }
            SoftwareGate::YesFlag => {
                ceremony::announce_step(&format!(
                    "{} -- SOFTWARE-ONLY ({why}; `--yes` given, no tap was performed).",
                    self.ceremony_text
                ));
            }
            SoftwareGate::AlreadyConfirmed => {
                ceremony::announce_step(&format!(
                    "{} -- SOFTWARE-ONLY ({why}; confirmed in the UI, no tap was \
                     performed).",
                    self.ceremony_text
                ));
            }
            SoftwareGate::Prompt => {
                confirm(&format!(
                    "{}\n(software-only: {why}, so this prompt is the only gate)",
                    self.ceremony_text
                ))
                .map_err(|e| match e {
                    ConsentError::NoConsentSurface { .. } => ConsentError::NoConsentSurface {
                        action: format!("{} `{}`", self.action, self.item),
                    },
                    other => other,
                })?;
            }
        }

        self.software_granted.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareState {
    /// No PIV / FIDO2 identity at all.
    None,
    /// At least one identity backed by a physical device.
    Real,
    /// Hardware identities exist but every one of them is a software stand-in.
    /// Treated exactly like `None`: claiming "this needs a hardware tap" here
    /// would be a lie, and skipping the prompt would be a bypass.
    MockOnly,
}

pub fn hardware_state() -> Result<HardwareState, ConsentError> {
    let ids = Identities::load().map_err(|e| ConsentError::Identities(e.to_string()))?;
    let mut saw_hardware = false;
    let mut saw_real = false;
    for entry in ids.items.values() {
        match &entry.kind {
            IdentityKind::YubiKeyPiv { mock, .. } | IdentityKind::Fido2HmacSecret { mock, .. } => {
                saw_hardware = true;
                saw_real |= !*mock;
            }
            _ => {}
        }
    }
    Ok(match (saw_hardware, saw_real) {
        (false, _) => HardwareState::None,
        (true, true) => HardwareState::Real,
        (true, false) => HardwareState::MockOnly,
    })
}

/// Gate one use of one credential. `action` is the user-facing verb, `item` the
/// credential name, `destination` where the plaintext is about to land.
///
/// This returns a guard, not a decision. The decision is taken in
/// `commands::decrypt_named`, which is the only function that can turn the
/// guard into plaintext and which asks the guard before offering any software
/// key to the header.
pub fn require(
    action: &str,
    item: &str,
    destination: &str,
    yes: bool,
) -> Result<ConsentGuard, ConsentError> {
    crate::hw::warn_banner_once();

    let hardware = hardware_state()?;
    let ceremony = Ceremony::new(action, item, destination);
    let ceremony_text = ceremony.to_string();
    let guard = ceremony::set(ceremony);

    if hardware == HardwareState::Real {
        ceremony::announce_step(&format!(
            "{ceremony_text} -- hardware-gated: if this secret names your device, \
             only the device can unwrap it and `--yes` does not apply."
        ));
    }

    let gate = if yes && hardware != HardwareState::Real {
        SoftwareGate::YesFlag
    } else {
        SoftwareGate::Prompt
    };

    Ok(ConsentGuard {
        _ceremony: guard,
        ceremony_text,
        action: action.to_string(),
        item: item.to_string(),
        hardware,
        gate,
        software_granted: AtomicBool::new(false),
    })
}

/// For the TUI, whose overlay `[Enter]` is the confirmation. `UiConfirmed` can
/// only be built by that key handler, so no other caller can claim a
/// confirmation it never took. It stands in for the y/N prompt and for nothing
/// else: the hardware rules in `decrypt_named` are identical either way.
pub fn require_after_confirm(
    action: &str,
    item: &str,
    destination: &str,
    _confirmed: crate::tui::UiConfirmed,
) -> Result<ConsentGuard, ConsentError> {
    crate::hw::warn_banner_once();

    let hardware = hardware_state()?;
    let ceremony = Ceremony::new(action, item, destination);
    let ceremony_text = ceremony.to_string();
    let guard = ceremony::set(ceremony);

    Ok(ConsentGuard {
        _ceremony: guard,
        ceremony_text,
        action: action.to_string(),
        item: item.to_string(),
        hardware,
        gate: SoftwareGate::AlreadyConfirmed,
        software_granted: AtomicBool::new(false),
    })
}

/// y/N prompt on the controlling terminal. Used both by `ConsentGuard` and by
/// the destructive-operation confirmations (`delete`, recipient removal) that
/// are not credential uses.
pub fn confirm(prompt: &str) -> Result<(), ConsentError> {
    let answer = ask(prompt)?;
    let trimmed = answer.trim().to_ascii_lowercase();
    if trimmed == "y" || trimmed == "yes" {
        Ok(())
    } else {
        Err(ConsentError::Cancelled)
    }
}

#[cfg(all(unix, not(test)))]
fn ask(prompt: &str) -> Result<String, ConsentError> {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    {
        Ok(tty) => {
            let mut w = &tty;
            write!(w, "{prompt}? [y/N] ")?;
            w.flush()?;
            let mut reader = io::BufReader::new(&tty);
            let mut buf = String::new();
            reader.read_line(&mut buf)?;
            Ok(buf)
        }
        Err(_) => ask_via_stdin(prompt),
    }
}

#[cfg(all(not(unix), not(test)))]
fn ask(prompt: &str) -> Result<String, ConsentError> {
    ask_via_stdin(prompt)
}

#[cfg(not(test))]
fn ask_via_stdin(prompt: &str) -> Result<String, ConsentError> {
    if !io::stdin().is_terminal() {
        return Err(ConsentError::NoConsentSurface {
            action: "continue".into(),
        });
    }
    eprint!("{prompt}? [y/N] ");
    io::stderr().flush()?;
    let mut buf = String::new();
    io::stdin().lock().read_line(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
pub(crate) static TEST_TTY_ANSWER: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Answer the next prompts with `answer`, or with "there is no terminal" when
/// `None`. Callers hold `tests_lock::ENV_LOCK` for the same reason they hold it
/// around the environment: this is process-global.
#[cfg(test)]
pub(crate) fn set_test_tty_answer(answer: Option<&str>) {
    let mut slot = TEST_TTY_ANSWER.lock().unwrap_or_else(|e| e.into_inner());
    *slot = answer.map(|s| s.to_string());
}

#[cfg(test)]
fn ask(_prompt: &str) -> Result<String, ConsentError> {
    let slot = TEST_TTY_ANSWER.lock().unwrap_or_else(|e| e.into_inner());
    match slot.as_deref() {
        Some(answer) => Ok(answer.to_string()),
        None => Err(ConsentError::NoConsentSurface {
            action: "continue".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_hardware_enrolled_in_an_empty_config() {
        let tmp = tempfile::TempDir::new().unwrap();
        let _g = crate::tests_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::tests_lock::set_var("RAGEWARDEN_CONFIG_DIR", tmp.path());
        let result = hardware_state();
        crate::tests_lock::remove_var("RAGEWARDEN_CONFIG_DIR");
        assert_eq!(result.unwrap(), HardwareState::None);
    }

    #[test]
    fn a_mock_only_vault_does_not_count_as_hardware_gated() {
        use crate::identities::{EnrolledIdentity, IdentityKind};

        let tmp = tempfile::TempDir::new().unwrap();
        let _g = crate::tests_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::tests_lock::set_var("RAGEWARDEN_CONFIG_DIR", tmp.path());

        let mut ids = Identities::default();
        ids.insert(EnrolledIdentity {
            id: "mock-yk".into(),
            kind: IdentityKind::YubiKeyPiv {
                public_key_hex: "00".repeat(32),
                serial: 1,
                slot: 0x95,
                mock: true,
            },
            label: crate::hw::mock_label("YubiKey"),
            created: chrono::Utc::now(),
            last_used: None,
        });
        ids.save().unwrap();
        let mock_only = hardware_state();

        ids.insert(EnrolledIdentity {
            id: "real-yk".into(),
            kind: IdentityKind::YubiKeyPiv {
                public_key_hex: "11".repeat(32),
                serial: 2,
                slot: 0x9d,
                mock: false,
            },
            label: "YubiKey".into(),
            created: chrono::Utc::now(),
            last_used: None,
        });
        ids.save().unwrap();
        let with_real = hardware_state();

        crate::tests_lock::remove_var("RAGEWARDEN_CONFIG_DIR");
        assert_eq!(mock_only.unwrap(), HardwareState::MockOnly);
        assert_eq!(with_real.unwrap(), HardwareState::Real);
    }
}
