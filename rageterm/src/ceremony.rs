//! The words the user reads immediately before touching a device.
//!
//! `core::Identity::try_unwrap_stanza` takes no context argument, so the
//! command layer parks a `Ceremony` here and the PIV / FIDO2 identities read it
//! back when they are about to block on the device. Nothing here grants
//! consent; consent is the physical touch. This module only guarantees that the
//! destination is named on screen *before* the device is asked.

use std::fmt;
use std::io::Write;
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ceremony {
    /// Verb the user typed: "Copy", "Reveal", "Autofill", ...
    pub action: String,
    /// Item the credential belongs to.
    pub item: String,
    /// Where the plaintext is about to go: "clipboard", "stdout",
    /// "FD 3 of `ssh`", "github.com". Never empty.
    pub destination: String,
}

impl Ceremony {
    pub fn new(action: &str, item: &str, destination: &str) -> Self {
        Self {
            action: action.to_string(),
            item: item.to_string(),
            destination: destination.to_string(),
        }
    }
}

impl fmt::Display for Ceremony {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} `{}` -> {}", self.action, self.item, self.destination)
    }
}

static CURRENT: Mutex<Option<Ceremony>> = Mutex::new(None);

/// Restores the previous ceremony on drop so nested calls (`rotate` decrypts
/// then re-encrypts) cannot leave a stale destination on screen.
pub struct CeremonyGuard {
    previous: Option<Ceremony>,
}

impl Drop for CeremonyGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = CURRENT.lock() {
            *slot = self.previous.take();
        }
    }
}

pub fn set(ceremony: Ceremony) -> CeremonyGuard {
    let previous = match CURRENT.lock() {
        Ok(mut slot) => slot.replace(ceremony),
        Err(poisoned) => {
            let mut slot = poisoned.into_inner();
            slot.replace(ceremony)
        }
    };
    CeremonyGuard { previous }
}

pub fn current() -> Option<Ceremony> {
    match CURRENT.lock() {
        Ok(slot) => slot.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

/// What a device backend prints right before it blocks. `device` is a concrete
/// description ("YubiKey #0a1b2c3d slot 0x9d", "FIDO2 authenticator") so the
/// user can tell which token to touch.
pub fn announce_touch(device: &str, why: &str) {
    let mut err = std::io::stderr();
    match current() {
        Some(c) => {
            let _ = writeln!(err, "\nRagewarden: {c}");
            let _ = writeln!(err, "  {why} -- touch {device} now (Ctrl-C to cancel).");
        }
        None => {
            let _ = writeln!(err, "\nRagewarden: {why}");
            let _ = writeln!(err, "  Touch {device} now (Ctrl-C to cancel).");
        }
    }
    let _ = err.flush();
}

/// A blocking step that is *not* a touch (PIN entry, enrollment setup). Kept
/// separate so nothing prints "touch" when no touch is coming.
pub fn announce_step(text: &str) {
    let mut err = std::io::stderr();
    let _ = writeln!(err, "Ragewarden: {text}");
    let _ = err.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_the_destination() {
        let c = Ceremony::new("Copy", "aws/prod", "clipboard");
        assert_eq!(c.to_string(), "Copy `aws/prod` -> clipboard");
    }

    #[test]
    fn guard_restores_previous_ceremony() {
        let outer = set(Ceremony::new("Rotate", "a", "re-encrypt"));
        assert_eq!(current().unwrap().action, "Rotate");
        {
            let _inner = set(Ceremony::new("Copy", "a", "clipboard"));
            assert_eq!(current().unwrap().action, "Copy");
        }
        assert_eq!(current().unwrap().action, "Rotate");
        drop(outer);
        assert!(current().is_none());
    }
}
