//! The single decision point for "is this a real device or a test stand-in?".
//!
//! Everything that can produce key material without a physical device lives
//! behind `mock_enabled()`. That function is compiled out entirely unless the
//! crate is built with `--features mock-hardware` or as a test binary, and the
//! `compile_error!` below makes `cargo build --release --features mock-hardware`
//! fail outright. A shipped `rageterm` therefore has no code path that turns
//! `RAGEWARDEN_MOCK_HARDWARE=1` into a usable identity.

#[cfg(all(feature = "mock-hardware", release_build))]
compile_error!(
    "the `mock-hardware` feature must never be enabled in a release build: it \
     compiles software stand-ins that can decrypt without a physical device"
);

pub const MOCK_ENV: &str = "RAGEWARDEN_MOCK_HARDWARE";

/// Prefix stamped onto every label a mock enrollment produces. `is_mock_label`
/// is the read side; `recipients list`, `identities` and the enroll output all
/// go through these two so a stand-in can never be mistaken for a device.
pub const MOCK_LABEL_PREFIX: &str = "[MOCK -- NOT REAL HARDWARE] ";

pub const MOCK_BANNER: &str = "\
!! RAGEWARDEN_MOCK_HARDWARE=1: hardware ceremonies are being SIMULATED IN SOFTWARE.
!! The \"tap\" is a file in the config directory. Nothing here is phishing-resistant.
!! This build is a test build; do not use it for real secrets.";

#[cfg(any(test, feature = "mock-hardware"))]
pub fn mock_enabled() -> bool {
    matches!(std::env::var(MOCK_ENV).as_deref(), Ok("1"))
}

#[cfg(not(any(test, feature = "mock-hardware")))]
pub fn mock_enabled() -> bool {
    false
}

/// True when the environment asks for mock mode but this binary cannot honour
/// it. Callers use this to explain the refusal instead of silently ignoring it.
pub fn mock_requested_but_unavailable() -> bool {
    !mock_supported() && matches!(std::env::var(MOCK_ENV).as_deref(), Ok("1"))
}

pub const fn mock_supported() -> bool {
    cfg!(any(test, feature = "mock-hardware"))
}

pub fn mock_label(base: &str) -> String {
    if is_mock_label(base) {
        base.to_string()
    } else {
        format!("{MOCK_LABEL_PREFIX}{base}")
    }
}

pub fn is_mock_label(label: &str) -> bool {
    label.starts_with(MOCK_LABEL_PREFIX)
}

/// Printed once per process, before anything that could be mistaken for a real
/// ceremony. Goes to stderr so it survives `rageterm get x > file`.
pub fn warn_banner_once() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static SHOWN: AtomicBool = AtomicBool::new(false);
    if mock_enabled() && !SHOWN.swap(true, Ordering::SeqCst) {
        eprintln!("{MOCK_BANNER}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_label_is_idempotent_and_detectable() {
        let once = mock_label("YubiKey #1");
        let twice = mock_label(&once);
        assert_eq!(once, twice);
        assert!(is_mock_label(&once));
        assert!(!is_mock_label("YubiKey #1"));
    }

    #[test]
    fn mock_supported_matches_cfg() {
        assert!(mock_supported());
        assert!(!mock_requested_but_unavailable());
    }
}
