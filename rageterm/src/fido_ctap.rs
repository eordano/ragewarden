//! The CTAP2-over-HID transport -- the only code in rageterm that talks to a
//! real FIDO2 authenticator. Nothing above this file knows `ctap_hid_fido2`
//! exists.
//!
//! DEVICE-BLOCKED: `make_credential` / `get_assertion` cannot run without an
//! authenticator, so the two `FidoError`-producing calls below are untested
//! here. Everything that *can* be tested without a device -- the error
//! classification and the extension-output extraction -- is split into free
//! functions with unit tests at the bottom.

use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::{
    Extension as AssertionExtension, GetAssertionArgsBuilder,
};
use ctap_hid_fido2::fidokey::make_credential::make_credential_params::{
    Extension as CredentialExtension, MakeCredentialArgsBuilder,
};
use ctap_hid_fido2::{Cfg, FidoKeyHid, FidoKeyHidFactory};
use rand::Rng;

use crate::ceremony;
use crate::fido::{Fido2Device, FidoError};

pub struct CtapDevice {
    key: FidoKeyHid,
    description: String,
    /// Cached for the lifetime of one command so a PIN is typed at most once.
    pin: Option<String>,
    /// What getInfo said about this authenticator's verification options,
    /// read once per opened device.
    verification: Option<Verification>,
}

/// Which verification a ceremony requests on its first attempt.
///
/// CTAP 2.1 keeps TWO per-credential hmac-secret seeds and selects between
/// them by the assertion's UV flag (§12.5, CredRandomWithUV /
/// CredRandomWithoutUV) -- so this choice is not UX, it decides WHICH 32-byte
/// secret the vault item is wrapped to. The rule:
///
///   * built-in UV configured (options.uv == true, e.g. a YubiKey Bio):
///     send `uv: true` and let the authenticator verify. The PRF binds to
///     CredRandomWithUV.
///   * a client PIN is set (options.clientPin == true): send pinUvAuthParam.
///     getAssertion does NOT demand this on its own -- per spec it happily
///     answers a PIN-less request with UV=0 and the possession-only seed, so
///     skipping the PIN here would not fail, it would silently bind the vault
///     to a secret the PIN never protects. The PIN must be asked for up
///     front, not on demand.
///   * neither: send neither option. `uv: true` to a device that cannot
///     verify anyone is CTAP2_ERR_INVALID_OPTION (a stock YubiKey out of the
///     box; the virtual CanoKey in tests/ragewarden-canokey.nix, which found
///     this) -- absence is the only correct encoding.
///
/// Corollary, asserted in the VM test: enabling a PIN on an already-enrolled
/// authenticator moves later assertions from the second seed to the first,
/// so items wrapped before the PIN stop opening. Re-enroll and rotate after
/// changing a key's PIN or biometric configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    BuiltInUv,
    Pin,
    PossessionOnly,
}

/// Pure so the arm selection is unit-testable without a device.
pub fn verification_plan(pin_set: bool, built_in_uv: bool) -> Verification {
    if built_in_uv {
        Verification::BuiltInUv
    } else if pin_set {
        Verification::Pin
    } else {
        Verification::PossessionOnly
    }
}

pub fn open_single_authenticator() -> Result<CtapDevice, FidoError> {
    let devices = ctap_hid_fido2::get_fidokey_devices();
    match devices.len() {
        0 => return Err(FidoError::NoDevice),
        1 => {}
        _ => return Err(FidoError::AmbiguousDevice),
    }
    let description = devices[0].info.clone();

    let cfg = Cfg::init();
    let key = FidoKeyHidFactory::create(&cfg).map_err(|e| classify(&e.to_string()))?;
    Ok(CtapDevice {
        key,
        description,
        pin: None,
        verification: None,
    })
}

impl CtapDevice {
    fn verification(&mut self) -> Result<Verification, FidoError> {
        if let Some(v) = self.verification {
            return Ok(v);
        }
        // One getInfo, scanned locally: enable_info_option() would issue a
        // fresh USB round trip per option.
        let info = self.key.get_info().map_err(|e| classify(&e.to_string()))?;
        let opt = |name: &str| {
            info.options
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, set)| *set)
        };
        let v = verification_plan(opt("clientPin") == Some(true), opt("uv") == Some(true));
        self.verification = Some(v);
        Ok(v)
    }

    fn prompt_pin(&mut self) -> Result<String, FidoError> {
        if let Some(pin) = &self.pin {
            return Ok(pin.clone());
        }
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            return Err(FidoError::NoPinPrompt);
        }
        ceremony::announce_step("this authenticator requires its FIDO2 PIN");
        let pin = rpassword::prompt_password("FIDO2 PIN: ").map_err(FidoError::Io)?;
        self.pin = Some(pin.clone());
        Ok(pin)
    }
}

impl Fido2Device for CtapDevice {
    fn make_hmac_credential(&mut self, rp_id: &str) -> Result<Vec<u8>, FidoError> {
        let mut challenge = [0u8; 32];
        rand::rng().fill_bytes(&mut challenge);
        let extensions = vec![CredentialExtension::HmacSecret(Some(true))];

        ceremony::announce_touch(
            &self.describe(),
            "Creating the hmac-secret credential this vault will be wrapped to",
        );

        // Which verification to request -- and so which CredRandom the vault
        // binds to -- is the `verification_plan` doc comment's subject; the
        // short version is that both getting it wrong ways are silent
        // (possession-only secrets, or CTAP2_ERR_INVALID_OPTION on keys with
        // nothing to verify), so it is decided from getInfo, not defaulted.
        let plan = self.verification()?;
        let mut pin: Option<String> = None;
        loop {
            // A set client PIN must be collected UP FRONT: only makeCredential
            // ever demands one on its own, and by the time an assertion is
            // being requested a PIN-less attempt would not fail -- it would
            // succeed against the wrong seed.
            if pin.is_none() && plan == Verification::Pin {
                pin = Some(self.prompt_pin()?);
            }
            let args = {
                let mut builder =
                    MakeCredentialArgsBuilder::new(rp_id, &challenge).extensions(&extensions);
                builder = match (pin.as_deref(), plan) {
                    (Some(p), _) => builder.pin(p),
                    // Builder default is uv: Some(true) -- kept, deliberately.
                    (None, Verification::BuiltInUv) => builder,
                    (None, _) => builder.without_pin_and_uv(),
                };
                builder.build()
            };
            let attestation = self.key.make_credential_with_args(&args);
            match attestation {
                Ok(att) => {
                    if !att
                        .extensions
                        .iter()
                        .any(|e| matches!(e, CredentialExtension::HmacSecret(_)))
                    {
                        return Err(FidoError::NoHmacSecret);
                    }
                    return Ok(att.credential_descriptor.id);
                }
                Err(e) => {
                    let classified = classify(&e.to_string());
                    if matches!(classified, FidoError::PinRequired) && pin.is_none() {
                        pin = Some(self.prompt_pin()?);
                        continue;
                    }
                    return Err(classified);
                }
            }
        }
    }

    fn hmac_secret(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
    ) -> Result<[u8; 32], FidoError> {
        let mut challenge = [0u8; 32];
        rand::rng().fill_bytes(&mut challenge);
        let extensions = vec![AssertionExtension::HmacSecret(Some(*salt))];

        ceremony::announce_touch(&self.describe(), "Unwrapping this credential");

        // Same rule as make_hmac_credential, and it matters MORE here: a
        // PIN-less getAssertion against a PIN-set key succeeds with UV=0 and
        // hands back the possession-only CredRandom's output -- a wrong-secret
        // path, not an error path. See `verification_plan`.
        let plan = self.verification()?;
        let mut pin: Option<String> = None;
        loop {
            if pin.is_none() && plan == Verification::Pin {
                pin = Some(self.prompt_pin()?);
            }
            let args = {
                let mut builder = GetAssertionArgsBuilder::new(rp_id, &challenge)
                    .credential_id(credential_id)
                    .extensions(&extensions);
                builder = match (pin.as_deref(), plan) {
                    (Some(p), _) => builder.pin(p),
                    (None, Verification::BuiltInUv) => builder,
                    (None, _) => builder.without_pin_and_uv(),
                };
                builder.build()
            };
            let assertion = self.key.get_assertion_with_args(&args);
            match assertion {
                Ok(assertions) => {
                    // One credential id was supplied, so the first assertion is
                    // the only one (allowList form of getAssertion).
                    let a = assertions
                        .first()
                        .ok_or_else(|| FidoError::Hardware("empty assertion list".into()))?;
                    return extract_hmac_output(&a.extensions);
                }
                Err(e) => {
                    let classified = classify(&e.to_string());
                    if matches!(classified, FidoError::PinRequired) && pin.is_none() {
                        pin = Some(self.prompt_pin()?);
                        continue;
                    }
                    return Err(classified);
                }
            }
        }
    }

    fn describe(&self) -> String {
        if self.description.trim().is_empty() {
            "your FIDO2 security key".to_string()
        } else {
            format!("your FIDO2 security key ({})", self.description.trim())
        }
    }
}

/// The hmac-secret output rides back in the assertion's extension list.
pub fn extract_hmac_output(extensions: &[AssertionExtension]) -> Result<[u8; 32], FidoError> {
    for ext in extensions {
        if let AssertionExtension::HmacSecret(Some(out)) = ext {
            return Ok(*out);
        }
    }
    Err(FidoError::NoPrfOutput)
}

/// `ctap-hid-fido2` surfaces CTAP status codes as `anyhow` strings built by
/// `ctapdef::get_ctap_status_message`, so the status has to be recovered from
/// the message. Matching on the `CTAP2_ERR_*` symbol (not on prose) keeps this
/// stable across the crate's wording changes.
pub fn classify(message: &str) -> FidoError {
    let m = message.to_ascii_uppercase();
    if m.contains("CTAP2_ERR_PIN_REQUIRED") || m.contains("CTAP2_ERR_PUAT_REQUIRED") {
        return FidoError::PinRequired;
    }
    if m.contains("CTAP2_ERR_PIN_INVALID") || m.contains("CTAP2_ERR_PIN_AUTH_INVALID") {
        return FidoError::PinInvalid;
    }
    if m.contains("CTAP2_ERR_PIN_BLOCKED") || m.contains("CTAP2_ERR_PIN_AUTH_BLOCKED") {
        return FidoError::PinBlocked;
    }
    if m.contains("CTAP2_ERR_ACTION_TIMEOUT")
        || m.contains("CTAP2_ERR_USER_ACTION_TIMEOUT")
        || m.contains("CTAP2_ERR_KEEPALIVE_CANCEL")
        || m.contains("CTAP2_ERR_OPERATION_DENIED")
    {
        return FidoError::TouchNotRegistered;
    }
    if m.contains("CTAP2_ERR_NO_CREDENTIALS") {
        return FidoError::UnknownCredential;
    }
    if m.contains("CTAP2_ERR_UNSUPPORTED_EXTENSION") || m.contains("CTAP2_ERR_UNSUPPORTED_OPTION") {
        return FidoError::NoHmacSecret;
    }
    if m.contains("FIDO DEVICE NOT FOUND") {
        return FidoError::NoDevice;
    }
    if m.contains("MULTIPLE FIDO DEVICES FOUND") {
        return FidoError::AmbiguousDevice;
    }
    FidoError::Hardware(message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_maps_ctap_status_symbols() {
        assert!(matches!(
            classify("0x36 CTAP2_ERR_PIN_REQUIRED  PIN is required."),
            FidoError::PinRequired
        ));
        assert!(matches!(
            classify("0x32 CTAP2_ERR_PIN_BLOCKED PIN Blocked."),
            FidoError::PinBlocked
        ));
        assert!(matches!(
            classify("0x2E CTAP2_ERR_NO_CREDENTIALS"),
            FidoError::UnknownCredential
        ));
        assert!(matches!(
            classify("FIDO device not found."),
            FidoError::NoDevice
        ));
        assert!(matches!(
            classify("Multiple FIDO devices found."),
            FidoError::AmbiguousDevice
        ));
    }

    #[test]
    fn classify_falls_through_to_hardware_for_unknown_text() {
        assert!(matches!(classify("hid write failed"), FidoError::Hardware(_)));
    }

    #[test]
    fn verification_plan_asks_for_the_strongest_verification_the_device_has() {
        // Built-in UV wins even when a PIN is also set: the authenticator
        // verifies the user itself and no PIN needs typing.
        assert_eq!(verification_plan(true, true), Verification::BuiltInUv);
        assert_eq!(verification_plan(false, true), Verification::BuiltInUv);
        // A set PIN MUST be requested up front -- getAssertion would not ask.
        assert_eq!(verification_plan(true, false), Verification::Pin);
        // And a device with nothing to verify must be asked for nothing:
        // uv=true here is CTAP2_ERR_INVALID_OPTION, the bug the virtual
        // CanoKey found on first contact.
        assert_eq!(verification_plan(false, false), Verification::PossessionOnly);
    }

    #[test]
    fn extract_hmac_output_finds_the_extension_and_rejects_its_absence() {
        let out = [7u8; 32];
        let found =
            extract_hmac_output(&[AssertionExtension::HmacSecret(Some(out))]).unwrap();
        assert_eq!(found, out);

        assert!(matches!(
            extract_hmac_output(&[AssertionExtension::HmacSecret(None)]),
            Err(FidoError::NoPrfOutput)
        ));
        assert!(matches!(
            extract_hmac_output(&[]),
            Err(FidoError::NoPrfOutput)
        ));
    }
}
