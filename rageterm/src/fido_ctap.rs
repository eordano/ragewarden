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
use crate::fido::{AssertionSignature, Fido2Device, FidoError, NewCredential};

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
/// The seed an item is wrapped to is fixed at enrollment and recorded
/// (`IdentityKind::Fido2HmacSecret::uv`), so `seed_plan` keeps asking for it
/// after the authenticator's PIN or biometric configuration changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    BuiltInUv,
    Pin,
    PossessionOnly,
}

/// Which verification to request for a credential bound to seed `uv` on an
/// authenticator currently configured as `current`. A possession-only
/// credential keeps asking for the possession-only seed after a PIN is set; a
/// verified one cannot be opened once the authenticator stops verifying.
pub fn seed_plan(uv: Option<bool>, current: Verification) -> Result<Verification, FidoError> {
    match (uv, current) {
        (None, plan) => Ok(plan),
        (Some(false), _) => Ok(Verification::PossessionOnly),
        (Some(true), Verification::PossessionOnly) => Err(FidoError::Hardware(
            "this credential was enrolled with a PIN or biometric, and the authenticator \
             no longer has one configured; restore it to open these items"
                .into(),
        )),
        (Some(true), plan) => Ok(plan),
    }
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
        let description = match ceremony::current() {
            Some(c) => format!("{c}\nThis authenticator requires its FIDO2 PIN."),
            None => "This authenticator requires its FIDO2 PIN.".to_string(),
        };
        let pin = crate::pin::read_pin("FIDO2 PIN: ", &description).map_err(|e| match e {
            crate::pin::PinError::NoPinSource => FidoError::NoPinPrompt,
            crate::pin::PinError::Io(io) => FidoError::Io(io),
            other => FidoError::Pin(other.to_string()),
        })?;
        self.pin = Some(pin.to_string());
        Ok(pin.to_string())
    }
}

impl Fido2Device for CtapDevice {
    fn make_hmac_credential(&mut self, rp_id: &str) -> Result<NewCredential, FidoError> {
        let mut challenge = [0u8; 32];
        rand::rng().fill_bytes(&mut challenge);
        let extensions = vec![CredentialExtension::HmacSecret(Some(true))];

        ceremony::announce_touch(
            &self.describe(),
            "Creating the hmac-secret credential this vault will be wrapped to",
        );

        let plan = self.verification()?;
        let mut pin: Option<String> = None;
        loop {
            if pin.is_none() && plan == Verification::Pin {
                pin = Some(self.prompt_pin()?);
            }
            let args = {
                let mut builder =
                    MakeCredentialArgsBuilder::new(rp_id, &challenge).extensions(&extensions);
                builder = match (pin.as_deref(), plan) {
                    (Some(p), _) => builder.pin(p),
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
                    return Ok(NewCredential {
                        id: att.credential_descriptor.id,
                        public_key: es256_point(&att.credential_publickey.der),
                    });
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

    fn sign_assertion(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        client_data: &[u8],
        user_presence: bool,
    ) -> Result<AssertionSignature, FidoError> {
        if user_presence {
            ceremony::announce_touch(
                &self.describe(),
                "Reading this credential's public key from its signature",
            );
        }
        let mut builder = GetAssertionArgsBuilder::new(rp_id, client_data)
            .credential_id(credential_id)
            .without_pin_and_uv();
        if !user_presence {
            builder = builder.without_up();
        }
        let assertions = self
            .key
            .get_assertion_with_args(&builder.build())
            .map_err(|e| classify(&e.to_string()))?;
        let a = assertions
            .first()
            .ok_or_else(|| FidoError::Hardware("empty assertion list".into()))?;
        Ok(AssertionSignature {
            authenticator_data: a.auth_data.clone(),
            signature_der: a.signature.clone(),
        })
    }

    fn verifies_users(&mut self) -> Result<bool, FidoError> {
        Ok(self.verification()? != Verification::PossessionOnly)
    }

    fn hmac_secret(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
        uv: Option<bool>,
        client_data: Option<&[u8]>,
    ) -> Result<crate::fido::HmacAssertion, FidoError> {
        let mut random = [0u8; 32];
        rand::rng().fill_bytes(&mut random);
        let challenge = client_data.unwrap_or(&random[..]);
        let extensions = vec![AssertionExtension::HmacSecret(Some(*salt))];

        let current = self.verification()?;
        let plan = seed_plan(uv, current)?;
        if uv == Some(false) && current != Verification::PossessionOnly {
            ceremony::announce_step(
                "this credential was enrolled before the authenticator had a PIN or \
                 biometric, so its items open with a touch alone. Run `rageterm \
                 enroll-fido2` again and `rageterm reencrypt --all` to put them behind \
                 the PIN.",
            );
        }

        ceremony::announce_touch(&self.describe(), "Unwrapping this credential");

        let mut pin: Option<String> = None;
        loop {
            if pin.is_none() && plan == Verification::Pin {
                pin = Some(self.prompt_pin()?);
            }
            let args = {
                let mut builder = GetAssertionArgsBuilder::new(rp_id, challenge)
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
                    let a = assertions
                        .first()
                        .ok_or_else(|| FidoError::Hardware("empty assertion list".into()))?;
                    return Ok(crate::fido::HmacAssertion {
                        prf: extract_hmac_output(&a.extensions)?,
                        user_present: a.flags.user_present_result,
                        user_verified: a.flags.user_verified_result,
                        signed: AssertionSignature {
                            authenticator_data: a.auth_data.clone(),
                            signature_der: a.signature.clone(),
                        },
                    });
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

/// An ES256 credential key as ctap-hid-fido2 hands it over (`0x04 || X || Y`,
/// which it calls `der`); any other algorithm's key is `None`.
fn es256_point(raw: &[u8]) -> Option<[u8; 65]> {
    let point: [u8; 65] = raw.try_into().ok()?;
    p256::PublicKey::from_sec1_bytes(&point).ok()?;
    Some(point)
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
        assert!(matches!(
            classify("hid write failed"),
            FidoError::Hardware(_)
        ));
    }

    #[test]
    fn a_possession_only_credential_keeps_its_seed_after_a_pin_is_set() {
        assert_eq!(
            seed_plan(Some(false), Verification::Pin).unwrap(),
            Verification::PossessionOnly
        );
        assert_eq!(
            seed_plan(Some(true), Verification::Pin).unwrap(),
            Verification::Pin
        );
        assert_eq!(
            seed_plan(None, Verification::Pin).unwrap(),
            Verification::Pin
        );
        assert!(seed_plan(Some(true), Verification::PossessionOnly).is_err());
    }

    #[test]
    fn verification_plan_asks_for_the_strongest_verification_the_device_has() {
        assert_eq!(verification_plan(true, true), Verification::BuiltInUv);
        assert_eq!(verification_plan(false, true), Verification::BuiltInUv);
        assert_eq!(verification_plan(true, false), Verification::Pin);
        assert_eq!(
            verification_plan(false, false),
            Verification::PossessionOnly
        );
    }

    #[test]
    fn extract_hmac_output_finds_the_extension_and_rejects_its_absence() {
        let out = [7u8; 32];
        let found = extract_hmac_output(&[AssertionExtension::HmacSecret(Some(out))]).unwrap();
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
