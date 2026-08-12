# RageDroid

A Bitwarden-compatible Android client where every individual credential is protected by a
hardware tap (YubiKey, FIDO2, or device StrongBox) on top of the regular master-password
encryption.

The goal: a master password leak does not leak any of the actual secrets. Each reveal requires
a deliberate physical action.

Built on:

- The Bitwarden Rust SDK and existing Bitwarden / Vaultwarden server infrastructure for
  storage, sync, and the master-password layer.
- The [age](https://age-encryption.org) format and the
  [`age` Rust crate](https://crates.io/crates/age) for the per-secret layer.
- [yubikit-android](https://github.com/Yubico/yubikit-android) for YubiKey USB-OTG and NFC
  interaction.
- AndroidKeystore / StrongBox for device-bound identities.

See [DESIGN.md](DESIGN.md) for the full architecture and open questions.

This subfolder currently contains design only -- no code yet. The design needs to settle on
seven open questions in §10 of DESIGN.md before scaffolding makes sense.
