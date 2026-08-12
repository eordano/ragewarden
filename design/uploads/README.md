# Ragewarden

A Bitwarden-compatible secrets ecosystem where each individual credential is wrapped in a
hardware-tap layer (age recipients backed by YubiKey PIV, FIDO2 hmac-secret, or platform
secure-enclave identities) on top of the regular Bitwarden master-password layer.

The pitch: a phishing-resistant Bitwarden where the master password leaking does not leak
any of the actual secrets. Every individual *use* of a credential -- autofill, copy, agent
load, or last-resort reveal -- requires a deliberate physical action, with the destination
named in the prompt before the tap.

## Three coordinated products, one shared core

| product | runtime | purpose | status |
|---|---|---|---|
| [**ragedroid**](ragedroid/DESIGN.md)   | Android (Kotlin + JNI) | mobile autofill, NFC YubiKey                          | design |
| [**ragemanifest**](ragemanifest/DESIGN.md) | Browser MV3 (Rust -> WASM) | Chromium / Firefox / Safari extension; WebAuthn for tap | design |
| [**rageterm**](rageterm/DESIGN.md)     | Native binary (Rust) | CLI by default, `--tui` interactive; SSH-agent-style integrations | design |

All three share [**ragewarden-core**](core/DESIGN.md), the Rust crate that owns the age
encryption layer + Bitwarden client primitives. One audit surface, one bug fix touches all
three.

## Status

Design phase. No code yet. `core/src/lib.rs` declares the API surface with `todo!()`s; phase
1 implements those for software identities, then we have an end-to-end demo across all three
frontends.

See [DESIGN.md](DESIGN.md) for the ecosystem-level design and decisions.
