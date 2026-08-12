# Ragewarden

A Bitwarden-compatible secrets ecosystem where each individual credential is wrapped in a
hardware-tap layer (age recipients backed by YubiKey PIV, FIDO2 hmac-secret, WebAuthn
passkeys with PRF, or platform secure-enclave identities) on top of the regular Bitwarden
master-password layer.

The pitch: a phishing-resistant Bitwarden where the master password leaking does not leak
any of the actual secrets. Every individual *use* of a credential -- autofill, copy, agent
load, or last-resort reveal -- requires a deliberate physical action, with the destination
named in the prompt before the tap.

See [`DESIGN.md`](DESIGN.md) for the ecosystem design -- threat model, crypto layering,
shared decisions, and the canonical [5-phase roadmap](DESIGN.md#7-sequencing). The four
[non-negotiable principles](DESIGN.md#0-design-principles) are in §0; every frontend
honors them.

## Three coordinated products, one shared core

| product | runtime | UI source | status |
|---|---|---|---|
| [**ragedroid**](ragedroid/DESIGN.md)   | Android (Kotlin + JNI) | native Compose | phases 1-4 done -- autofill, IME, onboarding, JNI bridge, Roborazzi snapshots |
| [**ragemanifest**](ragemanifest/DESIGN.md) | Browser MV3 (Rust -> WASM) | hosts [`design/`](design/) directly | phases 1-4 done -- 23 WASM exports, Chromium/Firefox/Safari builds, content-script autofill, native messaging |
| [**rageterm**](rageterm/DESIGN.md)     | Native binary (Rust) | CLI + ratatui TUI | phases 1-4 done -- Vaultwarden round-trip, native-host mode, pass-import, ssh-agent, autotype |

All three share [**ragewarden-core**](core/DESIGN.md), the Rust crate that owns the age
encryption layer + Bitwarden helpers. One audit surface, one bug fix touches all three.

## Status

Phases 1-4 of the [5-phase roadmap](DESIGN.md#7-sequencing) are complete or scaffolded.
Phase 5 (production) is in progress.

What works today:

- **ragewarden-core**: 106 tests passing. X25519 + scrypt round-trips; PBKDF2 / HKDF /
  Type-2 helpers match Bitwarden's spec; `sync` module ships register / login /
  fetch_vault / cipher CRUD; TOTP (RFC 6238 SHA1/SHA256/SHA512); all five hardware-stanza
  paths (`piv-p256`, `fido2-hmac`, `webauthn-prf-v1`, `ragedroid-keystore-v1`, recovery);
  audit log + history tracking; cross-device recipient registry.
- **rageterm**: full CLI round-trip against Vaultwarden (`register -> login -> sync -> set ->
  list -> copy -> get -> reveal -> exec -> totp`); native-host mode for ragemanifest;
  `pass-import` migration; `agent add` for ssh-agent; `fill --to` autotype; `pass`-style
  command aliases. Local file store as offline fallback.
- **ragedroid**: Compose app with Bitwarden API integration (`BitwardenVaultRepository`),
  onboarding gate, autofill service (`RagewardenAutofillService`), IME service
  (`RagewardenInputMethodService`), JNI bridge, TOTP card with countdown, identity
  dispatch (Keystore/PIV/FIDO2 PRF), Hilt DI, baseline profile, Roborazzi snapshots,
  standard + fdroid flavors. Runs on emulator end-to-end.
- **ragemanifest**: 23 WASM exports (login, register, vault fetch, cipher CRUD, decrypt
  with PRF callbacks, TOTP, registry, audit, history). Background service worker handles
  vault.status/fetch/lookup/unlock. Content-script autofill with Shadow DOM chip.
  Onboarding overlay for login/registration. Passkey PRF enrollment + per-use ceremony.
  Chromium, Firefox MV3, and Safari host-app builds. Playwright e2e suite with virtual
  WebAuthn.
- **CI/CD**: `ci.yml` runs Rust workspace (Linux + macOS), WASM build, Android matrix,
  5-target rageterm cross-build, and three e2e tiers (Vaultwarden, Playwright, Gradle
  Managed Devices). `release.yml` builds all artifacts + reproducible-build verification.
- **End-to-end harness**: three tiers -- Rust <-> real Vaultwarden (Docker), Playwright +
  virtual WebAuthn PRF (Chromium), Android emulator (Pixel 6 API 34). See [`E2E.md`](E2E.md).

What remains for phase 5 (production):

- QR enrollment for TOTP (all three frontends).
- Bulk-protect wizard for existing unprotected items.
- Live hardware identity ceremonies (currently mock-mode; requires real YubiKey/FIDO2
  hardware testing).
- Signed releases (GPG, Android keystore, Apple Developer ID, Authenticode).
- Store distribution (Play Store, F-Droid, Chrome Web Store, AMO, App Store).
- Homebrew tap + `cargo install` publication.
- Docs site.
- Organization sharing (design-doc level -- separate threat model).

## Layout

```
ragewarden/
+-- DESIGN.md                ecosystem design + 5-phase roadmap
+-- core/                    ragewarden-core: shared Rust crate
+-- ragedroid/               Android frontend (Kotlin + JNI)
+-- ragemanifest/            browser extension (Rust -> WASM)
+-- rageterm/                native CLI / TUI
+-- design/                  read-only HTML/CSS/JS prototype, source of UI truth
```

The [`design/`](design/) folder is the canonical UI source. `ragemanifest` consumes it at
build time (it's a browser extension; design is already browser-shaped). `ragedroid`
hand-translates it to Compose for security reasons (a WebView with biometric/autofill
bridges is unacceptable attack surface for a vault app).

## Build

The whole Rust workspace builds with stock `cargo`.

```sh
cargo build --workspace
cargo test  --workspace
```

On macOS you may hit `ld: library not found for -liconv` from `aws-lc-sys`/`ring`. Work
around it by pointing `LIBRARY_PATH` at the SDK's lib directory before building:

```sh
export LIBRARY_PATH="$(xcrun --show-sdk-path)/usr/lib"
cargo build --workspace
```

Per-frontend builds and verification: see each subdirectory's `README.md`.
