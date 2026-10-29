# Ragewarden

A Bitwarden-compatible secrets ecosystem where each individual credential is wrapped in a
hardware-tap layer (age recipients backed by YubiKey PIV, FIDO2 hmac-secret, WebAuthn
passkeys with PRF, or platform secure-enclave identities) on top of the regular Bitwarden
master-password layer.

The point: a phishing-resistant Bitwarden where the master password leaking does not leak
any of the actual secrets. A "rage item" is a vault item whose secret fields are wrapped
in age stanzas for a set of hardware recipients. Every individual use of a credential -- autofill, copy, agent
load, or last-resort reveal -- requires a deliberate physical action, with the destination
named in the prompt before the tap.

See [`DESIGN.md`](DESIGN.md) for the ecosystem design -- threat model, crypto layering,
shared decisions, and the canonical [5-phase roadmap](DESIGN.md#7-sequencing). The four
[non-negotiable principles](DESIGN.md#0-design-principles) are in §0; every frontend
honors them.

## Three coordinated products, one shared core

| product | runtime | UI source |
|---|---|---|
| [ragedroid](ragedroid/DESIGN.md) | Android (Kotlin + JNI) | native Compose |
| [ragemanifest](ragemanifest/DESIGN.md) | Browser MV3 (Rust -> WASM) | plain ES-module popup on the [`design/`](design/) tokens |
| [rageterm](rageterm/DESIGN.md) | Native binary (Rust) | CLI + ratatui TUI |

All three share [ragewarden-core](core/DESIGN.md), the Rust crate that owns the age
encryption layer + Bitwarden helpers. One audit surface, one bug fix touches all three.

## Status

Phases 1-4 of the [roadmap](DESIGN.md#7-sequencing) are done; phase 5 (production) is
under way: what remains is store distribution and signing, Homebrew and crates.io, a docs
site, the third-party audit and v1.0.

- ragewarden-core: age encryption to X25519, scrypt and every hardware stanza
  (`piv-p256` in age-plugin-yubikey's format, `piv-x25519-v2`, `fido2-hmac`,
  `webauthn-prf-v1`, `ragedroid-keystore-v1`/`-v2`, recovery), per-secret PRF salts and
  legacy re-wrap; PBKDF2 and Argon2id, Type-2 EncStrings; `sync` with login, KDF pin and
  upgrade, refresh, and cipher builders that keep every field (login, note, card,
  identity, SSH key) with single- or multi-field protection; TOTP; the recipient
  registry, revision history and audit log shared by all three clients.
- rageterm: the CLI and `--tui` against Vaultwarden (`register`, `login`, `sync`, `set`,
  `get`, `copy`, `reveal`, `exec`, `totp`, `mv`, `reencrypt`, `restrict`, `generate`);
  YubiKey PIV (P-256 by default), FIDO2, OS-keyring, software and paper identities; the
  native-messaging host for the extension, with signed touch proofs; `pass-import`;
  `agent add`; `fill --to` autotype on Linux, macOS and Windows.
- ragedroid: Compose app on the Bitwarden API with an offline encrypted cache and a lock
  that drops the keys; autofill (with inline suggestions) and a keyboard that both unlock
  and tap; YubiKey PIV and FIDO2 over NFC and USB, Android Keystore (StrongBox or TEE),
  Credential Manager passkeys; TOTP with QR scan; typed items; standard and fdroid
  flavours.
- ragemanifest: Chromium, Firefox and Safari builds; passkeys with PRF, phone passkeys
  through the relay page, PIV and FIDO2 through rageterm; a local lock with auto-lock;
  origin-pinned autofill in every frame; typed items, TOTP, history and audit.
- CI and release: `ci.yml` runs the Rust workspace (Linux and macOS), the wasm build, the
  Android matrix, the rageterm cross-builds and the three e2e tiers (Vaultwarden,
  Playwright, Android emulator); `release.yml` builds every artifact and verifies
  reproducibility. See [`E2E.md`](E2E.md).

## Layout

`DESIGN.md` holds the ecosystem design and 5-phase roadmap; `core/` is
ragewarden-core, the shared Rust crate; `ragedroid/` the Android frontend
(Kotlin + JNI); `ragemanifest/` the browser extension (Rust -> WASM);
`rageterm/` the native CLI / TUI; `design/` the read-only HTML/CSS/JS prototype.

The [`design/`](design/) folder is the canonical UI design. `ragemanifest` implements it as
plain ES modules and takes only its tokens and fonts at build time; `ragedroid`
hand-translates it to Compose (a WebView with biometric/autofill bridges is unacceptable
attack surface for a vault app).

## Build

The whole Rust workspace builds with stock `cargo`.

```sh
cargo build --workspace
cargo test  --workspace
```

On macOS, build with Apple's toolchain (Xcode or the Command Line Tools, `/usr/bin/cc`)
or inside `nix develop <nixos-config>#ragewarden`. Rust's standard library links
`-liconv`; Apple's linker finds it in the SDK, and the devshell brings nixpkgs' libiconv as
a build input. nixpkgs' clang outside that shell has neither and stops at
`ld: library not found for -liconv`, already while linking dependencies' build scripts.

Per-frontend builds and verification: see each frontend subdirectory's `README.md`
(`rageterm/`, `ragedroid/`, `ragemanifest/`; the shared crate is documented in
`core/DESIGN.md`).
