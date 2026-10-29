# RageDroid

Android client for the [Ragewarden](../DESIGN.md) ecosystem. Every individual credential
sits behind a hardware tap on top of the regular Bitwarden master-password layer, so a
master-password leak does not leak any of the actual secrets. See
[`DESIGN.md`](DESIGN.md) for the full Android-specific design.

## Layout

- Gradle root: `settings.gradle.kts`, `build.gradle.kts`, `gradle.properties`,
  `gradle/libs.versions.toml` (pinned AGP, Kotlin, Compose, ...).
- `jni/`: Cargo crate built into `libragedroid_jni.so` by cargo-ndk; JNI
  exports over ragewarden-core (`lib.rs`, `jni_identity.rs`, `sync_jni.rs`,
  `lock_jni.rs`, `items_jni.rs`, `http.rs`, `error.rs`), each wrapped so a Rust panic
  throws instead of aborting.
- `app/`: the single-module Compose app; `build.gradle.kts` carries the AGP
  config and the cargo-ndk task wiring. Under
  `src/main/kotlin/ragewarden/ragedroid/`: `MainActivity.kt`,
  `RageApplication.kt`, `jni/` (static native bindings), `data/` (vault
  repository, lock state, history, clipboard, audit), `identities/`
  (Keystore, FIDO2-hmac and passkey-PRF identities, hardware-tap
  coordination), `autofill/` (autofill service + heuristics), `ime/` (input
  method delivery), `di/` (Hilt), `model/`, and `ui/` (`RageApp.kt`,
  `components/`, `screens/`, `theme/`). `res/` holds strings, themes and the
  launcher icon.
- `baselineprofile/`: the baseline-profile module.

## Build (full APK)

The NixOS config flake's `android` dev shell pins the toolchain: SDK 37 / build-tools 37.0.0,
NDK 26.3.11579264, JDK 21, Gradle 9.7.1 (the version in
`gradle/wrapper/gradle-wrapper.properties`), cargo-ndk, Rust with the Android targets, and
the `ragedroid-avd` / `ragedroid-emulator` / `ragedroid-wait-boot` helpers. Use its `gradle`
directly; the wrapper jar is not committed, and CI regenerates it from the pinned version
and SHA-256.

```bash
nix develop <nixos-config>#android
cd ragedroid/
gradle :app:testStandardDebugUnitTest :app:testFdroidDebugUnitTest
gradle :app:assembleStandardDebug :app:assembleFdroidDebug
(cd .. && cargo test -p ragedroid-jni --lib)
```

APKs land in `app/build/outputs/apk/{standard,fdroid}/debug/`. Without the dev shell, the
same toolchain installed by hand works: JDK 21, the SDK and NDK above, `cargo-ndk`, and
`rustup target add aarch64-linux-android x86_64-linux-android`, with `ANDROID_HOME` and
`ANDROID_NDK_HOME` exported.

What this does, in order:

1. Gradle resolves the Compose / AGP / Kotlin dependency graph from `gradle/libs.versions.toml`.
2. The `cargoNdkBuild` task (registered in `app/build.gradle.kts`) shells out to:
   ```
   cargo ndk -o app/src/main/jniLibs -t arm64-v8a -t x86_64 build --release -p ragedroid-jni
   ```
   from the workspace root. This cross-compiles `ragedroid-jni` for both ABIs and drops the
   resulting `libragedroid_jni.so` files into `app/src/main/jniLibs/<abi>/`.
3. AGP merges the JNI libs into the APK, runs `kotlinc` against `app/src/main/kotlin/`,
   builds the resource table, and assembles the APK.

The Rust release build uses `codegen-units=16`, `lto=fat`, and a fixed
`rust-toolchain.toml`; `scripts/repro/verify-ragedroid.sh` checks byte-level
reproducibility of the APKs. `gradle-wrapper.properties` pins the Gradle version and its
`distributionSha256Sum` (the published SHA-256 of the distribution zip, which nixpkgs'
`gradle_9` fetches under the same hash); CI passes the sum to `gradle wrapper`, so a
`./gradlew` it generates refuses any other distribution.

### Run

```bash
gradle :app:installStandardDebug && adb shell am start -n ragewarden.ragedroid/.MainActivity
```

## Just the JNI (no Android SDK needed)

To verify the Rust side compiles and the round-trip works end-to-end, from the workspace
root:

```bash
cd ../    # if you're in ragedroid/
cargo build -p ragedroid-jni
cargo test -p ragedroid-jni
```

The tests exercise the same code paths the JNI methods take, just without going through
JNI. This is the entry point CI runs before any Android-side checks.

## Features

Sign-in against any Bitwarden or Vaultwarden server (PBKDF2 or Argon2id, KDF pin and
consented upgrade, token refresh), an encrypted offline cache and a lock that drops the
keys; logins, notes, cards, identities and SSH keys with per-field protection; YubiKey PIV
(P-256 and X25519) and FIDO2 over NFC and USB, Android Keystore (StrongBox or TEE),
Credential Manager passkeys with PRF, a paper recovery phrase; autofill with inline
suggestions and a keyboard, both able to unlock and tap; TOTP with QR scan; rotation,
bulk re-encrypt, revision history and an audit log. [`DESIGN.md`](DESIGN.md) has the
design.

## Troubleshooting

`cargo: command not found` during `cargoNdkBuild` -- Gradle inherits the shell's PATH;
make sure your IDE / shell exports `~/.cargo/bin`.

`error: linker 'aarch64-linux-android-clang' not found` -- `cargo-ndk` couldn't find the
NDK. Set `ANDROID_NDK_HOME` (or `ANDROID_NDK_ROOT`) before invoking Gradle.

`UnsatisfiedLinkError: dlopen failed` -- the `.so` is in `app/src/main/jniLibs/<abi>/`
but ABI doesn't match the device. Check `adb shell getprop ro.product.cpu.abi`; arm64-v8a
should cover any 2017+ phone, x86_64 covers most emulators.

`error[E0462]: found staticlib instead of cdylib` -- re-run `cargo ndk` from a clean
`target/`; stale artifacts from an older `crate-type` confuse the linker.
