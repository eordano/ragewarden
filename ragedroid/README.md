# RageDroid

Android client for the [Ragewarden](../DESIGN.md) ecosystem. Every individual credential
sits behind a hardware tap on top of the regular Bitwarden master-password layer, so a
master-password leak does not leak any of the actual secrets. See
[`DESIGN.md`](DESIGN.md) for the full Android-specific design.

---

## Layout

```
ragedroid/
+-- settings.gradle.kts
+-- build.gradle.kts
+-- gradle.properties
+-- gradle/libs.versions.toml      <- pinned versions for AGP, Kotlin, Compose, etc.
+-- jni/                           <- Cargo crate; builds libragedroid_jni.so via cargo-ndk
|   +-- Cargo.toml
|   +-- src/lib.rs                 <- JNI exports over ragewarden-core
+-- app/                           <- single-module Compose app
    +-- build.gradle.kts           <- AGP config + cargo-ndk task wiring
    +-- src/main/
        +-- AndroidManifest.xml
        +-- kotlin/ragewarden/ragedroid/
        |   +-- MainActivity.kt
        |   +-- data/              <- DemoVaultStore (in-memory, JNI-backed)
        |   +-- fixtures/          <- hardcoded vault + recipient data
        |   +-- jni/RageNative.kt  <- static native bindings
        |   +-- ui/
        |       +-- RageApp.kt
        |       +-- components/    <- AppBar, RageChip, InlineTapReveal, ...
        |       +-- screens/       <- VaultListScreen, ItemDetailScreen
        |       +-- theme/         <- Color, Type, MotionTokens, Theme
        +-- res/                   <- strings, themes, launcher icon
```

---

## Build (full APK)

Phase 1 needs both an Android SDK and the cargo-ndk plugin. None of these are required to
verify the Rust JNI crate alone (see "Just the JNI" below).

### Prerequisites

| tool | version | how |
|------|---------|-----|
| JDK | 17 | `brew install openjdk@17` or your distro's OpenJDK package |
| Android SDK | platform 34, build-tools 34.x | install via Android Studio or `sdkmanager` |
| Android NDK | 26.x or newer | `sdkmanager --install "ndk;26.3.11579264"` |
| `cargo` | 1.94+ (matches `rust-toolchain.toml`) | rustup |
| `cargo-ndk` | 3.x | `cargo install cargo-ndk` |
| Rust Android targets | `aarch64-linux-android`, `x86_64-linux-android` | `rustup target add aarch64-linux-android x86_64-linux-android` |

### Required environment variables

```bash
export ANDROID_HOME="$HOME/Library/Android/sdk"           # or wherever it's installed
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/26.3.11579264" # adjust to your installed NDK
export JAVA_HOME=$(/usr/libexec/java_home -v 17)          # macOS -- Linux: just point at /usr/lib/jvm/...
```

If building the Rust workspace on macOS you may need to work around a libiconv linker
quirk -- see the top-level [`README.md`](../README.md#build) for the `LIBRARY_PATH`
workaround.

### Generate the Gradle wrapper jar

The Gradle wrapper script + properties file are checked in; the `gradle-wrapper.jar` binary
is not, because we don't ship binaries to the repo. Run once:

```bash
cd ragedroid/
gradle wrapper --gradle-version 8.10.2
```

(Requires a system-installed `gradle` to bootstrap, OR you can copy a `gradle-wrapper.jar`
from any Android Studio project.)

### Build the APK

```bash
cd ragedroid/
./gradlew :app:assembleDebug
```

Produces `app/build/outputs/apk/debug/app-debug.apk`.

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

The Rust output is reproducible at the byte level (`codegen-units=1`, `lto=fat`, fixed
`rust-toolchain.toml`); the Java side will be reproducible once we pin the Gradle wrapper
SHA in phase 3.

### Run

```bash
./gradlew :app:installDebug && adb shell am start -n ragewarden.ragedroid/.MainActivity
```

---

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

---

## What's in phase 1 (this build)

- Rust JNI bridge: `encrypt`, `decryptWithSoftwareSecret`, `generateSoftwareIdentity`,
  `pubkeyFromArmoredSecret`, `smoke`. Software-identity round-trip only.
- Kotlin Compose UI: vault list + item detail with the action-before-tap pattern.
- Hardcoded fixture data (`fixtures/Fixtures.kt`) standing in for the Bitwarden vault.
- The "tap" is a software-identity authorize button -- no NFC, no USB-OTG, no Credential
  Manager. The user's chosen action is named in the prompt before the button appears, so
  the design principle holds regardless of how the tap is implemented.

## What comes next (per the canonical [5-phase roadmap](../DESIGN.md#7-sequencing))

- **Phase 2** -- replace the in-memory `DemoVaultStore` with a real Bitwarden / Vaultwarden
  vault. Same `sync` module that already powers rageterm phase 2.
- **Phase 3** -- hardware identities: yubikit-android (PIV + FIDO2), Credential Manager
  passkey path (`webauthn-prf-v1`), Android Keystore (StrongBox / TEE). The
  `PasskeyIdentityStub` class in `jni/RageNative.kt` is the placeholder.
- **Phase 4** -- Android Autofill API service (the `BitwardenAutofillService` adapter
  described in `DESIGN.md` §4e), IME service for `Send to keyboard`, multi-flavor builds
  (`standard` for Play, `fdroid` without Play services).
- **Phase 5** -- TOTP, baseline profiles, audit prep, signing + Play / F-Droid
  distribution.

See [`DESIGN.md`](DESIGN.md) for the longer-form roadmap.

---

## Troubleshooting

**`cargo: command not found` during `cargoNdkBuild`** -- Gradle inherits the shell's PATH;
make sure your IDE / shell exports `~/.cargo/bin`.

**`error: linker 'aarch64-linux-android-clang' not found`** -- `cargo-ndk` couldn't find the
NDK. Set `ANDROID_NDK_HOME` (or `ANDROID_NDK_ROOT`) before invoking Gradle.

**`UnsatisfiedLinkError: dlopen failed`** -- the `.so` is in `app/src/main/jniLibs/<abi>/`
but ABI doesn't match the device. Check `adb shell getprop ro.product.cpu.abi`; arm64-v8a
should cover any 2017+ phone, x86_64 covers most emulators.

**`error[E0462]: found staticlib instead of cdylib`** -- re-run `cargo ndk` from a clean
`target/` (the JNI crate's `crate-type` recently changed; stale artifacts can confuse the
linker).
