# End-to-end test harness

Three tiers verify the ecosystem without manual testing; the hardware a person still has to
touch is listed at the end.

## Tier 1 -- Rust against a real Vaultwarden

Files: `rageterm/tests/e2e_vaultwarden.rs`, `rageterm/tests/e2e_protocol.rs`,
`rageterm/tests/support/`.

- `e2e_vaultwarden.rs` -- register, login, encrypt, POST, fetch, `extract_rage_blob`,
  decrypt; and the same vault driven through `ragemanifest::snapshot::build_snapshot`, so
  the browser's code path flags the cipher as protected.
- `e2e_protocol.rs` -- core's account protocol against the real server: KDF upgrade
  (PBKDF2 100k -> 600k -> Argon2id), Argon2id registration and login, the downgrade pin,
  token refresh, field-preserving protect and rotate of a full login, typed items (card,
  identity, SSH key) with protected fields, folder moves, the history document and its
  migration, wrong-key detection.

Run inside `nix develop <nixos-config>#ragewarden`, which exports `RAGEWARDEN_VAULTWARDEN_BIN`:

```bash
cargo test -p rageterm --test e2e_vaultwarden --test e2e_protocol -- --test-threads=1
```

Each test starts its own Vaultwarden on a free loopback port with a throwaway data
directory: the binary named by `RAGEWARDEN_VAULTWARDEN_BIN`, or `vaultwarden/server:1.32.7`
in Docker when `RAGEWARDEN_E2E=1`; with neither, the tests print a note and skip.

The NixOS-config checks run the rest of rageterm against `services.vaultwarden`:
`ragewarden-e2e` (about 40 CLI subtests, the clipboard and the Secret Service keyring under
Xvfb with a session bus), `ragewarden-canokey` and `ragewarden-canokey-touch` (PIV and FIDO2
against a virtual CanoKey with a touch sensor, the native-messaging host and its signed
proofs, `migrate-piv`, `attest-fido2`).

CI: the `e2e-vaultwarden` job in `.github/workflows/ci.yml` runs on every push.

## Tier 2 -- the browser extension

Playwright 1.63.0 launches Chromium with the unpacked `--test-hooks` build. Chrome DevTools
Protocol's
[`WebAuthn.addVirtualAuthenticator`](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/)
seeds a CTAP2 platform authenticator with user verification, resident keys and PRF. One
Vaultwarden is shared by the run: `VAULTWARDEN_URL`, `RAGEWARDEN_VAULTWARDEN_BIN`, docker or
podman (`docker.io/vaultwarden/server:1.37.3`), or a cargo-built binary. The real rageterm
plays the other client.

Files: `ragemanifest/tests/playwright/`. The specs and the cross-client actions they cover
are listed in
[`CROSS-CLIENT-ACTIONS.md`](ragemanifest/tests/playwright/tests/CROSS-CLIENT-ACTIONS.md):
onboarding, the shipped PRF write/read path with an authenticator-refused control,
lock and origin-pinned fill, the content-script chip in frames, popup UX, typed items,
legacy-KDF upgrade, the passkey relay, the rageterm cross-client fuzz, and the journey's
browser half.

```bash
cd ragemanifest/tests/playwright
pnpm install --frozen-lockfile
pnpm exec playwright test
```

`global-setup.ts` builds the wasm if `pkg/` is stale, the extension and its mock-tap
variant, and rageterm unless `RAGETERM_BIN` is set.

Around Playwright:

- `pnpm run test:unit` -- the glue under node with a fake extension API.
- `tests/firefox-bidi.mjs` -- real headless Firefox over WebDriver BiDi: install, popup,
  event page, tap window.
- The NixOS-config check `ragemanifest` -- wasm, the three zipped builds, smoke, unit, store
  package, Firefox and the host cargo tests, hermetically.

PRF on Firefox and Safari and the Safari app are signed off by hand
([`firefox-checklist.md`](ragemanifest/tests/manual/firefox-checklist.md)): no virtual
authenticator on those browsers exposes PRF.

CI: the `e2e-playwright` job runs on every push and uploads the HTML report on failure.

## Tier 3 -- Android

The Robolectric/Roborazzi suite runs on every build (`gradle :app:testStandardDebugUnitTest
:app:testFdroidDebugUnitTest`). On a device:

- Instrumented tests -- CI runs them on a Gradle Managed Device (Pixel 6 API 34, `aosp`
  image); locally, boot the dev shell's AVD (`ragedroid-avd`, `ragedroid-emulator`,
  `ragedroid-wait-boot`) and run `gradle :app:connectedStandardDebugAndroidTest`.
- `tests/journey/run.sh` -- a host-side runner that stands up a throwaway Vaultwarden,
  builds a fixture with rageterm, `adb reverse`s the loopback port (the app refuses any
  non-loopback server), drives the server-backed tests against the attached emulator, then
  runs the extension's Playwright `android-recovery.spec.ts` against the same server (it
  needs the #ragewarden dev shell's Chromium and wasm toolchain as well as adb). With
  `JOURNEY_BENCH=1` it also runs the macrobenchmarks and writes the baseline profile. Those tests require instrumentation arguments
  only the runner supplies, so the journey package is filtered out of unarmed runs via a
  `notPackage` argument in `ragedroid/app/build.gradle.kts` -- a bare
  `connectedAndroidTest` neither runs nor fails them.

Files: `ragedroid/app/src/androidTest/kotlin/ragewarden/ragedroid/`.

Tests:

- `journey/JourneyTest` (run.sh only) -- the end-to-end journey through the shipped
  debug APK, driven by the Compose test rule, with the Compose semantics tree captured
  before and after every interaction (`MainActivity` sets `FLAG_SECURE`, so every screen
  capture comes back blank by design; the semantics tree is the artifact). A secret
  written by rageterm on the host, wrapped to a 24-word paper recovery identity, is
  recovered on the phone by typing those 24 words -- preceded by a negative control: a
  valid decoy mnemonic (minted on a second throwaway account, so it derives a real age
  identity that is simply not a recipient) must be refused first, which is what makes
  the reveal evidence of a real age unwrap rather than of a screen echoing test input.
  Along the way it asserts the vault list hides all three clients' meta ciphers (by
  absolute header count, not delta), that the vault row's recipient pip equals the
  number of recipients rageterm actually wrapped to (the age GREASE stanza must not be
  counted), and that saving an item wrapped only to foreign recipients is gated behind
  an explicit "Save anyway" confirmation -- Cancel must leave the server untouched.
- `journey/DeliveryFlowsTest` (run.sh only) -- against a third-party login form
  (`LoginFixtureActivity`): autofill after the Authorize tap, the keyboard typing an
  unprotected password, the keyboard sending a protected item to the tap sheet and typing
  nothing when declined, the RFC 6238 code on the detail screen, a protected card and SSH
  key round-tripping through Vaultwarden, and the shared history through JNI.
- `registry/RegistryPushInstrumentedTest` (run.sh only; self-skips without its
  arguments) -- reproduces the cold-cache `pushRecipientRegistry` bug against a vault
  another client already published into: run.sh seeds a browser registry by running the
  shipped `ragemanifest/ext/wasm` bundle under node, the test signs in from cold
  (asserting the cache really is empty), enrols a real AndroidKeyStore recipient plus a
  mock one, pushes, and asserts against a fresh sync that the vault holds exactly ONE
  `__ragedroid_recipients_v1__` marker, that the browser's entries survived the merge,
  that this device's key was published, and that the mock never reached the wire.
- `jni/RageNativeShapeTest` (managed device) -- exercises the packaged
  `libragedroid_jni.so` error surface: malformed recipients JSON, malformed PRF-inputs
  JSON, an unknown recipient kind, a garbage armored age secret, and a bad decrypt
  secret must each throw `RageNativeException.MalformedStanza` (naming the offending
  argument in the message) rather than succeeding or crashing, and a Rust panic in an
  export throws `RageNativeException.Internal` instead of killing the app.
- `identities/KeystoreMockRoundTripTest` -- a real P-256 key opening real
  `ragedroid-keystore` stanzas through the packaged library.
- `data/RecipientStoreInstrumentedTest` (managed device) -- `RecipientStore` against
  real SharedPreferences: add/load round-trip fidelity, per-account isolation, removal,
  `defaultEncrypt` persistence, per-account clear, blank account-id as a no-op, and
  that the raw prefs payload contains no plaintext display name or keystore handle.

Run locally:

```bash
nix develop <nixos-config>#android       # JDK 21, SDK 37, NDK 26.3, gradle 9.7.1, cargo-ndk, the AVD helpers
cd ragedroid
gradle :app:compileStandardDebugAndroidTestKotlin      # fast compile-only check
ragedroid-avd; ragedroid-emulator & ragedroid-wait-boot
gradle :app:connectedStandardDebugAndroidTest           # instrumented tests
bash ../tests/journey/run.sh                            # journey, delivery flows, registry push, browser half
```

The emulator needs KVM (Linux) or HVF (macOS).

Coverage notes:

- Real NFC / USB-OTG YubiKeys and the biometric Keystore are signed off by hand (below).
- The journey carries a secret rageterm -> ragedroid and an item the phone wrote on to the
  browser (`ragemanifest/tests/playwright/tests/android-recovery.spec.ts`, opened with the
  same paper phrase). A phrase generated ON the phone and consumed by another client is
  not covered.
- No pixels: `FLAG_SECURE` blanks every capture of the app, host-side `screencap`
  included. The per-step Compose semantics tree is the artifact instead.

CI: the `e2e-android` job in `.github/workflows/ci.yml` runs the managed-device task
on every push (ubuntu-latest, KVM enabled). The journey itself does NOT run in CI -- the
comment block above `e2e-android` in `ci.yml` records why -- but the `journey-contract`
job asserts on every push that `run.sh`, `JourneyTest` and `app/build.gradle.kts` stay
wired together (instrumentation-argument names and the like) without executing anything.

## Vaultwarden test-harness conventions

Any new test harness that launches Vaultwarden (Docker, podman, cargo-built
native binary, devcontainer, ad-hoc shell snippet in a doc -- anywhere) MUST
set the four rate-limit env vars below. Vaultwarden's defaults (10 logins /
60 s per IP, 10 admin / 60 s per IP) silently flake any harness that
registers more than a handful of test users in quick succession from the
single 127.0.0.1 source the test runner presents:

```
SIGNUPS_ALLOWED=true            # needed for register flow
WEB_VAULT_ENABLED=false         # we don't ship the web vault in tests
LOGIN_RATELIMIT_MAX_BURST=1000  # was 10
LOGIN_RATELIMIT_SECONDS=1       # was 60
ADMIN_RATELIMIT_MAX_BURST=1000  # was 10
ADMIN_RATELIMIT_SECONDS=1       # was 60
```

These are TEST-ONLY relaxations. Never apply them to a production
Vaultwarden -- the limiter exists for a reason there. The canonical values
live in `ragemanifest/tests/playwright/global-setup.ts` (both `startContainer`
and `startNativeBinary`) and `rageterm/tests/e2e_vaultwarden.rs` (the
`RELAXED_*_RATELIMIT_*` constants); keep new sites in lockstep with those.

## What we don't simulate

Hardware ceremonies that actually need a person:

- Real YubiKey (NFC tap, USB-OTG insertion). The virtual CanoKey and the mock identities
  cover the protocol; the physical path runs on a tagged release candidate before signing.
- Real Touch ID / Windows Hello / iCloud Keychain. The CDP virtual authenticator
  approximates the protocol surface but not the OS UI; we accept that gap.
- Real Play Store / F-Droid / Chrome Web Store submission. CI verifies the build
  artifact is well-formed; submission is operator-driven.

These are listed as release-gate items in `SECURITY.md` so a human signs them off
before each release.
