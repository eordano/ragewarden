# End-to-end test harness

Layered harness so we can verify the ecosystem works without manual user testing.

---

## Tier 1 -- Rust <-> real Vaultwarden ✅ ready

Spins up `vaultwarden/server` via [`testcontainers`](https://docs.rs/testcontainers/),
registers a fresh user, posts a `rage:v1` cipher, re-fetches it, and decrypts the round-
trip.

**Files**: `rageterm/tests/e2e_vaultwarden.rs`.

**Tests**:

- `round_trip_via_real_vaultwarden` -- register -> login -> encrypt -> POST -> fetch ->
  `extract_rage_blob` -> decrypt. Verifies the full `core::sync` HTTP path against an
  unmodified Vaultwarden image.
- `cross_frontend_interop_via_ragemanifest_snapshot` -- same setup, but after fetch we
  drive `ragemanifest::snapshot::build_snapshot` over the same `Vault` and assert the
  cipher is correctly flagged `rage = true` from the browser-extension code path.

**Run locally**:

```bash
RAGEWARDEN_E2E=1 cargo test -p rageterm --test e2e_vaultwarden -- --ignored --nocapture --test-threads=1
```

Requires Docker running locally (the harness pulls `vaultwarden/server:1.32.7` once and
caches it). Each test starts and tears down its own container.

**CI**: the `e2e-vaultwarden` job in `.github/workflows/ci.yml` runs on every push.

---

## Tier 2 -- Browser extension via Playwright + virtual WebAuthn ✅ ready

Headless Chromium is launched (Playwright-pinned 1.49.1) with the unpacked extension;
Chrome DevTools Protocol's
[`WebAuthn.addVirtualAuthenticator`](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/)
seeds a virtual platform authenticator with `protocol: "ctap2"`, `transport: "internal"`,
`hasUserVerification: true`, `hasResidentKey: true`, and **`hasPrf: true`**. The PRF
capability is the whole point -- without it, `navigator.credentials.get` won't return
a 32-byte derivation we can use as a wrapping key. Each test stands up its own real
Vaultwarden via `docker run vaultwarden/server:1.32.7` (same image, env vars, and
`/alive` healthcheck as Tier 1).

**Files**: `ragemanifest/tests/playwright/`.

**Tests**:

- `tests/onboarding.spec.ts` -- opens the popup, fills the onboarding overlay
  (server URL + email + master password), clicks "Create account", waits for
  `vault.bootstrap()` to expose `window.RagewardenVault.bootstrapResult`, and
  asserts the popup dispatched `ragewarden:vault-updated`.
- `tests/passkey-prf-roundtrip.spec.ts` -- same bootstrap, plus:
  1. Attaches the virtual PRF authenticator via CDP.
  2. `navigator.credentials.create(...)` enrols a passkey; an immediate
     `navigator.credentials.get(...)` returns 32 PRF bytes used as an AES-GCM
     wrapping key. Production ragemanifest will eventually run this through the
     `webauthn-prf-v1` recipient stanza in `ragewarden-core`; until that path
     lands, the harness drives the WASM directly via
     `window.RagewardenVault.crypto`.
  3. `wasm_software_keygen` mints an age identity; the secret is AES-GCM-wrapped
     under the PRF-derived key and stashed in `chrome.storage.local`. The
     pubkey becomes an `x25519` recipient and `wasm_create_cipher` posts a
     rage-protected cipher to Vaultwarden (rage blob in the `rage:v1` HIDDEN
     custom field, both layers Type-2-wrapped).
  4. The popup is "closed" (page navigated to `about:blank` and back to the
     popup URL -- the JS context resets, `chrome.storage.*` persists, the CDP
     virtual authenticator survives because the target stays alive).
  5. A second PRF eval reproduces the wrapping key, unwraps the age secret,
     and `wasm_decrypt_with_software` recovers the plaintext.

**Principles verified** (per `DESIGN.md` §0):

- §0a -- the popup renders the destination string (`Reveal github.com password?`)
  *before* `navigator.credentials.get` fires; the test asserts both the prompt
  element is in the DOM at the moment of the PRF call and that its text
  contains the destination.
- §0b -- counters bump in lockstep: each `revealOnce` increments
  `counters.prf`, `counters.decrypt`, and `counters.wasmDecryptCalls`. After
  two reveals all three are 2.
- §0c -- after the reveal Promise resolves, `window.RagewardenVault` is walked
  and asserted to contain no string field equal to the plaintext.
- §0d -- the test fetches the cipher directly from `${VAULTWARDEN_URL}/api/sync`
  with the bearer token and asserts the JSON contains Type-2 EncString markers
  (`"2."`) and **does not** contain the plaintext. Both layers (master-key
  Type-2 + rage age) are opaque to the server.

**Run locally**:

```bash
cd ragemanifest/tests/playwright
npm ci
npx playwright install --with-deps chromium
( cd ../../.. && wasm-pack build --target web ragemanifest )   # global-setup does this too
npx playwright test
```

Requires Docker running locally (the harness pulls `vaultwarden/server:1.32.7`
once and caches it). `global-setup.ts` builds WASM if `pkg/` is stale, stages
`ext/` -> `dist/extension/` (with `wasm/` dropped under it), boots one
Vaultwarden container shared across all tests, and polls `/alive` until 2xx
with a 60s deadline. `global-teardown.ts` stops + removes the container.

**CI**: the `e2e-playwright` job in `.github/workflows/ci.yml` runs on every
push (Linux runner; Node 20 + cargo + wasm-pack + Docker; Playwright HTML
report uploaded on failure).

**Gaps / punted**:

- **Firefox / Safari**. CDP virtual authenticators with `hasPrf` are a
  Chromium-only capability; Firefox's WebDriver BiDi `webauthn` module exposes
  similar primitives but Playwright's adapter doesn't surface PRF yet. We keep
  Tier 2 Chromium-only and rely on manual testing on Firefox/Safari at release
  time. Documented in `ragemanifest/DESIGN.md` §6a.
- **Native messaging path** (`NativeMessagingPivIdentity` from
  `ragemanifest/DESIGN.md` §3b) is post-MVP and not in Tier 2.
- **Copy with auto-clear** is not exercised yet -- the harness focuses on the
  PRF roundtrip; clipboard auto-clear is design-doc level until the popup glue
  exposes a `copy` action.

---

## Tier 3 -- Android via Gradle Managed Devices + UIAutomator ✅ ready

A Pixel 6 API 34 (`aosp` system image, no Play services) is provisioned by AGP's
[Gradle Managed Devices](https://developer.android.com/studio/test/gradle-managed-devices)
DSL. Espresso + the Compose test rule drive the in-app screens; UIAutomator drives the
out-of-process surfaces (the IME's `ComposeView`, the system autofill picker, the
`AutofillAuthActivity` running under the system_server-bound autofill manager).

**Files**: `ragedroid/app/src/androidTest/kotlin/ragewarden/ragedroid/`.

**Tests**:

- `MainFlowTest` -- launches `MainActivity`, opens the GitHub fixture, taps **Reveal**,
  asserts the action title (`"Reveal GitHub password?"`) is visible *before* the
  `Authorize` button is tapped (verifies §0a -- action chosen before tap), then asserts
  the GitHub plaintext is rendered in `RevealedPasswordCard`. Hides and reveals again to
  verify a fresh tap ceremony is required for each use (verifies §0b -- strict tap per
  use).
- `TotpFlowTest` -- opens an item with a `totpSeed`, asserts the `TotpCard` displays a
  six-digit numeric code, taps **Copy**, asserts the success toast surfaces.
- `ImeFlowTest` -- UIAutomator. Programmatically enables and switches to
  `RagewardenInputMethodService` via `ime enable` / `ime set` shell commands run through
  `UiAutomation.executeShellCommand`. Focuses the `EditText` on a tiny `TestActivity`,
  picks the GitHub row from the IME's vault picker, asserts the tap-prompt title carries
  the destination domain (verifies §0a), confirms via the `Authorize` button, asserts
  `EditText.getText()` matches the GitHub plaintext, and asserts the active IME is no
  longer ragewarden (the IME yielded via `switchToPreviousInputMethod`).
- `AutofillFlowTest` -- UIAutomator. Sets `secure autofill_service` to
  `ragewarden.ragedroid/.autofill.RagewardenAutofillService` via shell, focuses the
  username field on `TestActivity`, taps the cold dataset chip in the system picker,
  asserts the `AutofillAuthActivity` surfaces the action (`"Autofill into ..."`) *before*
  the `Authorize` button is tapped (verifies §0a + the §0c "no plaintext yet" property --
  the cold dataset is empty until the auth path succeeds), confirms via Authorize,
  asserts both fields receive the expected fixture plaintext, then asserts
  `AutofillAuthActivity` has finished and the `TestActivity`'s intent extras carry no
  plaintext (verifies §0c -- plaintext isn't reachable from any state after fill).

`TestActivity` lives at
`ragedroid/app/src/androidTest/kotlin/ragewarden/ragedroid/testfixtures/TestActivity.kt`
and inflates the `test_form_activity` layout with a username `EditText`
(`autofillHints="username"`) and password `EditText` (`autofillHints="password"`).

`DemoVaultStore` is fixture-driven (deterministic without any real hardware) so the
phase-1 software identity satisfies the JNI path. No `RAGEWARDEN_MOCK_HARDWARE=1` flag is
read in phase 4; when phase 3 introduces real `KotlinIdentity` callbacks, that flag will
be wired into the JNI bridge and propagated from
`InstrumentationRegistry.getArguments()`.

**Run locally**:

```bash
cd ragedroid
export JAVA_HOME=/path/to/zulu-17
export PATH=$JAVA_HOME/bin:$PATH
export ANDROID_HOME=/path/to/android-sdk
export ANDROID_SDK_ROOT=$ANDROID_HOME
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/26.3.11579264

./gradlew :app:compileStandardDebugAndroidTestKotlin     # fast compile-only check
./gradlew :app:pixel6Api34StandardDebugAndroidTest       # full e2e -- boots emulator
```

The full run requires KVM (Linux) or HAXM/HVF (mac/Windows). On Apple Silicon the
`x86_64` AOSP image is slow without nested virt; CI is the canonical path.

**Limitations**:

- The system autofill picker UI shape is API-level-sensitive. Only API 34 is exercised;
  the text-matching selectors (`"Autofill into ..."`) match the cold-dataset RemoteView
  rendering on API 34's autofill picker.
- Inline-suggestion presentations (API 30+ inline / API 33+ `Presentations`) are not
  exercised -- phase 4 wires only the legacy `RemoteViews` dataset path.
- Real hardware paths (NFC / USB-OTG YubiKey, biometric Keystore) are out of scope here;
  see "What we don't simulate" below.

**CI**: the `e2e-android` job in `.github/workflows/ci.yml` runs on every push, on
ubuntu-latest with KVM enabled.

---

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

---

## What we don't simulate

Hardware ceremonies that actually need a person:

- **Real YubiKey** (NFC tap, USB-OTG insertion). Mock-mode covers the trait callbacks;
  the real-hardware path runs on a tagged release-candidate before signing.
- **Real Touch ID / Windows Hello / iCloud Keychain**. The CDP virtual authenticator
  approximates the protocol surface but not the OS UI; we accept that gap.
- **Real Play Store / F-Droid / Chrome Web Store submission**. CI verifies the build
  artifact is well-formed; submission is operator-driven.

These are listed as release-gate items in `SECURITY.md` so a human signs them off
before each release.
