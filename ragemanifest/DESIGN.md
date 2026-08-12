# RageManifest -- browser extension

Cross-browser MV3 web extension for the [Ragewarden](../DESIGN.md) ecosystem. Read the
ecosystem design first. This file is browser-specific.

---

## 1. Targets

| browser | extension model | host requirement | distribution |
|---|---|---|---|
| Chrome / Edge / Brave / Arc / Vivaldi | MV3 | none | Chrome Web Store, sideload |
| Firefox | MV3 (with `event_pages` accommodation) | none | AMO (addons.mozilla.org), sideload |
| Safari | MV3 wrapped in macOS host app | macOS host app + Apple Developer ID | App Store |

One Rust -> WASM core. Three thin shells. Manifests differ; logic doesn't.

---

## 2. Module layout

```
ragemanifest/
+-- DESIGN.md                # this file
+-- README.md
+-- Cargo.toml               # WASM crate (cdylib) -- wasm-bindgen, ragewarden-core
+-- src/lib.rs               # WASM exports: encrypt, decrypt, identity-callbacks
+-- ts/                      # TypeScript glue
|   +-- popup/               # popup UI (tiny react or solid app)
|   +-- content/             # content script for autofill probing
|   +-- background/          # MV3 service worker / event page
|   +-- webauthn.ts          # WebAuthn-prf identity wrapping
|   +-- native-host.ts       # native messaging bridge to rageterm-as-helper
+-- manifests/
|   +-- chromium.json
|   +-- firefox.json
|   +-- safari.json
+-- safari-host-app/         # macOS Xcode project for Safari shell (App Store distribution)
+-- icons/
+-- build.mjs                # esbuild orchestrator; vite-style; builds 3 zip artifacts
```

The WASM lib loads once per service worker; encrypt/decrypt happen there. The popup, content
script, and background communicate via standard `runtime.sendMessage`.

### 2a. Popup glue (`ext/glue/`) -- phase 2

The canonical `design/` folder is hosted as the popup. Crypto + vault sync are bridged
through ES modules under `ext/glue/`:

- `crypto.js` -- thin re-export of the WASM surface for the software-identity entry
  points (`init`, `softwareKeygen`, `encrypt`, `decryptWithSoftware`, `moduleTag`,
  `isReady`). All inputs/outputs are `Uint8Array`.
- `vault.js` -- session-aware popup state. On bootstrap we look up a saved session blob;
  if absent the user is sent through `onboarding.js` (which delegates to the WASM
  `wasm_register` / `wasm_login` exports). With a session in hand, `wasm_fetch_vault`
  returns a `{ ciphers, folders }` snapshot already shaped for the design's `data.jsx`
  consumers (cipher names, login usernames, primary URIs decrypted; secret fields stay
  encrypted). `revealPassword(itemId, fieldName)` calls `wasm_decrypt_cipher_field`
  per use -- there is no module-level plaintext cache anywhere in the glue.
- `storage.js` -- persists the session blob in `chrome.storage.local`, AES-GCM-wrapped
  under an ephemeral 256-bit key kept in `chrome.storage.session`. Browser restart
  drops the session-storage key, so the on-disk envelope becomes undecryptable and the
  user is funneled back through onboarding. Inside one browser session, repeated popup
  opens decrypt the envelope cheaply. This is a phase-2-acceptable approximation;
  phase 3 will replace the AES key with a passkey-PRF derivation so even an attacker
  with full file-system access can't recover the bearer token without a tap.
- `onboarding.js` -- minimal overlay rendered before the design's React tree mounts.
  Surfaces server URL + email + password fields; toggles to a register flow when the
  user opts to create an account. On success, hands the session blob back to the
  bootstrap and dismisses itself.
- `init.js` -- popup-init glue, loaded as an ES module after the design's React + the
  inline-compiled scripts. Boots WASM, runs `vault.bootstrap()`, exposes
  `window.RagewardenVault`, dispatches a `ragewarden:vault-updated` event so the
  design layer can refresh, and renders a tiny status badge.

§0b is enforced naturally now that ciphers arrive from the server already encrypted:
each reveal / copy / autofill triggers a fresh `wasm_decrypt_cipher_field`, the
plaintext exists only inside the resolving Promise's resolution scope, and the JS
glue holds no decrypted bytes beyond the call site.

---

## 3. Identity implementations

**The browser path is passkey-first.** We do not require the user to plug in or tap a
specific hardware token; we ask the browser for a passkey, and the browser presents whatever
the user has set up -- Touch ID, Windows Hello, Android phone over the cross-device flow,
iCloud Keychain, a security key plugged in or held to NFC, a password manager that vends
passkeys, etc. The browser owns the modal and the credential picker.

### 3a. PasskeyIdentity (primary, day-one)

Built on WebAuthn with the [PRF extension](https://w3c.github.io/webauthn/#prf-extension).
PRF takes a per-secret salt and returns a 32-byte HMAC-SHA-256 derivation that's bound to
the chosen passkey; we HKDF-expand it to a file key.

**Enrollment** -- `navigator.credentials.create(...)` with our relying-party ID
(`ragewarden` -- set per the WebAuthn `rp.id` rules; bound to the extension's identity, not a
domain), `userVerification: "required"`, and `extensions.prf: { eval: { first: salt } }`. The
browser shows its native passkey-creation modal:

- macOS / iOS Safari + Chrome: "Save passkey to iCloud Keychain / [security key] / [paired
  iPhone]" picker.
- Windows: Windows Hello biometric or security key.
- Android (cross-device flow on desktop browser): pair phone via QR code, finish on phone
  with biometric.
- ChromeOS / Linux Chrome: security key required (no native platform authenticator), or
  paired Android via cross-device.

We store the resulting credential ID + display label as a `Recipient::PasskeyPrf { credential_id, salt, rp_id, label }` in the vault's recipient list. The PRF output never leaves the
browser process; we use it immediately to encrypt the file key.

**Use** -- `navigator.credentials.get({ publicKey: { allowCredentials: [{ id: credentialId, type: 'public-key' }], userVerification: 'required', extensions: { prf: { eval: { first: salt } } } } })`.
Browser presents whichever modal applies (Touch ID prompt, security-key tap UI, cross-device
QR, etc.). On success, PRF output -> HKDF -> file key -> WASM decrypt -> plaintext goes to the
bound consumer.

**Why this is better than naming a hardware token:**

- The user enrolls with whatever they already have. No "you need to buy a YubiKey."
- Each unlock is *one user action* -- biometric, tap, whatever -- without us prescribing
  what kind. The browser already solved this UX.
- Multiple passkeys per user = multiple recipients, free. Enroll a Touch ID passkey on the
  Mac, a Windows Hello passkey on the work PC, a YubiKey passkey as the cross-device
  fallback. Everything goes in the recipient list.
- The cross-device flow (passkey on phone, scan QR on laptop) means a user with no local
  authenticator on a borrowed device can still authenticate via their phone.

**Browser version requirements:**

| browser | minimum for PRF | notes |
|---|---|---|
| Chrome / Edge / Brave / Arc | 116+ | Stable; widely deployed |
| Firefox | 132+ | Behind `security.webauth.webauthn_enable_prf` flag in some builds; stable in recent |
| Safari | 18+ | macOS Sonoma+ / iOS 17.2+ |

Below those: passkey enrollment works but PRF doesn't, so we can't derive a key from the
passkey. Fall back to recovery-passphrase identity for users on older browsers, or direct
them to upgrade. Document the matrix in the install flow.

### 3b. NativeMessagingPivIdentity (PIV via rageterm)

For users who already have rage-encrypted secrets via a YubiKey PIV slot from another
frontend (ragedroid or rageterm), or who explicitly want PIV semantics, we proxy through
`rageterm --native-host`. PIV smart-card operations are not reachable from browsers
(WebUSB / WebHID don't expose CCID).

```
extension                              rageterm (--native-host)
   |                                       |
   |  stanzas[], action_context            |
   | ---------------------------------►    |
   |                                       |  user taps YubiKey
   |                                       |  PCSC scalar mult
   |                                       |
   |             file_key (32 bytes)       |
   | ◄---------------------------------    |
   |                                       |
```

The protocol carries only the stanza and the action context (e.g., "autofill github.com");
plaintext never leaves rageterm -- the file key it returns is what unlocks the age blob in
the extension's WASM module. Native messaging requires the user to install rageterm and
register its host manifest (`com.ragewarden.host`); covered in onboarding.

Why route file-key back instead of routing plaintext through rageterm: keeps rageterm out of
the plaintext flow when the consumer is the browser autofill API. Smaller blast radius.

This path is **secondary**. Most users will never see it. It exists for cross-frontend
compatibility, not as the primary onboarding path.

**Wiring (post-MVP cross-frontend interop):**

`ragemanifest/ext/glue/native-host.js` exposes `nativeMessagingPivIdentity({...})`,
which conforms to the same `{ kind, tryUnwrap(stanza) }` shape used by the popup's
in-process `KotlinIdentity` adapters. The popup builds an identity list per decrypt
attempt; if the user has rageterm installed and registered (`com.ragewarden.host`),
the native-messaging adapter sits at the end of the list and answers stanzas tagged
`piv-p256` by routing through the background's `chrome.runtime.connectNative` port.
Background does the JSON-RPC round-trip; the file key bytes come back base64-encoded
and are handed straight to the existing `wasm_decrypt_with_software` path. Plaintext
never leaves the browser process; rageterm only ever sees the stanza body and the
file key.

The native host is **never auto-launched**: the user has to opt in by running
`rageterm install-native-host --browser chromium|firefox`. On a fresh install the
adapter's `tryUnwrap` short-circuits at `probe()` (returns `available: false`) and the
popup falls back to the next identity. This keeps the default ragemanifest install
fully self-contained while letting power users that already enrolled YubiKey-PIV
recipients via rageterm or ragedroid round-trip those ciphers in the browser.

### 3c. Software passphrase identity (recovery only)

Same as in the other frontends. Used at recovery, not in normal operation.

### 3d. Not supported in browser

- **Bare WebUSB / WebHID smart-card access** -- would need CCID. Browsers don't expose it.
  Routed via 3b for users who specifically want PIV.
- **NFC outside of WebAuthn** -- NFC reads only happen inside the browser's own WebAuthn
  flow. We can't talk to the YubiKey directly; we go through WebAuthn's authenticator
  selection (which can include NFC YubiKeys configured as passkeys).
- **Local OS keyring directly** -- not reachable. Could route via native host, but the value
  is small on a desktop where the platform passkey already covers the same use case.

So in practice: browser path = passkey + PRF (covers Touch ID, Windows Hello, NFC YubiKey,
USB security key, cross-device phone). Native host is the optional escape hatch for
preexisting PIV-protected secrets.

---

## 4. UI flows -- action chosen before tap

### 4a. The toolbar popup

Small popup app:
- Top: vault search.
- List of ciphers, filtered by current tab's domain by default.
- Per-cipher: explicit-action buttons.

```
github.com  -------------------------
  username: my-handle              [ copy ]
  password (🔒)                    [ autofill ] [ copy ] [ reveal ]
```

Each action triggers the prompt sheet (4b) bound to the destination. No "decrypt and choose
later."

### 4b. The prompt sheet (in-popup overlay)

Modal inside the popup that names the action and the destination, then triggers the passkey
ceremony.

```
+----------------------------------------+
| Autofill into github.com?              |
|                                        |
| Authenticate with your passkey.        |
|                                        |
| [ Cancel ]                             |
+----------------------------------------+
```

When the user clicks "Authenticate with passkey" (or just confirms), the popup calls
`navigator.credentials.get({ publicKey: { allowCredentials: [...our passkey ids...], userVerification: 'required', extensions: { prf: { eval: { first: salt } } } } })`.

The browser owns the rest: it shows its native picker (Touch ID prompt, Windows Hello,
security-key insert, NFC YubiKey, cross-device QR for phone-based passkeys). The user does
whatever their passkey requires -- biometric, tap, etc. On success, PRF output -> HKDF ->
file key -> WASM decrypt -> plaintext goes to the bound consumer (clipboard, autofill
content script). On failure / cancel: nothing happens.

We never tell the user *which* passkey to use. They picked at enrollment; the browser
remembers; the system modal handles disambiguation if there's more than one. The action
string (`"Autofill into github.com"`) is the only thing we control in that moment.

### 4c. Autofill content script -- wired

`ragemanifest/ext/content.js` runs at `document_idle` on `<all_urls>`. It walks the DOM
on focus events using the same heuristic family `ragedroid` uses in
`AutofillFieldHeuristics.kt`:

1. **autocomplete tokens** first (`autocomplete="username" / "email" /
   "current-password"`).
2. **Input types** next (`type="password"`, `type="email"`).
3. **Heuristic fallback** on the input's `name` / `id` / `placeholder` /
   `aria-label` / nearest `<label>` text against
   `/(user|email|login|account)/`.

Field detection is symmetric: focus on the password walks backward for the username;
focus on the username walks forward. If a form has only a password field, the chip
still appears.

When a credential field gains focus, the content script sends a
`{ kind: 'vault.lookup', origin }` message to the background service worker
(`ragemanifest/ext/background.js`). The background returns
`{ ok: true, matches: [...] }` derived from the in-memory snapshot. If there are no
matches the chip stays hidden.

If there is at least one match, the chip ("ragewarden · github.com") is rendered into a
**closed Shadow DOM** anchored at `<body>`:

- `attachShadow({ mode: 'closed' })` prevents site CSS from styling the chip.
- A closed root prevents page scripts from observing the chip's DOM via traversal.
- Element + style elements are minted from the content script process (not the page
  world), so site Trusted Types / Content Security Policy cannot block them.
- All elements are absolutely positioned with high `z-index`; resize/scroll listeners
  reposition the chip relative to the focused field.

Clicking the chip surfaces the **prompt sheet** (also in the closed shadow root). The
sheet renders `Autofill into <destination>?` *before* dispatching anything to the
background -- this is §0a's guardrail. The user clicks "Authenticate", which sends
`{ kind: 'vault.unlock', cipherId, action: 'autofill', destination }` to the
background. The background:

1. Refreshes its in-memory snapshot if needed (the WASM module re-instantiates per cold
   service-worker generation; the JS import + browser WASM cache make this cheap).
2. Picks the right identity (passkey-PRF in the popup path; native-host PIV via
   `ragemanifest/ext/glue/native-host.js` if `chrome.runtime.connectNative` resolves
   `com.ragewarden.host`).
3. Calls `wasm_decrypt_cipher_field`. The plaintext is shipped back to the content
   script in the message round-trip.

The content script types the plaintext into the form via dispatched `InputEvent`
sequences against the **native** `value` setter (frameworks like React patch the
prototype setter, so we call the unpatched descriptor directly to defeat their
short-circuit). Each character produces a `beforeinput` + `input` event with
`inputType: "insertText"`, with a small `setTimeout` delay between characters so SPA
debounced validators see them as discrete keystrokes. Final `change` and `blur` events
fire after the last character.

§0c is enforced by the message round-trip itself: the background returns the plaintext
once; the content script reads it, dispatches the events, then drops the reference. No
`window.RagewardenContent` field, no closure variable retains it.

The Tier-2 spec `tests/playwright/tests/autofill-content-script.spec.ts` exercises the
full path: enrol passkey + create rage cipher in the popup, then load
`tests/fixtures/login-form.html`, drive the chip through harness hooks, confirm the
prompt sheet names the destination, dispatch the fill, and read back the form's
captured `input` events to prove the keystrokes flowed through bubbling event
listeners (not the `.value=` shortcut).

### 4d. Reveal

Same modal pattern. Plaintext shown until the modal is dismissed. No persistence.

### 4e. Onboarding

1. Click toolbar icon -> "Sign in to Bitwarden / Vaultwarden."
2. Sign in (server URL + email + master password). WASM core derives keys; vault syncs.
3. "Set up Ragewarden protection" wizard:
   - **Step 1 -- Create a passkey for Ragewarden.** Calls `navigator.credentials.create`
     with PRF extension. The browser shows its passkey-creation picker. User saves to
     wherever they want (iCloud Keychain, Windows Hello, security key, etc.). We record the
     credential ID + a default per-secret salt scheme as a `PasskeyPrf` recipient.
   - **Step 2 (skippable) -- Enroll a backup passkey.** Strongly suggested. If the user
     skips, they're warned that losing the only passkey means losing the secrets.
   - **Step 3 (skippable) -- Paper recovery identity.** Generates a software age identity,
     displays as 24 BIP39 words, asks user to confirm they wrote it down. Mandatory if the
     user skipped step 2.
4. (Optional, post-MVP) "Install rageterm helper" -- only needed if the user wants
   PIV-protected secrets to round-trip into the browser. Most users skip this.

---

## 5. Cross-browser quirks

- **Manifest V3 background lifecycle** -- Chromium uses service workers; Firefox uses event
  pages (background scripts that get torn down faster than Chromium service workers).
  Practical impact: don't keep WASM-instantiated state across teardowns; re-instantiate per
  message. `WebAssembly.compileStreaming` once per generation is fast on both engines, so the
  re-init cost is dominated by the first WASM compile. Firefox event-page scripts are NOT ES
  modules, so `background.js` is authored as a non-module file (zero static `import` /
  `export`) and uses dynamic `import()` for the WASM bundle -- which works equally well in
  Chromium service workers. The same source ships to both targets; `build.mjs` handles the
  manifest-shape divergence.
- **`background` manifest divergence** -- Chromium accepts
  `{ "service_worker": "background.js", "type": "module" }`; Firefox MV3 wants
  `{ "scripts": ["background.js"] }` and rejects `"type": "module"`. `build.mjs`'s
  `target === 'firefox'` branch strips the Chromium-only keys before applying the Firefox
  overlay and asserts the resulting shape (an `Error` is thrown at build time if the
  produced manifest still carries `service_worker` or `"type": "module"`).
- **WebAuthn modal UI differs** -- Chrome shows a system modal; Firefox shows an in-browser
  modal; Safari shows a system sheet. All sufficient for our purposes; we don't try to style
  them.
- **PRF extension support** -- Chromium 116+, Firefox 132+, Safari 18+. Below those:
  WebAuthn-PRF identities don't work, fall back to recovery-passphrase or native host.
  `glue/passkey.js` checks the PRF extension result at ceremony time and throws a
  user-actionable message ("authenticator missing PRF capability") instead of a stack trace.
- **Storage namespace** -- both Chromium and Firefox MV3 expose `chrome.*`, but Firefox also
  binds the same surface to `browser.*`. `glue/storage.js` resolves
  `globalThis.chrome ?? globalThis.browser` defensively. `chrome.storage.session` works on
  both (Firefox 115+); the AES-GCM session-key envelope ports cleanly.
- **Native messaging path** differs per browser:
  - Chromium: registry on Windows, JSON manifest in `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` on macOS, similar on Linux.
  - Firefox: similar JSON manifest in browser-specific paths. The Firefox build currently
    omits `nativeMessaging` from `permissions` (PIV via host is out of scope this round);
    when it lands, `rageterm install-native-host --browser firefox` writes to the right place.
  - Safari: native messaging not supported; PIV via host requires the host app to do its own
    bridging via `NSExtensionContext`. Tricky; PIV on Safari ragemanifest is **post-MVP**.

---

## 6. Safari is meaningfully different

Chromium and Firefox ship at parity; Safari is the only post-MVP browser. Worth flagging
clearly because Safari is a step-change in cost compared to the other two.

- Safari Web Extensions ship **as part of a host macOS app** (or iOS app, but we're
  desktop-only). The host app must be Apple-Developer-ID-signed and (for App Store)
  notarized. Cost: $99/year Apple Developer Program.
- The MV3 manifest is mostly compatible but Apple's reviewer process is stricter than Chrome
  Web Store.
- The host app is a Swift/Xcode project. Minimal -- just enough to install the extension and
  satisfy Apple's "extensions must have a host app" requirement. Skeleton lives at
  `ragemanifest/safari-host-app/`.
- Native messaging path is different (see §5). PIV via rageterm-as-host is **post-MVP** on
  Safari.
- **Recommendation: Chromium and Firefox ship together; Safari follows in a separate
  release.** Same `ragemanifest` Cargo crate produces the WASM bundle; only the manifest
  and host-app shell differ. We commit to Safari but it's a phase-4 deliverable (per the
  canonical roadmap in [`../DESIGN.md`](../DESIGN.md#7-sequencing)), not part of the
  initial Chromium+Firefox launch.

---

## 6a. Test plan

Tier 2 of [`../E2E.md`](../E2E.md) lives in `ragemanifest/tests/playwright/`. The
harness drives the popup against a real Vaultwarden in Docker (same image, env
vars, and `/alive` healthcheck as Tier 1) with the extension loaded into headless
Chromium via `chromium.launchPersistentContext` + `--load-extension=...` /
`--disable-extensions-except=...`. Cross-frontend properties -- and the four
non-negotiable design principles in [`../DESIGN.md`](../DESIGN.md#0-design-principles) --
are asserted automatically.

### Virtual WebAuthn authenticator

Chrome DevTools Protocol's `WebAuthn.addVirtualAuthenticator` is the linchpin.
The harness attaches an authenticator with:

```json
{
  "protocol": "ctap2",
  "transport": "internal",
  "hasResidentKey": true,
  "hasUserVerification": true,
  "hasPrf": true,
  "automaticPresenceSimulation": true,
  "isUserVerified": true
}
```

`hasPrf: true` is the critical capability -- without it, `navigator.credentials.get`
returns no PRF results and there's no derivation surface to wrap an age secret
with. With it, an enrol + immediate `get()` returns a deterministic 32-byte
HMAC-SHA-256 derivation per `(credential, salt)` pair, which is exactly what
phase-3's [`PasskeyIdentity`](#3a-passkeyidentity-primary-day-one) will consume.

The popup is "closed and reopened" by navigating the page to `about:blank` and
back -- the JS context resets, `chrome.storage.*` persists, and the CDP virtual
authenticator survives because the target stays alive. A cross-page
`addVirtualAuthenticator` would lose the PRF seed (CDP's `Credential` schema
doesn't expose `prfSeed`).

### What's verified

| principle | assertion |
|---|---|
| §0a action named before tap | popup renders the destination string before `navigator.credentials.get` fires |
| §0b strict tap per use | per-reveal counters bump in lockstep (PRF, JS decrypt, WASM `wasm_decrypt_with_software`) -- see the caveats below before reading this as a proof |
| §0c plaintext lifetime microseconds | after the reveal Promise resolves, `window.RagewardenVault` is walked and contains no string equal to the plaintext |
| §0d server stores nothing usable | `${VAULTWARDEN_URL}/api/sync` returns Type-2 EncString markers and no plaintext bytes |

#### What the §0b counter assertion does and does not prove

The tap counters (`ext/glue/tap-counters.js`) were, until recently, dishonest in two
specific ways, and the fuzzer's lockstep assertion was passing over them:

- `prf_eval` was bumped after `performPresenceTap()`, which is a presence/UV assertion and
  evaluates no PRF at all. That bump now increments a separate `presence_tap` counter.
- `wasm_decrypt` and `js_decrypt` were bumped *before* the operation they name. A declined
  tap or a WASM error therefore left the counter claiming work that never happened. All
  three now bump only after the call returns.

What the assertion proves today: on the PRF reveal path, one reveal produces exactly one
PRF evaluation and one decrypt. What it still does not cover:

- `recoverFromPhrase()` (`ext/glue/vault.js`) calls
  `wasm_decrypt_cipher_field_with_secrets` with **no tap and no counter bump of any kind**.
  That is intentional for a paper-recovery path -- there is no authenticator to tap -- but it
  means the counters are silent on it, and §0b does not apply to it. Surfacing recovery
  decrypts as their own counter is **NOT YET IMPLEMENTED**.
- The fuzzer's §0b block iterates only `rage` ciphers, which always take the PRF branch, so
  the presence branch is not exercised by it.
- The counters are an instrumentation aid. They are not a security control: nothing in the
  extension refuses to decrypt because a counter looks wrong.

### Cross-browser caveats

- **Firefox / Safari are not in Tier 2 today.** CDP virtual authenticators with
  `hasPrf` are Chromium-only; Firefox's WebDriver BiDi `webauthn` module
  exposes similar primitives but Playwright's adapter doesn't surface PRF
  yet, and Safari has no remote-WebAuthn surface at all. The four Chromium
  Tier-2 assertions for §0a-§0d therefore stand in for the Firefox build
  too -- the same source code runs in both browsers, with `build.mjs`
  reconciling only the manifest shape.
- **Firefox release-gate manual smoke.** Each release runs the manual smoke
  in [`tests/manual/firefox-checklist.md`](tests/manual/firefox-checklist.md) -- it
  exercises the popup-mounts-under-`moz-extension://` path, the event-page
  cold-start lifecycle, the PRF capability checks in
  [`ext/glue/passkey.js`](ext/glue/passkey.js), and the live passkey
  ceremony against a real authenticator. Fast-iteration in dev runs
  [`tests/smoke-firefox.mjs`](tests/smoke-firefox.mjs), which combines manifest
  validation + `web-ext lint --self-hosted` + a Chromium-proxy popup load (the
  popup is browser-agnostic JS+WASM, so a Chromium load is a strong proxy
  signal that Firefox will mount it) + an opt-in headed `web-ext run` against
  a real Firefox install.

---

## 7. Build & distribution

- `wasm-pack build --target web ragemanifest` -> `pkg/`
- `node build.mjs chromium` / `firefox` / `safari` -> produces signed extension zip per target.
- CI: GitHub Actions with the three browsers (Chrome / Firefox installed via Playwright; Safari
  on macOS runner only).
- Release: tag-triggered -> uploads to Chrome Web Store via puppeteer, AMO via web-ext, App
  Store via altool. Manual approval for App Store.

---

## 8. Open browser-specific questions

1. **Page-script attack surface.** A compromised content script on a hostile site could
   in principle race the legitimate autofill -- but our model requires the user to *click* the
   ragewarden overlay button (initiated from extension UI, not page script) before any
   prompt fires. **Default: actions only initiated from extension-controlled UI**, never from
   page script. Document.

2. **Extension popup vs. side panel.** Chrome's side panel API is nicer than the popup
   (popup closes when focus moves; side panel persists). **Default: side panel on
   Chromium**, popup elsewhere.

3. **Vault cache in extension storage.** `chrome.storage.local` is unencrypted on disk in
   most browsers. Bitwarden's outer layer protects ciphers anyway, but the metadata leaks
   (cipher names, URIs). **Default: cache only what's needed for autofill matching, encrypt
   the cache with a session key derived from the master password, evict on lock.**

4. **Lock UX.** When does the extension auto-lock? On browser close, on manual lock, on
   timeout? **Default: auto-lock 15 minutes after last action; manual lock from popup;
   browser-close lock is automatic since the service worker dies anyway.**
