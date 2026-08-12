# Firefox release-gate checklist

This checklist is the manual smoke a release engineer runs before tagging a Firefox
release. It exists because the Tier-2 automated suite at
`ragemanifest/tests/playwright/` uses the Chrome DevTools Protocol's virtual
WebAuthn authenticator with `hasPrf: true`, which is Chromium-only. Firefox's
WebDriver BiDi `webauthn` module exposes virtual authenticators but Playwright's
adapter doesn't surface PRF yet, so the passkey-PRF ceremony cannot be exercised
under CI on Firefox today. See
[`ragemanifest/DESIGN.md`](../../DESIGN.md#6a-test-plan) §6a.

The automated smoke at `ragemanifest/tests/smoke-firefox.mjs` covers:

- Manifest static validation (gecko id + min-version, event-page background, no
  `nativeMessaging`).
- `web-ext lint --self-hosted` AMO-style structural validation.
- Functional popup + WASM bridge load (via headless Chromium serving
  `dist/firefox/`, since the popup is browser-agnostic JS).

What the automated smoke does *not* cover, and which this manual checklist must:

1. The popup actually mounts inside a real `moz-extension://...` origin.
2. The event-page background script wakes from the Firefox event-page lifecycle
   and re-instantiates WASM cheaply on cold-start.
3. The passkey-PRF ceremony works against a real authenticator.

---

## Prerequisites

- Firefox 132 or newer (`firefox --version`).
  - Install via `brew install --cask firefox` on macOS.
- Build the artifact: `cd ragemanifest && npm run build:firefox`.
- A passkey-bearing authenticator: Touch ID, Windows Hello, or a hardware key
  (YubiKey 5 series, SoloKeys, etc.). For the cross-device flow you can use a
  paired iPhone/Android.

---

## 1. Loading the extension

1. Open Firefox.
2. Navigate to `about:debugging#/runtime/this-firefox`.
3. Click **Load Temporary Add-on...**
4. Select `ragemanifest/dist/firefox/manifest.json`.
5. Verify:
   - The extension appears in the list as **Ragewarden** with the
     internal UUID Firefox assigned.
   - The "Inspect" button opens the background event-page console.
   - No errors are printed in the background event-page console at load.

Alternative: `cd ragemanifest && npx web-ext run --source-dir dist/firefox`.
This launches a fresh Firefox profile with the extension already loaded; useful
for fast iteration.

## 2. Popup mount

1. Click the toolbar puzzle-piece (or pin Ragewarden).
2. Click the Ragewarden icon.
3. Verify:
   - The popup HTML mounts; you see the design's "phone" frame.
   - The badge in the lower-left reads either `ragewarden ok ...` (signed in
     with a backend) or `ragewarden: sign-in cancelled` / a similar error
     (no backend) -- either is fine for popup-mount verification; the
     onboarding overlay should be functional.
   - DevTools (right-click in popup -> Inspect) shows no JS errors except the
     expected backend-network errors when no Vaultwarden is running.

## 3. Background event-page lifecycle

1. From `about:debugging#/runtime/this-firefox`, find Ragewarden, click
   **Inspect** next to the background script.
2. In the Inspector console, run:
   ```js
   await chrome.runtime.sendMessage({ kind: 'vault.status' });
   ```
   Expected: `{ ok: true, signedIn: false, email: null }` (or similar).
3. Wait 30+ seconds without using the extension. The event page should be
   suspended by Firefox.
4. Send the message again from any extension context. The event page wakes
   up, the WASM module re-instantiates, and the message returns within ~2s.

## 4. PRF capability detection

1. Open the popup; right-click -> Inspect.
2. In the popup's console, confirm the WebAuthn PRF surface exists:
   ```js
   typeof PublicKeyCredential !== 'undefined'
   ```
   Then run a passkey ceremony from the popup UI; on Firefox 132+ with PRF
   enabled it completes, and on older Firefox it fails with the explicit
   "authenticator missing PRF capability" message from `glue/passkey.js`.
3. On Firefox < 132 (or with the PRF pref disabled): `{ ..., prf: false,
   level: 'degraded', message: "...Update Firefox to 132+..." }` -- verify
   the message is user-actionable, not a stack trace.

## 5. Passkey ceremony (the autofill agent's surface)

> Coordinate with the autofill agent for the exact ceremony steps. At minimum,
> the high-level user journey is:

1. Sign in to a Vaultwarden / Bitwarden backend through the popup.
2. Run the "Set up Ragewarden protection" wizard.
3. At step "Create a passkey", verify Firefox shows its native passkey-creation
   modal (NOT a Ragewarden-styled modal -- we use the browser's built-in UI).
4. Save the passkey (Touch ID, Windows Hello, security key, or iCloud Keychain).
5. Reveal a stored secret. Verify the popup names the action ("Reveal
   github.com password?") *before* the passkey prompt fires (§0a).
6. The plaintext flows to the consumer (clipboard, autofill chip, or reveal
   panel) and the popup releases its reference (§0c).
7. Repeated reveals require fresh taps (§0b).

## 6. Content-script autofill

1. Navigate to a saved cipher's URL.
2. Focus a username/password field.
3. Verify the chip ("ragewarden · domain.com") appears, anchored at the field.
4. Click the chip. The in-page prompt sheet renders, naming the destination. It
   must NOT claim a tap is happening -- the in-page sheet is spoofable by the
   site and only starts the request.
5. Click "Continue". A separate Ragewarden window (`tap.html`, an extension
   page, not page content) opens, restating action / item / destination /
   requesting origin and whether the item is hardware-encrypted.
6. Click the authorize button in that window. Firefox shows the passkey modal.
7. Complete the tap. The window closes; both username and password fill into
   the form via dispatched `InputEvent`s.
8. Negative: repeat, but close the Ragewarden window without tapping. Nothing
   fills and the sheet reports that the window was closed.
9. Negative: repeat on a cipher that is *not* rage-protected. Step 5's window
   must say "NOT hardware-encrypted -- the tap only authorizes release", and a
   tap must still be required before anything fills.
10. Negative: repeat, and while the Ragewarden window is open, remove the
    password field from the page (devtools). Nothing fills; the sheet reports
    the field is gone.

## 7. Sign-out / lock

1. Use the popup's lock action (or close the browser).
2. Verify `chrome.storage.local` still has the encrypted session blob, but
   `chrome.storage.session` has dropped the envelope key.
3. Re-open the popup. The onboarding overlay should appear (envelope is
   un-decryptable without the session key).

---

## What to file as a regression

- Manifest fails to load at step 1.1 -> block the release.
- Popup fails to mount at step 2.1 -> block the release.
- PRF detection returns `prf: false` on a Firefox 132+ build that has PRF
  enabled in `about:config` -> file as a Firefox bug; ship a recovery-only
  build with a clear message.
- Passkey ceremony fails on a known-good authenticator -> block the release.
