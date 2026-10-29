# Release checklist -- real browsers, real authenticators

Run before tagging a release. Everything that needs no person and no hardware is automated
and must already be green: `nix build .#checks.x86_64-linux.ragemanifest` in the NixOS config flake (wasm,
the three zipped builds, the Firefox smoke and `web-ext lint`, unit tests, the store
package check, real headless Firefox over WebDriver BiDi -- install, popup mount, event-page
cold start, tap window -- and the host cargo tests) and the Tier-2 Playwright suite. What is
left needs an authenticator with PRF, a PIV/FIDO2 key, and macOS, none of which an
automated runner has: the virtual authenticators in WebDriver BiDi expose no PRF.

## Prerequisites

- Firefox 132+, Chrome 116+, Safari 18+ (macOS).
- A PRF-capable passkey provider (Touch ID / iCloud Keychain, Windows Hello, a YubiKey 5,
  a phone over the cross-device flow) and a YubiKey with a PIV slot or FIDO2 credential
  enrolled through rageterm, plus `rageterm install-native-host --browser firefox` (and
  `--browser chromium`).
- The release artifacts: `ragemanifest-firefox.zip` / the signed `.xpi`,
  `ragemanifest-chromium.zip`, and `Ragewarden.app` from `safari-host-app/build.sh`.

## 1. Each browser loads and signs in

1. Firefox: `about:debugging#/runtime/this-firefox` -> Load Temporary Add-on ->
   `dist/firefox/manifest.json` (or install the signed `.xpi`). Chrome: Load unpacked.
   Safari: open `Ragewarden.app`, enable the extension.
2. Open the popup. Sign in: the browser asks for access to the server's origin only;
   allow it. Expect the protection wizard.

## 2. Passkey protection (§0a, §0b)

1. Create passkey: the browser's own passkey dialog appears; save it. Add a backup passkey
   on a second authenticator, or skip and complete the paper phrase step.
2. A browser or authenticator without PRF must stop at step 1 with the message naming the
   minimum versions -- never a stack trace and never a published recipient.
3. Reveal an item: before the passkey dialog, the popup shows "Reveal <item>" and "to this
   screen". A second reveal asks for a second tap. The value hides after 10 s.
4. Copy: the clipboard holds the password, and 30 s later it is overwritten even if the
   popup was closed meanwhile.
5. Note whether the popup stays open while the OS passkey dialog has focus (Windows Hello,
   macOS sheets). Where it closes, the page chip's Ragewarden window must complete the
   same tap.

## 3. Page autofill

1. Open a saved site and focus its password field: the chip appears inside the viewport.
2. Click it: the Ragewarden window names the action, item, destination and whether the
   item is hardware-encrypted; tap; the form fills.
3. With two logins for the site, the chip opens a picker first.
4. A login form inside a frame: the window names "host (in a frame on embedder)".
5. Close the window without tapping: nothing fills.

## 4. PIV / FIDO2 through rageterm

1. Open an item wrapped to the YubiKey PIV or FIDO2 recipient: rageterm's notification
   asks for the touch, and the item opens only after it.
2. With the key unplugged, the item fails with a message, not a hang.

## 5. Lock

1. Lock from Settings: reopening the popup shows the lock screen; the master password
   unlocks it, also with the network off.
2. Lock the OS screen (Chromium, Firefox): the extension is locked afterwards. Safari has no
   idle API; there, leave it 15 minutes and confirm the idle deadline locks it.

## 6. Cross-device PRF (I14)

On a RageDroid phone, enrol its passkey (rp id `ragewarden.decent.foundation`) and write an
item wrapped to it only (no other recipient on that device). In the browser, reveal it:
a tab opens on `https://ragewarden.decent.foundation/prf` naming the action and the
destination; Use my passkey offers the phone (QR / hybrid, or the passkey synced to Google
Password Manager); after the tap the tab closes itself and the value appears. Cancelling on
the phone, or closing the tab, ends the reveal with a message and nothing revealed.

Block the release on any failure in 1-6.
