# RageManifest -- browser extension

Cross-browser MV3 extension for the [Ragewarden](../DESIGN.md) ecosystem. Read the ecosystem
design first; this file covers what is specific to browsers. The directory layout and the
build are in [`README.md`](README.md).

## 1. Targets

| browser | background | PRF minimum | distribution |
|---|---|---|---|
| Chrome / Edge / Brave / Arc / Vivaldi | module service worker (glue imported statically) | 116 | Chrome Web Store package from the release workflow; sideload |
| Firefox | event page (`background.scripts`, glue imported on demand) | 132 | AMO (unlisted, signed by the release workflow); sideload |
| Safari | non-persistent background page | 18 | `Ragewarden.app` from `safari-host-app/build.sh` |

One Rust crate compiled to wasm, one set of extension sources; `build.mjs` emits the
manifest each browser accepts. Safari has no idle API and no offscreen documents, so its
build drops `idle` and `offscreen`; the auto-lock deadline still runs on `alarms`. Safari
has no native-messaging host manifests either: `runtime.sendNativeMessage` reaches the
extension's own app, whose handler (`safari-host-app/Extension/SafariWebExtensionHandler.swift`)
relays the same framed request to `rageterm native-host` -- the one the app bundles, or an
installed one -- and returns its reply.

## 2. Identities

- **WebAuthn PRF passkey (primary).** Enrolment creates a passkey with the PRF extension
  for rp.id = the extension's own host (`defaultRpId()`), stores the credential, its salt
  and its public key, and publishes a `PasskeyPrf` registry entry. A browser or
  authenticator without PRF is refused at enrolment with a message naming the minimum
  versions. Every unlock is one `navigator.credentials.get` whose PRF output unwraps the
  item.
- **Software twin.** Enrolment also generates an age X25519 identity, wraps its secret
  under the passkey's PRF output and publishes it as a `Software` entry, so other clients
  can write to this browser. Opening it still costs the passkey tap.
- **Writes.** Saving an item costs one tap: each of this browser's passkey recipients gets
  a fresh salt, one assertion evaluates them, and the item is wrapped to the passkey that
  answered plus every public-key recipient. Bulk protect wraps to the public-key
  recipients only, so it needs no tap per item.
- **Backup passkey.** The first-run wizard can enrol a second authenticator as its own
  `PasskeyPrf` entry.
- **Phone passkey, through the relay.** A passkey made for `ragewarden.decent.foundation`
  -- RageDroid's, used over hybrid/QR or synced through a password manager -- can only be
  asked from a page on that origin. When a stanza names such a `PasskeyPrf` entry and
  nothing in this browser opens the item, the worker opens
  `https://ragewarden.decent.foundation/prf#<nonce>` (`relay/`, served by vpnhead). Its
  content script (`relay-content.js`, matched only on that path) hands the page the request
  -- the purpose challenge, the credential ids and their salts -- and carries back
  `{credentialId, prf output, authenticatorData, clientDataJSON, signature}`. The worker
  accepts the answer only from the tab it opened, for that nonce, before the deadline, then
  closes the tab; it and the popup each check that the client data is a `webauthn.get` on
  the relay origin for this purpose's challenge, that the authenticator data names the
  relay rp id with UP and UV, and that the signature verifies under the entry's published
  key (`attestationPublicKey`, SPKI). An entry without that key is not used.
  - *Trust.* The relay page sees the PRF output, which unwraps the item's stanza for that
    passkey; the relay origin and the code it serves are therefore part of the trusted
    base for items wrapped to a phone passkey. The page is three static files from the
    repository, packaged by `packages/ragemanifest/relay.nix` (which refuses third-party
    code and requests of its own) and served with `default-src 'self'`,
    `frame-ancestors 'none'` and `Cache-Control: no-store`.
  - *Replay.* The challenge is the hash of one action, item, destination and fresh nonce
    (§0a), so an assertion relayed for one reveal cannot authorise another, and a forged
    answer fails the signature check. What binding cannot do is take back a PRF output the
    page already saw: like a captured passkey PRF output on any client, it opens that
    stanza until the item is re-wrapped (per-secret salts keep it to that one secret).
- **Native host (PIV, FIDO2 hmac-secret).** Browsers cannot reach a smart card, so
  `piv-x25519-v2`, `piv-p256` and `fido2-hmac` stanzas go to rageterm over native
  messaging (`rageterm install-native-host --browser chromium|firefox`; on Safari through
  the app's relay). rageterm returns the
  stanza's file key and a `tap` block; the browser refuses a reply that does not claim a
  touched, verified device. Each request carries a fresh challenge, and a reply may prove
  the touch with `tap.proof` (`glue/native-proof.js`, native-unwrap-proof-v1): a P-256
  PIV slot's ES256 signature over the challenge, the stanza, the action and the
  destination, or a FIDO2 credential's assertion with clientDataHash = SHA-256 of that
  message (UP flag required). The key must be the `attestationPublicKey` of the registry
  entry the stanza names (`attestationKeysForStanza`). When that recipient publishes one,
  a reply without a valid proof is refused; a recipient that publishes none (an X25519
  slot before `rageterm migrate-piv`, a FIDO2 credential before `rageterm attest-fido2`)
  yields a receipt recorded as unattested.
- **Paper recovery phrase.** A BIP39 phrase whose public key is a `Recovery` recipient.
  It is published only after the user types back three words, and the recovery screen
  opens items with it offline.

## 3. The four principles in this client

- **§0a action before tap.** Every popup ceremony shows the action, the item and the
  destination ("Reveal github", "to this screen" / "the clipboard" / the tab's host) before
  the authenticator is asked; a mock build says MOCK on the same line. Autofill from a page
  goes through the Ragewarden window (`tap.html`), which names the action, item,
  protection and destination -- for a login form in a frame, the frame's host and the page
  that embeds it -- and runs the tap outside the page. The WebAuthn challenge is
  SHA-256({action, destination, cipherId, origin, nonce}), so a tap cannot be replayed for
  another use.
- **§0b strict tap per use.** `unlock.js` runs exactly one ceremony per unlock, chosen from
  the item's stanzas; nothing is cached. Receipts carry the assertion and are verified with
  WebCrypto in the glue and again in the worker before plaintext leaves it.
- **§0c shortest plaintext.** Reveals and recovered values hide after 10 s; a copy is wiped
  from the clipboard after 30 s by a worker alarm (an offscreen document on Chromium), which
  survives the popup closing; fills type into the page and drop the value.
- **§0d server opacity.** Secrets travel inside the rage blob inside a Type-2 EncString.

## 4. Flows

- **Popup.** Opens to the vault when unlocked and to a local lock screen otherwise. Items
  for the active tab's site are listed first. The detail screen offers Autofill, Copy,
  Reveal and Show TOTP code (the code of `login.totp`, or of a seed stored as the item's
  secret).
- **Edit.** A rename, a new username or site and a folder move send only the changed
  fields (core merges them into the stored cipher) and need no tap; a new secret is
  re-wrapped to the current recipients and the old one is recorded in core's v2 history
  document, as is a deleted item. The generator buttons draw from core's generator. An
  item still in the pre-`wrap_salt` format is flagged and its Re-save re-wraps it.
- **Cards, identities, SSH keys.** Each field has its own input and a Protect toggle;
  the protected ones are sealed together in one rage blob (`wasm_save_item`) and each
  reveals or copies on its own tap, while descriptive fields read with no tap. Changing a
  protected value reads the current payload once and seals every protected field again;
  rotation and bulk re-wrap carry the whole payload (`*`). Writing a single secret over
  an item that protects several fields is refused with nothing changed.
- **Lock.** The session envelope is sealed under a random data key, itself sealed under
  PBKDF2-SHA256 (600k) of the master password. Unlock is local and works offline. While
  unlocked the data key sits in `chrome.storage.session` with an idle deadline; the Lock
  button, 15 minutes without use and (outside Safari, which has no idle API) the OS screen
  lock remove it.
- **Autofill from a page.** The content script runs in every frame and shows a chip on
  login fields of an origin with saved logins: one login goes straight to the Ragewarden
  window, several open a picker. The worker re-checks the chosen item against the frame's
  origin; the fill lands only on the origin it was authorized for.
- **KDF pin.** Sign-in remembers the account's KDF parameters per (server, email) in
  `chrome.storage.local`, kept across logout; a later login with weaker ones is refused.
  An account below core's minimum is offered an upgrade to 600 000 iterations and signs in
  only after the user accepts it.
- **Onboarding.** Sign-in asks the browser for access to the server's origin only. The
  protection wizard then runs: passkey, backup passkey, paper phrase -- the phrase is
  mandatory when the backup is skipped; skipping the passkey ends on a "Not protected
  yet" card.
- **Audit.** Every action records its outcome (ok, declined, failed) after it runs.

## 5. Permissions

`storage`, `activeTab`, `clipboardWrite`, `alarms`, `idle`, `nativeMessaging`, and
`offscreen` on Chromium. No install-time host permissions: `<all_urls>` is only optional,
and sign-in requests the server's origin. Content scripts match `<all_urls>` so the chip
can appear on any login page.

## 6. Testing

Tier 2 of [`../E2E.md`](../E2E.md) is `tests/playwright/`: Chromium with the extension, a
CDP virtual authenticator with PRF, a real Vaultwarden and the real rageterm. The specs and
the cross-client actions they cover are listed in
[`tests/playwright/tests/CROSS-CLIENT-ACTIONS.md`](tests/playwright/tests/CROSS-CLIENT-ACTIONS.md).
The content-script leg runs against a mock-tap build because the virtual authenticator
does not follow into the tap window. Firefox runs for real in `tests/firefox-bidi.mjs`
(WebDriver BiDi). Everything except Playwright runs in the NixOS config flake check
`ragemanifest`. What needs a person and real hardware -- a PRF passkey on each browser,
a PIV/FIDO2 key through rageterm, the Safari app on macOS -- is the release checklist in
[`tests/manual/firefox-checklist.md`](tests/manual/firefox-checklist.md).

## 7. Release

`.github/workflows/release.yml` builds the wasm, stamps the tag's version into the
manifest and attaches to the draft release: the chromium, firefox and safari zips, the
Chrome Web Store package (checked by `tests/check-store-package.mjs`, not uploaded) and the
AMO-signed `.xpi`. CI builds the Safari app unsigned on macOS.
