# Cross-client action surface

What a user can do in each client, and the cross-client invariants the Tier-2 specs check.
`cross-client-fuzz.spec.ts` picks its randomized actions from here.

## Actions

| Action | rageterm | ragemanifest (popup / glue) | ragedroid |
|---|---|---|---|
| register, login | ✓ CLI | ✓ onboarding (requests the server origin) | ✓ onboarding |
| logout | ✓ | ✓ drops the session envelope and keys | ✓ |
| sync | ✓ | implicit (`vault.fetch`, refresh ↻) | implicit |
| set / create | ✓ `set` (`--type login|card|identity|ssh-key`, `--protect`, `--field`) | ✓ Edit screen, typed item editors (`saveItem`) | ✓ typed items with per-field Protect |
| edit, rename | ✓ `set` over an existing item | ✓ `editCipher` | ✓ |
| rotate to current recipients | ✓ `reencrypt` (`restrict --to` for a subset) | ✓ `rotateCipher` | ✓ |
| delete | ✓ `delete` | ✓ Delete item (master-password confirm) | ✓ |
| folders | ✓ `folders`, `mv` | ✓ Folders screen | ✓ Move to folder |
| copy | ✓ `copy` | ✓ Copy (wiped after 30 s by the worker) | ✓ |
| reveal | ✓ `reveal` | ✓ Reveal (hides after 10 s) | ✓ |
| autofill | ✓ `fill --to` | ✓ popup Autofill, and the page chip -> Ragewarden window -> fill | ✓ autofill service + IME |
| TOTP | ✓ `totp` | ✓ Show TOTP code | ✓ |
| get / exec / agent add | ✓ | n/a | n/a |
| recipients list / remove | ✓ | ✓ Recipients screen | ✓ |
| enrol a passkey | n/a | ✓ wizard, Recipients screen | ✓ (F-Droid build: API 34+) |
| enrol PIV / FIDO2 | ✓ `enroll-yubikey`, `enroll-fido2` | n/a (opens them through rageterm's native host) | ✓ |
| paper recovery: create | ✓ `enroll-recovery` | ✓ wizard, Paper recovery screen (published after three words are confirmed) | ✓ |
| paper recovery: open an item | ✓ `recover` | ✓ Recover with a phrase / Test it now | ✓ |
| pass-import | ✓ | n/a | n/a |
| install-native-host | ✓ (Chromium, Firefox) | consumes it (`glue/native-host.js`) | n/a |

## Identities and stanzas

| Identity | Stanza tag | Enrolled by | Opened by |
|---|---|---|---|
| Software (X25519) | `X25519` | term, droid, manifest (wrapped under the passkey) | the holder of the secret |
| YubiKey PIV | `piv-p256` (P-256), `piv-x25519-v2` (X25519) | term, droid | term, droid, manifest via the native host |
| FIDO2 hmac-secret | `fido2-hmac` | term, droid | term, droid, manifest via the native host |
| WebAuthn-PRF passkey | `webauthn-prf-v1` | manifest, droid | manifest (its own; the phone's through the relay page), droid |
| Android Keystore | `ragedroid-keystore-v2` (v1 read) | droid | droid |
| Paper recovery (BIP39) | `X25519` | term, droid, manifest | any client with the typed phrase |

Every enrolment publishes a public-only entry to the `__ragedroid_recipients_v1__`
registry cipher, which every client encrypts to.

## Invariants

| ID | Invariant | Where it is checked |
|---|---|---|
| I1 Round-trip | A cipher written on X opens on Y with the same plaintext | fuzz rounds |
| I2 List parity | Both clients see every name written | fuzz rounds |
| I3 Server opacity | Every field on `/api/sync` is a Type-2 EncString, no plaintext | fuzz rounds; passkey-prf-roundtrip §0d |
| I4 Registry coherence | An enrolment is visible to the other client's next fetch | fuzz warm-up and rounds |
| I5 Redundancy | A cipher for {A, B} opens with either | fuzz `I5` |
| I6 Rotation | After rotate, the current set opens it | fuzz rounds |
| I7 Idempotent enrolment | Re-publishing an entry does not duplicate it | fuzz `I7` |
| I8 Removal | A removed recipient is no longer encrypted to | fuzz `I8` |
| I9 §0a | The action, item and destination are on screen before the authenticator is asked | popup-ux `popup ceremonies…`; autofill-content-script (tap window) |
| I10 §0b | One tap per use; a second use is a second tap | passkey-prf-roundtrip |
| I11 §0c | No plaintext at rest after a reveal; values hide | passkey-prf-roundtrip; popup-ux recovery |
| I12 §0d | The server holds only opaque blobs | I3 |
| I13 Recovery | A phrase enrolled on one client opens items on another | fuzz `I13`; rageterm e2e |
| I14 Cross-device PRF | A phone passkey (rp id `ragewarden.decent.foundation`) opens, in the browser, an item the phone wrapped to it: through the relay page, with the assertion bound to that reveal and verified against the passkey's published key | prf-relay (the real relay page, a virtual authenticator on its origin); worker checks in unit `prf-relay`; real phone: manual release check |

## Fuzzer

Each round is a random mix of: rageterm writes a note or a login; the popup writes through
`wasm_create_cipher` to the registry's recipients; rageterm re-encrypts an earlier item
(`reencrypt --allow-revoke`, since a browser passkey stanza can only be written by the
browser). After every round I1, I2, I3, I4 and I6 are asserted.
