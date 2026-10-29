# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the repository's
Security tab and click "Report a vulnerability" (GitHub Security
Advisories). This is the only supported reporting channel.

Do not open a public issue for vulnerabilities. Reports submitted privately are
acknowledged within 72 hours and triaged within 7 days.

## Scope

In scope:

- Cryptographic primitives in `core/` (KDF derivation, age stanza wrapping, the
  Bitwarden Type-2 EncString helpers).
- The hardware-identity adapters in `rageterm/`, `ragedroid/`, `ragemanifest/`.
- Session storage and clipboard / autofill / IME delivery paths.
- The four non-negotiable principles (`DESIGN.md` §0a-d) -- any path that lets
  plaintext escape the action the user named in the prompt is in scope.
- The passkey relay page (`ragemanifest/relay/`, served at
  `https://ragewarden.decent.foundation/prf`) and the extension's handling of its answers.

Out of scope:

- Vulnerabilities in upstream Bitwarden / Vaultwarden that are not amplified by
  Ragewarden's wrapping. Report those upstream first.
- Issues that require an attacker to already have local code execution as the
  signed-in user (the threat model assumes the device boundary is uncompromised;
  see `DESIGN.md` §3).
- Anything already listed under "Residual risks" below; a report that only restates one
  of them will be closed as a duplicate.

## Residual risks

Ragewarden is pre-1.0 and has not had a third-party audit. These are true of the code at
HEAD, by design or because they concern data written by earlier versions:

| risk | effect | where |
|---|---|---|
| PRF stanzas written before the per-stanza `wrap_salt` | three-argument `webauthn-prf-v1` / `fido2-hmac` stanzas share one body key and a zero nonce across every secret of an authenticator; treat those secrets as exposed and rotate them. Every client flags them (`core::legacy_prf_wraps`) and re-wraps them (`core::rewrap`) | `DESIGN.md` §0e, `core/DESIGN.md` §2d |
| PRF stanzas written with the enrolment salt | written before per-secret salts: one captured PRF output opens every such stanza of that recipient. Current writes use a fresh salt per secret (`core::prf_requests_for`); re-wrapping the item replaces them | `DESIGN.md` §0e |
| software recipients | rageterm's software and OS-keyring identities and a paper phrase hold their key material on the device, not in hardware; `identity.age` is passphrase-encrypted unless enrolled with `--plaintext` or without a terminal | `DESIGN.md` §0d, `rageterm/README.md` |
| Android Keystore below API 35 | a key agreement cannot be bound to one prompt before Android 15, so an auth-bound Keystore key stays usable for 30 s after its prompt; from API 35 every use prompts | `ragedroid/docs/THREAT-MODEL.md` §6.1 |
| Android platform string copies | autofill, `commitText` and the clipboard take a `String`/`CharSequence` that the app cannot wipe; ragedroid zeroes its own buffers around them | `ragedroid/docs/THREAT-MODEL.md` §5.4 |
| unattested native-host unwraps | a YubiKey X25519 slot cannot sign, and a FIDO2 credential enrolled before key publishing has no published key, so the extension records their unwraps as unattested until `rageterm migrate-piv` / `rageterm attest-fido2` | `ragemanifest/DESIGN.md` §2 |

## Trusted parties

- **The passkey relay origin.** A phone passkey (rp id `ragewarden.decent.foundation`) is
  asked from the browser through `https://ragewarden.decent.foundation/prf`, and that page
  sees the PRF output it hands to the extension. Whoever controls that origin or the code
  it serves can therefore read the PRF outputs of phone-passkey reveals made through it,
  and with them open the stanzas they unwrap: the relay is part of the trusted base for
  items wrapped to a phone passkey, as the extension itself is for browser passkeys. The
  binding limits what a relay can do with an assertion: each challenge is the hash of one
  action, item, destination and nonce, the extension accepts an answer only from the tab
  it opened for that nonce and only with a signature under the passkey's published key,
  so an assertion cannot be replayed into another reveal. It cannot undo a PRF output
  already seen; per-secret salts keep that to the one secret, and re-wrapping the item
  retires it. `ragemanifest/DESIGN.md` §2 describes the flow.

Mock-hardware builds are fenced, not merely labelled: `rageterm`'s `mock-hardware` cargo
feature fails to compile in a release profile (`build.rs` + `compile_error!` in
`rageterm/src/hw.rs`), mock enrollments are never published to the cross-device recipient
registry, and `recipients list` re-derives the mock flag from `identities.json` rather than
trusting the stored label.

## Verification and the release checklist

CI and the NixOS-config checks run every hardware path against virtual devices: PIV and
FIDO2 on a virtual CanoKey (touch sensor included), passkeys on WebAuthn virtual
authenticators, Android on emulators. A physical device is the one thing they cannot
provide, so each of these is performed by a person before a release tag and recorded in
the release notes:

- [ ] `rageterm enroll-yubikey` against a physical YubiKey with a P-256 slot generated with
      `--touch-policy always` (rageterm reads the policy back and refuses any other), then
      `rageterm get` and confirm the key blinked and waited for the touch.
- [ ] `rageterm enroll-fido2` + one decrypt against a physical FIDO2 authenticator.
- [ ] ragemanifest: enroll a passkey with PRF on Chromium and on Firefox against a real
      authenticator (Touch ID / Windows Hello / USB key), then reveal and autofill.
- [ ] ragemanifest: reveal an item written by RageDroid to its phone passkey through the
      relay page (hybrid/QR from Chromium, and a passkey synced to Google Password
      Manager), and confirm the relay tab closes itself.
- [ ] ragedroid: NFC and USB-OTG YubiKey tap on a physical device; Credential Manager
      passkey on API 34+; StrongBox enrollment on a device that has one; a per-use Keystore
      prompt on API 35+.
- [ ] ragedroid: `FLAG_SECURE` visually confirmed -- screenshot and screen recording both
      refused on `MainActivity`, `AutofillAuthActivity`, `AutofillUnlockActivity` and
      `ImeAuthActivity`.
- [ ] Recovery: write down a paper identity, wipe the device, restore from it.
- [ ] Store submissions (Play, F-Droid, Chrome Web Store, AMO, App Store) and
      notarization / Authenticode signing.

## Audit prep

The 5-phase roadmap (`DESIGN.md` §7) calls for a third-party audit before the
phase-5 production release. The current candidate firms and their scope are
tracked privately; the audit report and remediations will be published with
the v1.0 release notes.

Reproducible builds are a release-blocking requirement; the verification is below.

## Reproducible-build verification

Three host-side scripts live under `scripts/repro/`:

- `verify-rageterm.sh` -- the stripped rageterm release binary for the host (or
  `--target=`) triple.
- `verify-ragemanifest-wasm.sh` -- `pkg/ragemanifest_bg.wasm` from
  `wasm-pack build --release`.
- `verify-ragedroid.sh` -- the unsigned standard and fdroid release APKs,
  normalized (entries sorted, timestamps zeroed, signing block dropped).

Each builds the committed tree (HEAD) in a fresh directory with the source path
remapped out of the artifact. With a row for the artifact in
`scripts/repro/EXPECTED_HASHES.txt` it compares the BLAKE3 hash against it;
without one, or with `--double-build`, it builds twice from two fresh trees at
different paths and requires the hashes to agree. `--update-expected` records a
hash only after such a double build and is run on the release tag, so the file
ships with the release for downstream rebuilders. `scripts/repro/test-lib.sh`
tests the comparison logic.
