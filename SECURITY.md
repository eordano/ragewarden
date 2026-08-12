# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the repository's
**Security** tab and click **"Report a vulnerability"** (GitHub Security
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

Out of scope:

- Vulnerabilities in upstream Bitwarden / Vaultwarden that are not amplified by
  Ragewarden's wrapping. Report those upstream first.
- Issues that require an attacker to already have local code execution as the
  signed-in user (the threat model assumes the device boundary is uncompromised;
  see `DESIGN.md` §3).
- Anything already listed under "Known gaps" below. Those are tracked, not news;
  a report that only restates one of them will be closed as a duplicate.

## Known gaps -- do not deploy this expecting the full threat model

Ragewarden is pre-1.0 and has **not** been audited. `DESIGN.md` §0e is the canonical,
maintained list of where the shipped code falls short of the four design principles;
read it before relying on any property in §0a-d. The security-relevant entries as of
this writing:

| gap | effect | where |
|---|---|---|
| PRF salt is per-recipient, not per-secret | one captured `prf_output` unwraps every `webauthn-prf-v1` / `fido2-hmac` stanza for that recipient, with no further taps -- the "no bulk siphon" row of the threat table is not cryptographically enforced | `core/src/stanza_format.rs`, `core/src/lib.rs` |
| pre-`wrap_salt` stanzas | three-argument PRF stanzas written before the per-stanza `wrap_salt` landed share one body key and a zero nonce across every secret; treat any such secret as compromised and rotate it. No frontend surfaces the `*_is_legacy_wrap` flag yet | `core/DESIGN.md` §2d |
| rageterm consent gate is vault-global | with a real hardware identity enrolled, `get` / `copy` announce "this needs a hardware tap" and then return without any gate; an item that also carries a software X25519 stanza unwraps from disk unattended | `rageterm/src/consent.rs`, `rageterm/src/commands.rs` |
| PIV touch policy unverifiable | a slot generated without `--touch-policy always` completes ECDH with no touch while the UI claims a tap happened | `rageterm/src/piv.rs`, `rageterm/src/piv_apdu.rs` |
| `sync::set_folder` skips `require_secure()` | public API that takes a raw `server_url: &str` and sends the bearer token without checking the scheme; no in-tree callers | `core/src/sync.rs` |
| KDF floor is 5 000 iterations | matches upstream Bitwarden's `PBKDF2_MIN_ITERATIONS` so legacy vaults still open, but a hostile server can still push a client well below the 600 000 default before the master-password hash is transmitted | `core/src/bitwarden.rs`, `core/src/sync.rs` |
| unwiped plaintext copies | `arboard` keeps a non-zeroizing clipboard string in its owner thread; `core::decrypt` / `aead_decrypt_filekey` / `decrypt_type2` keep non-zeroized intermediates | `rageterm/src/output.rs`, `core/src/lib.rs`, `core/src/bitwarden.rs` |
| clipboard-clear helper argv | `copy` passes an unsalted hex SHA-256 of the plaintext as `argv[3]` of a detached helper; world-readable in `/proc/<pid>/cmdline` for the clear window and offline-guessable for a low-entropy secret | `rageterm/src/output.rs` |
| no token refresh | a 401 forces a full re-login in every frontend | all frontends |
| ragedroid session key is not `setUserAuthenticationRequired` | the session blob is AES-256-GCM under an AndroidKeyStore key, but that key is usable whenever the app runs; the app lock does not zeroise in-memory key material | `ragedroid/app/.../data/SessionStore.kt`, `ragedroid/docs/THREAT-MODEL.md` §10 |

Mock-hardware builds are fenced, not merely labelled: `rageterm`'s `mock-hardware` cargo
feature fails to compile in a release profile (`build.rs` + `compile_error!` in
`rageterm/src/hw.rs`), mock enrollments are never published to the cross-device recipient
registry, and `recipients list` re-derives the mock flag from `identities.json` rather than
trusting the stored label.

## Release-gate checklist -- ceremonies that need a human

CI cannot sign these off. Each must be performed by a person on real hardware before a
release tag, and the result recorded in the release notes:

- [ ] `rageterm enroll-yubikey` against a physical YubiKey 5.7.0+ with
      `--touch-policy always`, then `rageterm get` and confirm the device actually
      demanded a touch (rageterm cannot verify this for you -- see "Known gaps").
- [ ] `rageterm enroll-fido2` + one decrypt against a physical FIDO2 authenticator.
- [ ] ragemanifest: enroll a passkey with PRF on Chromium and on Firefox against a real
      authenticator (Touch ID / Windows Hello / USB key), then reveal and autofill.
- [ ] ragedroid: NFC and USB-OTG YubiKey tap on a physical device; Credential Manager
      passkey on API 34+; StrongBox enrollment on a device that has one.
- [ ] ragedroid: `FLAG_SECURE` visually confirmed -- screenshot and screen recording both
      refused on `MainActivity` and `AutofillAuthActivity`.
- [ ] Recovery: write down a paper identity, wipe the device, restore from it.
- [ ] Store submissions (Play, F-Droid, Chrome Web Store, AMO, App Store) and
      notarization / Authenticode signing.

## Audit prep

The 5-phase roadmap (`DESIGN.md` §7) calls for a third-party audit before the
phase-5 production release. The current candidate firms and their scope are
tracked privately; the audit report and remediations will be published with
the v1.0 release notes.

Reproducible builds are a release-blocking requirement; see `DESIGN.md` §5
(Reproducibility) for the exact toolchain pinning.

## Reproducible-build verification

Three host-side scripts live under `scripts/repro/`:

- `verify-rageterm.sh` -- builds rageterm with the workspace-pinned release
  profile and compares the binary's b3sum against the expected hash for the
  current host triple.
- `verify-ragemanifest-wasm.sh` -- runs `wasm-pack build --release` and
  compares the resulting `pkg/ragemanifest_bg.wasm` bytecode hash.
- `verify-ragedroid.sh` -- runs `:app:assembleStandardRelease` and compares
  the APK hash. The hash includes the v2/v3 signature block today; the
  release CI job feeds in a known signing config (or
  `-PunsignedBuild=true`) so the resulting APK is byte-stable.

Expected hashes live in `scripts/repro/EXPECTED_HASHES.txt`. Each release-
candidate tag re-runs `--update-expected` from a clean CI runner so the file
ships with the release as a transparency artifact. Each script supports
`--dry-run` (prints the plan, exits 0) and `--update-expected` (re-emits the
hash table). `--help` documents the exact build invocation that produced the
recorded hash.
