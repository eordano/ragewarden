# Cross-client action surface

What a user can do across the ecosystem, where it originates, and which
cross-client invariants each action stresses. Used by
`cross-client-fuzz.spec.ts` to pick the actions to randomize.

## Auth + sync

| Action | rageterm | ragemanifest | ragedroid | Cross-client invariant |
|---|---|---|---|---|
| `register` | ✓ (CLI) | ✓ (popup onboarding) | ✓ (onboarding screen) | After register on X, login on Y produces a working session |
| `login` | ✓ | ✓ | ✓ | Same |
| `logout` | ✓ | ✓ | ✓ | Server bearer revoked; cached vault cleared |
| `sync` | ✓ | implicit (`vault.fetch`) | implicit (repository) | After sync, server-stored ciphers visible to all clients |

## Identity enrollment

| Identity kind | Stanza tag | Enrolled by | Decryptable on |
|---|---|---|---|
| Software passphrase | `X25519` | term, droid, manifest (recovery only) | all (with the secret) |
| YubiKey PIV | `piv-p256` | term, droid | term, droid |
| FIDO2 hmac-secret | `fido2-hmac` | term, droid | term, droid |
| WebAuthn-PRF passkey | `webauthn-prf-v1` | manifest, droid (API 34+) | manifest, droid |
| Android Keystore | `ragedroid-keystore-v1` | droid only | droid only |
| OS keyring | `X25519` (software-shaped) | term | term |
| Paper recovery (BIP39) | `X25519` (software-shaped) | term, droid | any client with the typed phrase |

After enrollment, two writes happen:
1. **Local recipient list** -- the legacy `Ragewarden Recipients (do not edit)`
   secure note. Holds the full Recipient struct including handles.
2. **Cross-device registry** -- the `__ragedroid_recipients_v1__` cipher.
   Holds a public-only WireEntry shape that other devices can encrypt to.

## Cipher CRUD

| Action | rageterm | manifest | droid | Notes |
|---|---|---|---|---|
| `set <name>` | ✓ (`set <name>`, `--type=login`, `--from-stdin`) | (via design's EditItem screen -> wasm_create_cipher) | (EditItemScreen -> BitwardenVaultRepository.update) | Encrypts to the active recipient set (local + cross-device, with FIDO2/PRF kinds filtered for non-owning devices) |
| `update` | (via `set` overwrite) | ditto | ditto | |
| `delete` | ✓ (`delete <name> [--yes]`) | ✓ (`RagewardenVault.deleteCipher` -> `wasm_delete_cipher`) | ✓ (`RageNative.deleteCipher` -> `BitwardenVaultRepository`) | Wire-level wired everywhere; popup UI surface via `vault.deleteCipher`, droid via item-detail menu |
| `rotate <name>` | ✓ (`--to <ids>` for subset, omit for full) | ✓ (`RagewardenVault.rotateCipher` -> `editCipher`) | ✓ (ItemDetailScreen `Rotate to current recipients` -> `backend.update`) | Re-encrypts to the current active set |
<!-- 2026-05-17 audit: rageterm delete confirmed in rageterm/src/commands.rs cmd_delete (line 1277) + main.rs (line 504); 12-delete.txt asset shows the live e2e -->
<!-- 2026-05-17 audit: popup delete/rotate exposed in ext/glue/init.js (lines 22-23) and ext/glue/vault.js (rotateCipher line 554, deleteCipher line 567); cross-client-fuzz.spec.ts lifecycle test exercises both -->
<!-- 2026-05-17 audit: droid delete in RageNative.kt:147 + BitwardenVaultRepository.kt:537; rotate in ItemDetailScreen.kt (SheetActions "Rotate to current recipients" -> onRotate -> backend.update) -->
<!-- 2026-05-16 audit: droid delete UI surface wired: ItemDetailScreen.kt SheetActions "Delete item" row -> DeleteConfirmSheet (type-to-confirm for rage items) -> MasterPasswordConfirm gate -> onDelete -> BitwardenVaultRepository.deleteCipher (audit-logged via AuditAction.Delete, HistoryStore.clearItem, snapshot pruned) -->


## Cipher consume

| Action | term | manifest | droid |
|---|---|---|---|
| `get` (stdout) | ✓ (`get`, `pipe`) | n/a | n/a |
| `copy` (clipboard) | ✓ (`copy`, top-level `-c`) | RagewardenVault.copyPassword | TapAction.Copy |
| `reveal` | ✓ (refused in tmux/screen/SSH unless `--force`) | RagewardenVault.revealPassword | TapAction.Reveal |
| `autofill` | ✓ (`fill --to ...`) | content-script chip + prompt | RagewardenAutofillService + IME |
| `exec` | ✓ | n/a | n/a |
| `agent add` | ✓ | n/a | n/a |
| TOTP | ✓ (`totp`) | wasm_totp_generate | TotpCard |

## Recipient management

| Action | term | manifest | droid |
|---|---|---|---|
| `recipients list` | ✓ | ✓ (`RagewardenVault.listRecipients` -> `wasm_fetch_registry`; popup UI surface still partial) | ✓ (`RecipientsScreen.kt` -- registry-backed list with per-row Remove) |
| `recipients remove` | ✓ (also unpublishes from registry) | ✓ (`RagewardenVault.removeRecipient` -> `wasm_unpublish_from_registry`) | ✓ (`RecipientsScreen.kt` remove action -- unpublishes + drops local material) |
<!-- 2026-05-17 audit: popup glue exposes listRecipients/removeRecipient in ext/glue/init.js:30-31 + ext/glue/vault.js:679/688; cross-client-fuzz lifecycle test invokes both; popup UI consumer not yet in ext/popup (caveat retained as 'UI surface still partial') -->
<!-- 2026-05-17 audit: droid RecipientsScreen.kt registered in RageApp.kt:448 (Stage.RecipientsList); lists union of registry entries with per-row Remove -->


## Recovery

| Action | term | manifest | droid |
|---|---|---|---|
| `enroll-recovery` | ✓ | ✓ (`RagewardenVault.enrollRecovery` -> returns 24-word phrase; popup never stores it) | ✓ (`PaperRecoveryWizardScreen.kt`, identities/RecoveryEnrollment.kt) |
| `recover` (re-derive from typed BIP39) | ✓ (`recover [--save]`) | ✓ (`RagewardenVault.recoverFromPhrase(cipherId, phrase)` -- one-shot, never stored) | ✓ (`RecoverFromPhraseScreen.kt` -- one-shot decrypt, plaintext auto-clears after 8s) |
<!-- 2026-05-17 audit: popup enrollRecovery/recoverFromPhrase wired in ext/glue/vault.js:620 + :659, init.js:27/29; cross-client-fuzz test 'I13' exercises recoverFromPhrase end-to-end -->
<!-- 2026-05-17 audit: droid screens PaperRecoveryWizardScreen.kt + RecoverFromPhraseScreen.kt registered in RageApp.kt:444/455 -->


## Cross-frontend interop helpers

| Action | term | manifest | droid |
|---|---|---|---|
| `install-native-host` | ✓ (Chromium / Firefox / Safari paths) | ext/glue/native-host.js consumes it | n/a |
| `pass-import` | ✓ | n/a | n/a |

---

## Cross-client invariants

The fuzzer asserts these after every randomized action:

| ID | Invariant | How tested |
|---|---|---|
| **I1** Round-trip | Cipher created on X is decryptable on Y if Y owns a compatible identity, with the same plaintext bytes | Write on rageterm, read on popup; assert plaintext equality |
| **I2** List parity | All clients agree on the set of cipher names (rage and plain) | `rageterm list --json` ∩ popup snapshot |
| **I3** Server opaque | Every `rage:v1` field on the server is a Type-2 EncString; never plaintext | Direct `/api/sync` fetch, scan all field values |
| **I4** Registry coherence | After enroll, registry document on Vaultwarden carries an entry; visible on next fetch by other clients | `/api/sync` shows the marker cipher |
| **I5** Multi-recipient redundancy | Cipher encrypted to {A,B,C} decrypts on any client owning A, B, or C | Run reveal on each owning client |
| **I6** Rotation | Post-rotate, only the new recipient set decrypts; old recipients stop working if rotated out | Rotate then test reveal on rotated-out client |
| **I7** Enrollment idempotency | Re-enrolling the same hardware (same serial/credential) replaces (not duplicates) the registry entry | Enroll twice, count entries |
| **I8** Removal symmetry | Remove recipient on X -> other clients stop encrypting to it on next set | Remove on term, write on manifest, term decrypts but rotated-out one fails |
| **I9** §0a action-named | Tap prompts name the destination before the credential ceremony | Existing Tier-2 spec covers manifest; droid has no automated coverage yet (manual); CLI prompts say it |
| **I10** §0b strict tap | One tap per use; counters bump in lockstep | Existing Tier-2 spec |
| **I11** §0c plaintext lifetime | Plaintext not retained after deliver | Existing Tier-2 spec |
| **I12** §0d server stores nothing usable | Server JSON contains only Type-2 markers + opaque blobs | I3 + Tier-2 §0d |
| **I13** Recovery | Phrase enrolled on X, `recover --save` on Y, then Y can decrypt every cipher targeting that recovery recipient | (not yet automated) |
| **I14** Cross-device PRF | Passkey enrolled in browser -> ragedroid Credential Manager unlocks the same `webauthn-prf-v1` stanza | (manual; release-gate) |

## Fuzzer status

`cross-client-fuzz.spec.ts` covers, per round, a randomized mix of:
- **rageterm-write secure-note** + read-back on both clients
- **rageterm-write login** (cipher_type=1) + read-back on both
- **popup-write** via `wasm_create_cipher` against the registry's
  Software entries + read-back on both
- **rotate** (rageterm side) of any previously-written cipher; both
  clients still decrypt to the original plaintext

Invariants asserted on every round:
- **I1 round-trip** ✓ (both clients decrypt to original plaintext)
- **I2 list parity** ✓ (popup snapshot includes every name written)
- **I3 server opacity** ✓ (every field is Type-2-wrapped, no plaintext leaks)
- **I4 registry coherence** ✓ (popup-write needs registry to include rageterm,
  which only happens if rageterm has published -- caught early as a fuzzer
  bug surface; warmup `sync` enforces it)
- **I6 rotation correctness** ✓ (post-rotate decrypt = original plaintext)

Showcase run: 100 rounds in 1.9 min, 74 unique ciphers + 26 rotates,
0 failures (seed=8070).

## Standalone tests (single-cipher, focused invariant)

In addition to the per-round fuzz mix:

- **I5 multi-recipient redundancy** ✓ -- `cross-client fuzz › I5`:
  popup writes a cipher via `wasm_create_cipher_with_prf` carrying
  both a Software stanza AND a webauthn-prf-v1 stanza. Baseline:
  popup decrypts via the Software path. Then the test wipes the
  local `ragewarden:software-identity` from chrome.storage and
  reboots the popup. The popup falls through to the PRF stanza and
  still decrypts. Confirms `wasm_decrypt_cipher_field_with_secrets`
  tries every identity against every stanza.
- **I7 idempotency** ✓ -- `cross-client fuzz › I7` re-publishes every
  registry entry the popup wrote at bootstrap; assert `entries.length`
  doesn't grow.
- **I8 removal symmetry** ✓ -- `cross-client fuzz › I8` writes a baseline
  cipher (decrypts on both), then the popup calls
  `wasm_unpublish_from_registry` on its own Software entry; rageterm
  syncs and writes another cipher. The new cipher decrypts on rageterm
  (its own identity is always in the encrypt set) but throws
  "no supplied identity matched any stanza" on the popup. Confirms the
  removal actually flows through to the encrypt-side recipient set.

## Wiring needed for the remaining invariants

| ID | What's needed |
|---|---|
| **I9** §0a action-named-before-tap | Coupled to the design layer's prompt-sheet rendering. Already covered by `passkey-prf-roundtrip.spec.ts` which hooks the design's React tree. Lifting into the fuzzer would require importing those hooks. Not blocking. |
| **I12** §0d server stores nothing | Same assertion as I3 -- every cipher field on `/api/sync` is a Type-2 EncString and contains no plaintext substring. Already per-round in the main fuzz loop. |
| **I14** Cross-device PRF | Hardware. Release-gate manual check (real Touch ID + real Android Credential Manager unlocking the same `webauthn-prf-v1` stanza via iCloud Keychain or paired-device flow). |

---

## Per-client action symmetry -- gaps

The directive "every client can do every action" is a separate axis from
the invariants above. Today the popup is read/decrypt-mostly; several
"device admin" actions only exist on rageterm (or on rageterm + ragedroid).
Below: the actions, with the current home and the missing client(s).

| Action | rageterm | manifest | ragedroid |
|---|---|---|---|
| `register` | ✓ (CLI; non-interactive line-by-line stdin) | ✓ (popup onboarding) | ✓ (onboarding screen) |
| `login` / `logout` / `sync` | ✓ | ✓ | ✓ |
| `enroll-recovery` (generate paper phrase) | ✓ | ✓ (`RagewardenVault.enrollRecovery()`) | ✓ |
| `recover` (re-derive from typed phrase) | ✓ (`recover [--save]`) | ✓ (`RagewardenVault.recoverFromPhrase(cipherId, phrase)`) | ✓ (`RecoverFromPhraseScreen.kt`) |
<!-- 2026-05-17 audit: droid RecoverFromPhraseScreen.kt is implemented and wired (RageApp.kt:444); cell flipped from gap -> ✓ -->

| `set` / `setCipher` | ✓ | ✓ (`RagewardenVault.setCipher`) | ✓ |
| `editCipher` / update | ✓ (via `set` overwrite) | ✓ (`RagewardenVault.editCipher`) | ✓ |
| `rotate` | ✓ | ✓ (`RagewardenVault.rotateCipher` -- decrypt + editCipher) | ✓ (ItemDetailScreen "Rotate to current recipients" sheet action -> `backend.update`) |
<!-- 2026-05-17 audit: droid rotate UI lives in ItemDetailScreen.kt (TapMode.Rotating + SheetActions onRotate -> backend.update); cell flipped from gap -> ✓ -->

| `delete` | ✓ (`delete <name> [--yes]`) | ✓ (`RagewardenVault.deleteCipher`) | ✓ |
| `folders list/create/rename/remove` | ✓ (`folders` subcommand) | ✓ (`RagewardenVault.{create,rename,delete}Folder`) | partial |
| `recipients list / remove` | ✓ | ✓ (`RagewardenVault.{listRecipients,removeRecipient}`) | ✓ (`RecipientsScreen.kt` -- list + per-row remove) |
<!-- 2026-05-17 audit: droid RecipientsScreen.kt is implemented and wired (RageApp.kt:448); cell flipped from gap -> ✓ -->

| `pass-import` | ✓ | n/a (browsers can't read pass(1) GPG store) | n/a |
| `set --type=login` | ✓ | partial -- `wasm_create_cipher` builds SecureNote shape; needs a cipher_type param | gap |
| `agent add` (ssh-agent) | ✓ | n/a | n/a |
| `fill --to <window>` (autotype) | ✓ (xdotool / ydotool / cliclick / SendInput) | content-script chip + InputEvents | autofill service + IME |

Remaining: ragedroid Compose UI for rotate, recover-from-phrase, and
recipients list/remove are now implemented (ItemDetailScreen rotate sheet,
RecoverFromPhraseScreen, RecipientsScreen). Action surface is identical at
the JNI layer (core::sync exposes everything). Outstanding popup gap: a
dedicated UI surface for `listRecipients`/`removeRecipient` (the glue API
exists; no popup screen consumes it yet -- exercised only through fuzz tests).
<!-- 2026-05-17 audit: previous "Remaining: ..." sentence claimed three droid gaps; all three are now wired. Rewritten to reflect actual outstanding gap (popup recipients UI). -->

