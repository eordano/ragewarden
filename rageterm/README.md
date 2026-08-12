# rageterm

Terminal client for the [Ragewarden](../DESIGN.md) ecosystem.

This is the **phase-2** implementation: a working CLI + minimal TUI that round-trips
plaintext either through a real Bitwarden / Vaultwarden server (`register`, `login`,
`sync`) or -- for offline / not-yet-logged-in users -- through the same phase-1 local-file
store at `~/.config/ragewarden/store.json` (mode 0600). Hardware identities still come in
phase 3; for now, both paths use a single software age identity.

See [`DESIGN.md`](DESIGN.md) for the full target command surface; this README documents what
phase 2 actually ships.

---

## Build

```sh
cargo build --release -p rageterm
```

Or for development:

```sh
cargo build -p rageterm
cargo test  -p rageterm
```

The release binary lands at `target/release/rageterm`.

---

## Storage layout

```
~/.config/ragewarden/
+-- identity.age        # AGE-SECRET-KEY-1... (mode 0600)
+-- session.json        # bearer + refresh tokens, server URLs, user-key halves (mode 0600)
+-- vault.json          # cached server-side vault snapshot (mode 0600)
+-- store.json          # offline-only fallback store (mode 0600)
```

`session.json` is created by `rageterm login` and removed by `rageterm logout`. `vault.json`
is populated by `rageterm sync` (and incrementally maintained by `rageterm set` against the
synced vault). Both remain absent until the user has logged in. `store.json` is the phase-1
offline-only fallback -- used only when no `session.json` is present.

`store.json` shape:

```json
{
  "version": 1,
  "items": {
    "github": {
      "rage_blob": "-----BEGIN AGE ENCRYPTED FILE-----\n...\n-----END AGE ENCRYPTED FILE-----\n",
      "created": "2026-05-03T20:30:00Z",
      "modified": "2026-05-03T20:30:00Z"
    }
  }
}
```

The directory location can be overridden with `RAGEWARDEN_CONFIG_DIR=...` (used by tests; also
handy on machines without a standard `$HOME/.config`).

---

## Command surface (phase 2)

The command name names what happens to the plaintext. There is no `decrypt` subcommand.

| command | what it does |
|---|---|
| `rageterm register --server <URL> --email <addr> [--name <n>] [--kdf-iterations N]` | registers a new account; prompts for the master password (or reads from stdin if not a TTY) |
| `rageterm login --server <URL> --email <addr>` | logs in; saves `session.json` (bearer + user-key halves, mode 0600) |
| `rageterm logout` | clears `session.json` and `vault.json`; leaves `identity.age` and `store.json` intact |
| `rageterm sync` | pulls the full vault from the server; refreshes `vault.json` |
| `rageterm enroll-software-identity` | generates a fresh `age::x25519::Identity`, writes it to `~/.config/ragewarden/identity.age` (0600), prints the public key (recipient) |
| `rageterm set <name>` | reads plaintext from stdin, encrypts to the enrolled identity, then either POST/PUT to the server (if logged in) or upserts in `store.json` (if offline) |
| `rageterm list` | prints item names. If logged in: vault entries (`rage` vs `plain` per cipher). If offline: store-file names + timestamps |
| `rageterm get <name>` | decrypts and writes plaintext bytes to stdout (no trailing newline; pass `--newline` if you want one) |
| `rageterm copy <name>` | decrypts, sets the system clipboard, fork-detaches a child to clear it after 30s (configurable via `--clear N`; `--clear 0` disables) |
| `rageterm reveal <name>` | decrypts, prints to TTY, holds until you press Enter |
| `rageterm exec <name> -- <command> [args...]` | decrypts, spawns `<command>` with the plaintext on FD 3 (or `$RAGEWARDEN_SECRET` if `--via-env`), waits for it, propagates the exit code |
| `rageterm --tui` | minimal `ratatui` UI: list with arrow-key nav, `c` copy, `r` reveal |

Global flags:

- `-y` / `--yes` -- skip the y/N confirmation prompt. It can only skip a *prompt*. When a
  PIV or FIDO2 identity is enrolled the key material only leaves the device after a
  physical touch, which no flag in this process can supply, so `--yes` changes nothing on
  that path. On a software-only vault (no hardware identity, or only mock stand-ins) there
  is no touch and `--yes` removes the last gate; rageterm prints `SOFTWARE-ONLY ... no tap
  was performed` on stderr every time it does.

Every command that produces plaintext -- `get`, `pipe`, `copy`, `reveal`, `exec`, `totp`,
`agent add`, `fill`, `reencrypt`, `restrict` -- goes through the same gate. `get`/`pipe` used to be
ungated entirely; non-interactive scripts that relied on that now need `--yes`, or a
hardware identity (in which case the tap is the consent and nothing needs to be passed).
The prompt is read from `/dev/tty`, never from stdin, so piped input can no longer answer
it.

The `copy` auto-clear runs in a detached child. It only clears the clipboard if the
SHA-256 of the current clipboard contents still matches what we wrote -- so it never stomps
on something the user pasted in themselves between the copy and the timeout.

---

## End-to-end example

```sh
# 1. Enroll a software identity. (Phase 1 only -- phase 2 adds YubiKey / FIDO2 / passkey.)
$ rageterm enroll-software-identity
Enrolled software identity at /home/me/.config/ragewarden/identity.age
Public key (recipient): age1ps4sxz6689v0wuyqatc88zhx8rkzn5l8f5mp5yp3mz0z73rtgstsqhqfh6
This file holds your secret key. Back it up. Loss = unrecoverable items
(phase 1 has no recovery identity).

# 2. Store a secret. The trailing newline from `echo` is trimmed.
$ echo "hunter2-but-better" | rageterm set github
Stored `github` (new item).

# 3. List items (no plaintext).
$ rageterm list
github  modified 2026-05-03 23:47:25 UTC

# 4. Pipe to stdout for ad-hoc consumers.
$ rageterm get github --newline
hunter2-but-better

# 5. Copy to clipboard with a 30-second auto-clear.
$ rageterm --yes copy github
Copied `github` to clipboard. Auto-clearing in 30s.

# 6. Reveal on screen until you press Enter.
$ rageterm --yes reveal github
--- secret (press Enter to dismiss) ---
hunter2-but-better
----------------------------------------
<Enter>

# 7. Pass to a child process on FD 3 (default -- keeps it out of `ps`).
$ rageterm --yes exec github -- sh -c 'echo "from FD 3:"; cat <&3'
from FD 3:
hunter2-but-better

# 8. Or via $RAGEWARDEN_SECRET if the consumer expects an env var.
$ rageterm --yes exec github --via-env -- sh -c 'echo "from env: $RAGEWARDEN_SECRET"'
from env: hunter2-but-better

# 9. Interactive TUI: list, arrow-key nav, c=copy, r=reveal, q=quit.
$ rageterm --tui
```

---

## TUI (`--tui`)

Minimal phase-1 surface: a list of items, arrow-key nav (`j`/`k` also work), and:

- `c` -- copy the selected item to the clipboard
- `r` -- reveal the selected item on screen
- `q` / `Esc` -- quit

`c` and `r` open an overlay that names the action; **press Enter to confirm**. In phase 1
the Enter key *is* the "tap" -- phase 2 will replace it with the real hardware ceremony
(YubiKey blink, Touch ID, etc.). The action-named-before-confirm flow is identical to the
final design, only the consent gesture changes.

---

## Vault integration (phase 2)

Once you have a working Vaultwarden / Bitwarden server, the full flow is:

```sh
# 1. Register a fresh account (server policy permitting). Prompts for the master password.
$ rageterm register \
    --server https://vault.example.com \
    --email "rageterm-bench-$(date +%s)@example.com" \
    --name "rageterm bench"
New master password: ********
Confirm master password: ********
Registered `rageterm-bench-....@example.com` on https://vault.example.com.
Run `rageterm login --server https://vault.example.com --email rageterm-bench-....@example.com` to log in.

# 2. Log in. Saves the session + user-key halves to ~/.config/ragewarden/session.json (0600).
$ rageterm login \
    --server https://vault.example.com \
    --email rageterm-bench-....@example.com
Master password: ********
Logged in as ... (kdf iters 600000). Session saved at ~/.config/ragewarden/session.json.
Run `rageterm sync` to pull the vault.

# 3. Enroll a software identity for the rage layer (one-time per account).
$ rageterm enroll-software-identity
Enrolled software identity at ~/.config/ragewarden/identity.age
Public key (recipient): age1...

# 4. Encrypt a secret and POST it to the server.
$ echo "hunter2" | rageterm set bench-cipher
Stored `bench-cipher` on server.

# 5. Pull the vault to confirm the cipher landed.
$ rageterm sync
Synced. 1 cipher(s); 1 rage-protected. Cache at ~/.config/ragewarden/vault.json.

# 6. List items in the vault.
$ rageterm list
bench-cipher  rage

# 7. Round-trip: decrypt the rage layer back to plaintext.
$ rageterm get bench-cipher --newline
hunter2

# 8. Or copy / reveal / exec, all consume the same vault.
$ rageterm --yes copy bench-cipher
Copied `bench-cipher` to clipboard. Auto-clearing in 30s.

# 9. Log out -- drops the session + cached vault, keeps identity.age.
$ rageterm logout
Logged out (session + vault cache cleared). identity.age preserved.
```

### Storage of the rage blob in a Bitwarden cipher

Per [`DESIGN.md`](../DESIGN.md) §3, each rage-protected secret lives in a SecureNote cipher
(`type == 2`) with:

- `name` -- Type-2-encrypted display name (the `<name>` you passed to `rageterm set`).
- `notes` -- Type-2-encrypted marker `"⛓ Protected with Ragewarden"` so users opening the
  cipher in another Bitwarden client see something explanatory.
- `fields[]` -- exactly one HIDDEN field with name `rage:v1` and value the ASCII-armored
  age blob.

This format is forward-compatible with `rage:v2` and works on any Bitwarden / Vaultwarden
server.

### Offline / not-logged-in fallback

Without a `session.json` on disk, all `set`/`get`/`list`/`copy`/`reveal`/`exec` operate
against the phase-1 local-file store at `~/.config/ragewarden/store.json`. Useful for
demos or for users who haven't logged in yet. The fallback is a strict alternative -- local
items don't sync to the server when you log in later; `rageterm set` writes to whichever
backend is currently active.

### Threat-model note on `session.json`

`session.json` holds the bearer token and the bare 32-byte halves of the user symmetric
key (mode 0600, owner-only). The trade-off:

- with the keys at rest, every `rageterm set/get/list` works without re-prompting for the
  master password -- important for unattended scripts and the `exec` path;
- without the keys at rest, an attacker who reads `session.json` cannot decrypt cached
  ciphers -- but they can still talk to the server using the bearer token (one round-trip
  away from the same capability).

Phase 4 will optionally lock `session.json` behind the OS keyring / a biometric.

---

## Phase 3 -- hardware identities

Phase 3 adds four new identity kinds and the supporting `enroll-*` / `recipients` /
`reencrypt` / `restrict` commands. Each enrollment registers the recipient in the vault's `Ragewarden Recipients
(do not edit)` SecureNote (or a local `recipients.json` fallback when offline). `rageterm
set` then encrypts to *every* enrolled recipient by default, so a single secret unlocks
from any of them.

### New commands

| command | what it does |
|---|---|
| `rageterm enroll-yubikey --public-key <PEM\|HEX\|PATH> [--slot 0x95] [--label ...]` | prove the card holds the private key for the supplied X25519 public key (one live ECDH + touch), then register the pubkey as a recipient. rageterm never generates the key -- use `ykman piv keys generate --algorithm X25519 <slot> pub.pem` first |
| `rageterm enroll-fido2 [--rp ragewarden] [--label ...]` | MakeCredential with the hmac-secret extension, then one probe getAssertion to prove the extension works; registers the credential ID as a recipient |
| `rageterm enroll-keyring [--user ...] [--label ...]` | generate a software age identity, store it under the OS keyring's `ragewarden` service, register the pubkey as a recipient |
| `rageterm enroll-recovery [--label recovery]` | generate a 24-word BIP39 mnemonic, derive an X25519 keypair, write `recovery.age` (0600), register the pubkey as a recipient. Re-prompts the user to type the words back as a confirmation step |
| `rageterm recipients list` | list configured recipients (id, kind, created, label) |
| `rageterm recipients remove <id>` | remove a recipient (with confirmation prompt) |
| `rageterm reencrypt [<name>] [--all [--folder ...]] [--only a,b,...] [--allow-revoke]` | re-encrypt items to the *current* recipient set -- folds a newly-enrolled recipient into secrets stored before it existed. One item by name, or `--all`/`--only` for a batch. Refuses under `--yes` if it would drop a recipient this machine can't wrap to, unless `--allow-revoke` |
| `rageterm restrict <name> --to id1,id2,...` | re-wrap `<name>` to *only* the named recipients, dropping the rest -- the deliberate narrow/revoke. Refused unless at least one named recipient is openable on this machine |

Global flag: `--no-wait` skips the hardware-access lock at `$XDG_RUNTIME_DIR/ragewarden.lock`
and fails fast if another rageterm process is using the YubiKey / FIDO2 token.

### Hardware testing matrix

The phase-3 wire formats (`piv-p256`, `fido2-hmac`, `webauthn-prf-v1`,
`ragedroid-keystore-v1`) are fully implemented in `ragewarden-core::stanza_format` and
covered by KAT tests. The rageterm hardware paths split into:

| identity kind | software stand-in (tests only) | real hardware status |
|---|---|---|
| YubiKey PIV (`piv-p256`) | software X25519 stand-in | implemented over PC/SC (`piv_pcsc.rs`); needs a slot holding an **X25519** key, i.e. YubiKey firmware 5.7.0+. Untested against a device |
| FIDO2 hmac-secret (`fido2-hmac`) | HMAC-SHA256 over a stored key | implemented over CTAP2-HID (`fido_ctap.rs`, `ctap-hid-fido2`). Untested against a device |
| OS keyring (`scrypt`/X25519 via Keychain etc.) | runs against the real OS keyring | works on macOS Keychain, Linux Secret Service, Windows Credential Manager |
| Paper recovery (BIP39 24 words) | n/a (always software) | works |

The software stand-ins are **compiled out** of any build that is not a test binary or an
explicit `cargo build --features mock-hardware`, and `build.rs` + a `compile_error!` in
`hw.rs` make `cargo build --release --features mock-hardware` fail outright. Setting
`RAGEWARDEN_MOCK_HARDWARE=1` against a normal build prints a notice and is otherwise
ignored.

When the stand-ins *are* compiled in, a mock enrollment is marked as such everywhere it
can be seen: the label carries a `[MOCK -- NOT REAL HARDWARE]` prefix, `recipients list`
prints `[MOCK]` (re-derived from `identities.json`, so editing the label does not hide
it), a banner goes to stderr on every run, and the recipient is **never published to the
cross-device registry** -- otherwise other frontends would encrypt to a file on this disk
believing a YubiKey guards it.

Real-hardware test plan (manual; not in CI):

- **YubiKey 5C / 5 NFC over USB-A/USB-C**: PCSC + PIV applet, slot 0x95.
- **FIDO2-only key (e.g., Solo Token)**: CTAP2 over USB-HID, `getAssertion` with
  `hmac-secret`.
- **Apple Touch ID + macOS Keychain**: keyring identity round trip.
- **Windows Hello + Credential Manager**: keyring identity round trip on Windows 11.

### Phase-3 storage layout

```
~/.config/ragewarden/
+-- identity.age        # phase-1 fallback software identity (optional after phase 3)
+-- recovery.age        # phase-3 paper recovery secret (BIP39-derived, 0600)
+-- recipients.json     # offline fallback recipient list (when no session)
+-- identities.json     # local registry of enrolled hardware/keyring/recovery identities
+-- mock-piv-*.bin      # software stand-in PIV secrets (only in a `mock-hardware`/test build)
+-- mock-fido-*.bin     # software stand-in FIDO2 HMAC keys
+-- session.json        # vault session (phase 2)
+-- vault.json          # vault cache (phase 2)
+-- store.json          # phase-1 offline-only fallback store
```

When logged in, the recipient list lives in the vault's `Ragewarden Recipients (do not
edit)` SecureNote -- `recipients.json` is only used as the no-session fallback.

### Live integration test

```sh
RAGEWARDEN_LIVE_TEST=1 \
RAGEWARDEN_LIVE_SERVER=https://vault.example.com \
RAGEWARDEN_LIVE_EMAIL=...@example.com \
RAGEWARDEN_LIVE_PASSWORD=... \
cargo test -p rageterm --test live_vault -- --ignored --nocapture
```

Without those env vars the test skips with a clear message. The test exercises the
recovery identity round trip against a real Vaultwarden -- the keyring path is exercised
in-process by `keyring_id::tests`.

---

## What's still stubbed / out of scope after phase 3

Phase 4+:

- Verification of the PIV and FIDO2 paths against real devices (the code is written and
  unit-tested against scripted transports; nobody has run it with a YubiKey in hand).
- A `core/` stanza tag for P-256 PIV slots. `piv-p256` is X25519 on the wire, so
  pre-5.7.0 YubiKeys cannot be enrolled.
- Daemon mode. Phase 3 is still one-shot; clipboard auto-clear uses fork-and-detach.
- Encrypted local cache (`cache.db`). Phase 1's `store.json` is the entire cache.

`cargo test -p rageterm` covers, in addition to the phase-1/2 tests: hardware lock
acquire/release, mock-mode PIV stanza dispatch, mock-mode FIDO2 stanza dispatch, OS
keyring round-trip (skipped if the keyring backend is unavailable), enrolled-recovery
end-to-end via the assembled identity list, and BIP39 mnemonic <-> X25519 derivation
determinism.

---

## Platform notes

- **Unix**: `identity.age` and `store.json` are created mode `0600`; the parent directory is
  `0700`. `exec` passes the plaintext on FD 3 by default.
- **macOS**: same as Unix. The clipboard backend is `arboard` (NSPasteboard). `fill` drives
  `cliclick -f -`, which reads its command stream from stdin -- the plaintext is never a
  command-line argument, matching `xdotool --file -` / `ydotool --file -` on Linux. Because
  that stream is line-oriented (cliclick trims each line and splits on newlines), `fill`
  refuses a secret containing a line break or ending in whitespace rather than typing
  something other than what is stored; use `copy` or `exec` for those.
- **Windows**: builds, but `exec`'s default FD 3 path is unsupported -- pass `--via-env`
  instead. File ACLs aren't tightened in phase 1; documented gap.
