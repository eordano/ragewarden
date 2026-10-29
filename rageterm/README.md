# rageterm

Terminal client for the [Ragewarden](../DESIGN.md) ecosystem: a CLI and a TUI over a
Bitwarden / Vaultwarden account, where every protected item is an age blob wrapped to your
hardware and software recipients. [`DESIGN.md`](DESIGN.md) has the design.

## Build

```sh
nix develop <nixos-config>#ragewarden   # pcsclite, dbus, udev, pkg-config
cargo build --release -p rageterm
cargo test -p rageterm
```

`nix build <nixos-config>#rageterm` builds the package. The NixOS checks
`ragewarden-e2e`, `ragewarden-canokey` and `ragewarden-canokey-touch` drive the release
binary against Vaultwarden and against a virtual CanoKey (PIV and FIDO2, touch sensor
included). `tests/clipboard.rs` and `tests/keyring.rs` need a display and a Secret Service,
so `cargo test` lists them as ignored; `ragewarden-e2e` runs them under Xvfb with
gnome-keyring (`-- --include-ignored`).

## Storage

Everything lives under `~/.config/ragewarden/` (`RAGEWARDEN_CONFIG_DIR` overrides it); the
directory is 0700 and every file is created 0600 (owner-only ACL on Windows):

| file | holds |
|---|---|
| `identity.age` | the software age identity, passphrase-encrypted (`--plaintext` or no terminal at enrolment keeps it bare; `protect-identity` encrypts it later) |
| `identity.pub` | its public key, so recipients can be listed without the passphrase |
| `identities.json` | enrolled PIV / FIDO2 / keyring / paper-recovery identities |
| `session.json` | bearer and refresh tokens and the user-key halves, from `login`; encrypted to `identity.age` when that is passphrase-protected. A 401 refreshes the bearer once, saves it and retries |
| `kdf-pins.json` | the KDF each (server, email) last logged in with; `login` refuses a weaker one from the server. Kept across `logout` |
| `audit.jsonl` | what was revealed, copied, filled or deleted, with the outcome (`audit` reads it) |
| `vault.json` | the last synced vault (server-encrypted Type-2 data) |
| `store.json` | items written with `set --offline`; uploaded by the next `login` |
| `recovery.age` | only after `recover --save`: the paper key, deliberately put on disk |

## Commands

The command names what happens to the plaintext; there is no `decrypt`.

| command | what it does |
|---|---|
| `register [--kdf argon2id]`, `login [--allow-weak-kdf]`, `logout`, `sync` | account and vault (`--password-stdin` reads the master password from stdin). A login under PBKDF2 below 100 000 iterations asks first (or needs `--allow-weak-kdf`), then upgrades the account to the default KDF |
| `set <name> [--type login --username U --url URL...] [--folder F] [--offline] [--generate]` | encrypt to the current recipient set and store on the server (or locally with `--offline`); `--generate` stores a new password instead of reading one |
| `set <name> --type card\|identity\|ssh-key [--protect F,...] [--with FIELD=VALUE...]` | a typed item: `--protect` names the fields sealed in the blob (default: number, SSN or private key), `--with` fills the others; several protected values are prompted for, or read from stdin as a JSON object |
| `set <name> --field F` | write one protected field of an existing item (CVV, notes, passphrase, ...), keeping its others |
| `generate [--length N] [--no-symbols] [--words N]` | print a random password, or a passphrase of N words |
| `list`, `folders` | names only, never contents; `[legacy-wrap]` marks items to re-wrap |
| `mv <name> [--folder F]`, `delete <name>`, `audit [--limit N]` | move between folders, delete (the last revision goes to the account's history document first), read the audit log |
| `get` / `pipe <name> [--field F]` | plaintext to stdout: the primary secret, or one protected field |
| `copy <name> [--clear N]` | plaintext to the clipboard, cleared after N seconds (30) if unchanged |
| `reveal <name>` | plaintext on the terminal until Enter; refused under tmux/screen/ssh without `--force` |
| `exec <name> -- cmd...` | plaintext on FD 3 of `cmd` (`--via-env` for `$RAGEWARDEN_SECRET`; `--clean-env [--keep VAR]` for a minimal environment) |
| `agent add <name>`, `fill <name> [--to ...]`, `totp <name>` | ssh-agent, autotype, TOTP code |
| `enroll-software-identity`, `protect-identity` | software identity |
| `enroll-yubikey --public-key ... [--slot 0x95] [--x25519 [--stanza-v2]]`, `enroll-fido2`, `enroll-keyring`, `enroll-recovery` | recipients (PIV slots are P-256 unless `--x25519`) |
| `migrate-piv [--slot S --public-key P256.pem]`, `attest-fido2 [id]` | move an X25519 slot's items to a P-256 slot; recover an older FIDO2 credential's public key (one touch) |
| `recipients list` / `remove <id>` | the recipient set |
| `reencrypt [<name> \| --all \| --legacy \| --only a,b]` (alias `rotate`), `restrict <name> --to ids` | re-wrap to the current set, or narrow it |
| `pass-import`, `install-native-host`, `native-host`, `recover [--save]` | migration, browser bridge, paper recovery |
| `--tui` | full-screen list: `/` search, `c` copy, `r` reveal, `a` ssh-agent, `x` exec |

## Consent

Every command that produces plaintext goes through one gate (`consent.rs`): a confirmation
read from `/dev/tty` (never stdin), or the TUI overlay's Enter. When the item's header names
an enrolled device, only that device can unwrap it, and a missing or declining device is an
error, never a fallback to a software key. `--yes` skips the prompt only on a vault with no
real device enrolled, and says `SOFTWARE-ONLY` every time. Device PINs come from the terminal
or, without one (the native host), from `pinentry`.

The gate governs rageterm invocations. A process that can read `identity.age` directly
gets nothing from a protected file without its passphrase; a bare one (`--plaintext`) is as
strong as the file's permissions.

## Protected items on the server

A protected item is a Bitwarden cipher with a Type-2-encrypted name, the notes marker
`"⛓ Protected with Ragewarden"` and one hidden field `rage:v1` holding the armored age blob.
Logins also carry their username and URIs so autofill can match them. The blob seals the
item's primary field as raw bytes, or, when other fields are protected too (a card's CVV,
an SSH key's passphrase), a field map (`core::protected`); a `rage:fields` field lists
them, and they are left out of the Type-2 layer. Rotation and restriction re-wrap the whole
payload, and `set` writes one field at a time while keeping the rest.

## Hardware

| identity | stanza | verified with |
|---|---|---|
| YubiKey PIV, P-256 slot (every YubiKey 4/5; the default) | `piv-p256` in age-plugin-yubikey's format | virtual CanoKey (`ragewarden-canokey`; `ragewarden-canokey-touch` for the native host's signed proof) |
| YubiKey PIV, X25519 slot (`--x25519`) | `piv-p256`, or `piv-x25519-v2` once enrolled with `--stanza-v2` | virtual CanoKey (`ragewarden-canokey`, touch policy read back via GET METADATA; `migrate-piv`) |
| FIDO2 hmac-secret | `fido2-hmac` | virtual CanoKey, including the UP flag, a PIN set after enrolment, and the native host's signed assertion |
| OS keyring | software X25519 in the keyring | gnome-keyring's Secret Service in `ragewarden-e2e` (`tests/keyring.rs`); consent is the y/N prompt |
| paper recovery | X25519 from 24 BIP39 words | NixOS e2e |

`--public-key` takes the slot's PEM (as `yubico-piv-tool -a generate` writes it) or its
point in hex; the curve comes from the key. The PIV card is chosen by the enrolled serial. The FIDO2 seed (with or without user
verification) is recorded at enrolment and used for every later wrap and unwrap. Hardware is
reached under one process-wide lock (`$XDG_RUNTIME_DIR/ragewarden.lock`; `--no-wait` fails
fast instead of waiting).

Browser unwraps through the native host are attested by the device: a P-256 slot signs
the browser's per-unwrap challenge, and a FIDO2 credential's assertion covers it (the
proof is the same touch). The registry publishes each device's key as
`attestationPublicKey`, and the browser checks the proof against the key of the
recipient the item's stanza names.

Migrations:

- An X25519 slot cannot sign, so `recipients list` marks it `[unattested, legacy X25519]`
  and its browser unwraps carry an unattested receipt. `rageterm migrate-piv` prints the
  steps; `migrate-piv --slot 0x9d --public-key p256.pem` enrols the P-256 slot, re-wraps
  every item that names the X25519 slot to it (a touch each), and retires the X25519
  recipient once all moved (re-run it to finish after an interruption).
- A FIDO2 credential enrolled before rageterm kept its public key is marked
  `[unattested: rageterm attest-fido2]`; `attest-fido2` recovers the key from the
  credential's own signatures with one touch and publishes it. `sync` republishes any
  device key the registry lost (for example, rewritten by an older client).
- `enroll-yubikey --x25519 --stanza-v2` publishes an X25519 slot with `stanzaVersion: 2`
  and wraps to it with the recipient-bound `piv-x25519-v2` stanza; turn it on once every
  client that opens your items reads v2, then `reencrypt --all`.
- `reencrypt --legacy` rewrites the items `list` marks `[legacy-wrap]`, whose FIDO2
  stanza predates the per-secret wrap salt.

The software stand-ins (`--features mock-hardware`, tests) cannot be compiled into a release
build, label themselves `[MOCK]`, and are never published to other devices or wrapped to
where stand-ins are disabled.

## Platforms

- Linux and macOS: as above. `fill` uses `xdotool`/`ydotool` on Linux, with the plaintext
  on stdin. On macOS rageterm types itself with CoreGraphics keyboard events, so every
  character (line breaks, trailing spaces) goes through and the plaintext stays in the
  process; it needs the terminal's Accessibility permission, and falls back to `cliclick`
  when that is missing and cliclick is installed.
- Windows: config files get an owner-only ACL; `fill` uses PowerShell `SendKeys` with the
  plaintext on stdin; `exec` hands the child an inherited pipe handle named by
  `$RAGEWARDEN_SECRET_HANDLE` (Windows has no FD 3); `agent add` talks to OpenSSH's
  `\\.\pipe\openssh-ssh-agent` (or `$SSH_AUTH_SOCK`); `install-native-host` writes the
  manifest under `%APPDATA%` (or `%ProgramData%` with `--system`) and registers it for Chrome,
  Chromium and Edge, or Firefox. `nix develop <nixos-config>#ragewarden-windows` then
  `cargo check -p rageterm` (or `build`) cross-compiles all of it from Linux.

## Live test

```sh
RAGEWARDEN_LIVE_TEST=1 RAGEWARDEN_LIVE_SERVER=https://vault.example.com \
RAGEWARDEN_LIVE_EMAIL=... RAGEWARDEN_LIVE_PASSWORD=... \
cargo test -p rageterm --test live_vault -- --ignored --nocapture
```
