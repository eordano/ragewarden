# RageManifest -- browser extension

The Ragewarden extension for Chromium-family browsers, Firefox and Safari: a Bitwarden client
in which every credential is also wrapped to your hardware recipients, so opening one takes a
tap of your passkey or security key. Design and principles: [`DESIGN.md`](DESIGN.md) and the
ecosystem [`../DESIGN.md`](../DESIGN.md).

## Layout

- `src/` -- the Rust crate. `src/wasm/` is the wasm-bindgen surface over ragewarden-core
  (login, sync, cipher CRUD, registry, decrypt with WebAuthn-PRF / software / native-host
  identities, TOTP, recovery); `src/decide.rs`, `src/snapshot.rs`, `src/reveal.rs` and
  `src/prf_identity.rs` hold the decisions it makes, as host-tested Rust.
- `ext/popup/` -- the toolbar popup: plain ES modules (`app.js` screens, `ui.js` widgets),
  styled by `popup.css` and the design tokens copied from `../design/`.
- `ext/glue/` -- the bridge between the popup and the wasm: session envelope and lock
  (`storage.js`), vault operations (`vault.js`), the hardware-tap ceremonies and receipts
  (`hardware-tap.js`, `passkey.js`, `assertion.js`, `receipt-check.js`), the native-host
  bridge to rageterm (`native-host.js`, `native-proof.js`), onboarding, audit, clipboard.
- `ext/background.js` -- the worker: origin lookups, the tap-window broker, receipt checks
  before any plaintext leaves it, auto-lock alarms, the clipboard wipe.
- `ext/content.js` -- the in-page chip on login forms (all frames).
- `ext/tap.html`, `ext/tap.js` -- the Ragewarden window that names the action, item and
  destination and runs the tap for page autofill.
- `ext/manifest.json`, `ext/manifests/{firefox,safari}.json` -- the base manifest and the
  per-browser overrides `build.mjs` applies.
- `safari-host-app/` -- the macOS host app and `build.sh`, which turns `dist/safari` into
  `Ragewarden.app`.

## Build

Enter the dev shell first: `nix develop` here, or `nix develop .#ragewarden` from the
NixOS config repository. It provides cargo with the wasm32 target, wasm-pack, wasm-bindgen
(matching the `=0.2.127` pin), binaryen, node, web-ext, Firefox, the Playwright browsers,
Vaultwarden and util-linux.

```sh
wasm-pack build --target web .          # -> pkg/
node build.mjs chromium                 # -> dist/chromium/  (also firefox, safari)
node build.mjs chromium --zip           # release zip; refused with any test flag
```

`build.mjs` copies the popup, glue, wasm and tap window into `dist/<browser>/`, emits the
manifest for that browser and checks the result: no mock-tap backend, no test hooks, no
install-time host permissions, no design-prototype code in a release build. Flags:

- `--with-wasm` runs wasm-pack first; `--watch` rebuilds on changes.
- `--test-hooks` exposes the test globals and grants `<all_urls>` at install so automation
  never meets a permission prompt.
- `--allow-mock-tap` (with `RAGEWARDEN_UNSAFE_MOCK_TAP=1`), `--force-mock-tap` and `--vm`
  produce builds that fabricate taps; they cannot be zipped.
- `RAGEWARDEN_EXT_VERSION=1.2.3` stamps the manifest version (the release workflow sets it
  from the tag).

The Nix packages are `nix build .#ragemanifest-wasm` and `.#ragemanifest` (chromium and
firefox zips plus the unsigned `.xpi`).

## Install

- **Chromium**: `chrome://extensions` -> Developer mode -> Load unpacked -> `dist/chromium`.
- **Firefox**: `about:debugging#/runtime/this-firefox` -> Load Temporary Add-on ->
  `dist/firefox/manifest.json`. Signed builds come from the release workflow (AMO, unlisted).
- **Safari**: on macOS, `node build.mjs safari && safari-host-app/build.sh`, then open the
  printed `Ragewarden.app` and enable the extension in Safari -> Settings -> Extensions
  (Develop -> Allow Unsigned Extensions for an unsigned build). `SAFARI_TEAM_ID` signs it.

Sign-in asks the browser for access to your server's origin only; nothing else is granted.
Hardware PIV and FIDO2 keys work through rageterm's native-messaging host
(`rageterm install-native-host --browser chromium|firefox`; Safari reaches it through the
app, which bundles rageterm when built with `RAGETERM_BIN`); passkeys work in the browser
directly.

## Tests

| Command | What it covers |
|---|---|
| `cargo test -p ragemanifest` | the crate's host-side logic |
| `pnpm run test:unit` | glue modules under node with a fake extension API (lock, receipts, worker release gate, origin matching, audit, recovery-word picking, host permission, native touch proofs) |
| `node tests/smoke-firefox.mjs --static-only` | Firefox manifest rules and `web-ext lint` |
| `pnpm run test:firefox` | real headless Firefox over WebDriver BiDi: install, popup, event page, tap window |
| `node tests/check-store-package.mjs <zip> <version>` | the Chrome Web Store's upload rules |
| `cd tests/playwright && pnpm install --frozen-lockfile && pnpm exec playwright test` | Tier-2: Chromium with the extension, a virtual WebAuthn authenticator with PRF, a real Vaultwarden and rageterm |
| `nix build .#checks.x86_64-linux.ragemanifest` (NixOS config) | wasm, the three zipped builds, smoke, unit, store package, Firefox and the host cargo tests, hermetically |

Playwright's global setup builds the wasm if stale, the extension (`--test-hooks`) and a
mock-tap variant for the content-script spec, builds rageterm unless `RAGETERM_BIN` is set,
and starts Vaultwarden from `VAULTWARDEN_URL`, `RAGEWARDEN_VAULTWARDEN_BIN` (the dev shell
sets it), `RAGEWARDEN_CONTAINER_RUNTIME`/docker/podman
(`docker.io/vaultwarden/server:1.37.3`), or `RAGEWARDEN_USE_CARGO_VAULTWARDEN=1`.
The specs are listed in [`tests/playwright/tests/CROSS-CLIENT-ACTIONS.md`](tests/playwright/tests/CROSS-CLIENT-ACTIONS.md).
The release checklist for real hardware is [`tests/manual/firefox-checklist.md`](tests/manual/firefox-checklist.md).
