# Designer asks -- what's missing to ship full functionality

A walk through the Android surface, screen by screen, listing every gap
between what's implemented today and what a production-grade end-user app
needs. Each item has rough scope and where the engineering already lands.

## A. Onboarding (multi-step flow is half-built)

The current `OnboardingScreen` is labeled "STEP 1 OF 3" but only ships
step 1 (sign in / register against Bitwarden). Steps 2 and 3 are not
designed yet. Engineering has the underlying primitives ready
(`core::recovery`, `core::stanza_format` for hardware identities), so this
is a UX-only block.

* **Step 2 -- recovery enrollment**: show the BIP39 mnemonic, ask the user
  to confirm they wrote it down. Layout for the 24-word grid, "I've stored
  this safely" affirmation, optional QR fallback. Backend already
  generates it (`core::recovery::generate`).
* **Step 3 -- first hardware identity**: pick from {YubiKey PIV, FIDO2
  HMAC-Secret, WebAuthn PRF, Android Keystore-backed key}. Probably one
  primary flow + an "add more later" affordance. Each authenticator type
  needs its own enrollment art (icons, instructions, success state, error
  state).
* **Resume mid-flow**: if the user backgrounds the app between steps,
  what state do they come back to? Currently there's no persistence of
  partial onboarding.
* **Empty-vault first-run**: after onboarding completes, the user is
  on a vault list with zero items. Today that page renders blank -- needs
  a hero illustration + "Add your first secret" CTA.

## B. Settings (entire screen missing)

`onSettings = { toast = Toast("Settings -- phase 2") }` in `RageApp.kt`.
The button exists in the app bar but tapping it shows a toast. Needs a
full screen design with at least:

* Account section: email, server URL, KDF iterations, account ID. Sign
  out / forget device.
* Identity management: list of enrolled hardware/recovery identities
  with last-used timestamps, ability to rename, ability to remove.
* Recovery: re-print the mnemonic (gated by re-auth), download recovery
  file (today only the file is supported, no UI).
* Autofill / IME: enable/disable Android autofill service, enable/disable
  custom keyboard, link to system settings.
* Telemetry / privacy: probably none, but should be explicit ("we don't
  send anything").
* About: version, build hash, link to source.

## C. Recipient management (read-only stub)

`EditItemScreen` currently shows the recipient list with the label
"Recipients · view only -- Editing the recipient set lands with
multi-recipient encrypt". Engineering has multi-recipient encrypt working
in `ragewarden_core`, so this is a UX-only gap.

* **Picker UI**: when adding/editing an item, choose which identities
  can decrypt. Multi-select with the user's identity pool as options.
  Probably grouped by type: software, hardware, recovery.
* **Default recipient policy**: per-item override of "always include
  recovery", "always include all hardware". Today the default is
  hardcoded (recovery only).
* **Visual distinction**: hardware vs software identity should look
  different in the list -- the user's mental model is "tap-to-decrypt"
  vs "always available".

## D. Add / create new item

A "+" affordance is absent from the vault list app bar. Today new items
only appear via the (also absent) recipient picker. Needs:

* Vault list app bar "+" button + new-item screen: type picker (Login,
  Card, Note, Identity, SSH key -- these match the cipher types we already
  parse), then per-type fields.
* Generator UI for passwords: length, charset toggles, copy button.
* Recipient assignment as part of the create flow (see C).
* Folder assignment (folders are another gap -- see G).

## E. Item detail + edit polish

Most of the detail screen is built. Some smaller asks:

* **Action button row** ("Autofill / Copy / Reveal"): currently three
  equal-weight buttons. Designers should review whether this matches the
  user's intent -- "Reveal" is the rarest action, "Autofill" is most
  common.
* **History view**: items have a `history` count ("4 versions"). No
  screen to browse history. Backend support exists in the cipher schema.
* **Notes field URL linkify**: tappable `https://...` in notes (Android's
  `LinkifyCompat`). Pure ergonomic polish, invisible to other Bitwarden
  clients, no markdown rendering.
* **Delete affordance**: the `MoreVert` overflow has menu items, but
  delete-with-confirmation isn't designed.

## F. Reveal & tap-to-authorize

`InlineTapReveal` exists for the "tap your YubiKey" / "place your phone
near the NFC reader" flow. Polish needed:

* **Connecting / scanning animation**: a placeholder breathing dot.
  Needs proper hardware-specific imagery: USB-C plug, NFC pulse,
  fingerprint sensor.
* **Failure states**: "wrong key", "tap timed out", "user cancelled" --
  three different recoverable error UIs.
* **Multi-identity disambiguation**: if more than one enrolled identity
  could decrypt this item, today we just try them in order. Designer
  call: do we let the user pick? Or just show the first one that
  responds?

## G. Folders

Folders show up in the list as filter chips ("All / Work / Personal /
Infrastructure"), but the chip set is hardcoded. Folders are decrypted
on sync but no editing UI exists.

* Folder management screen (rename, delete, color, icon).
* "Move to folder" affordance on item detail / edit.
* "New folder" flow.

## H. Search

A search bar exists at the top of the vault list. Currently a flat
substring match across name/username/site. Designers should weigh:

* Empty-query state -- show recents? Pinned items?
* Result item layout -- how is "the password matched" shown vs "the
  username matched"?
* Filter modifiers (`is:rage`, `folder:Work`) -- terminal-power-user
  affordance, probably skip.

## I. Autofill flow (system integration)

`RagewardenAutofillService` and `AutofillAuthActivity` exist. The
fill-into-form path needs:

* **Picker UI**: when the system autofill panel asks "fill from
  Ragewarden?", we present a list of matching items. Visual layout for
  this picker isn't designed.
* **Reveal-required affordance**: rage-protected items need a tap before
  autofill. The picker needs to show "tap to authorize" inline rather
  than the user re-entering the app.
* **"No match" empty state**: the system shows our chip but we have
  nothing for this domain.

## J. Custom IME (input method)

`RagewardenInputMethodService` is wired but unstyled. Designers should
weigh whether this is even kept (custom keyboards have ergonomic and
trust costs). If kept, needs full keyboard layout art.

## K. Errors, network failures, offline state

* **Network down**: today, sync errors silently -- vault shows last
  cached snapshot but no indicator that it's stale.
* **Server returns 4xx/5xx**: currently surfaced as a small red text
  next to the failing button. Probably needs more structure (icon,
  heading, "retry" button).
* **Token expiry**: when the bearer token expires, today we'd fail on
  next request. Refresh-token flow exists in core. Designers should
  decide: silent re-auth, or "your session expired, sign in again"
  full-screen?
* **Offline-first edit indicator**: when the user edits an item and
  there's no network, the change is queued (engineering ask: this isn't
  built yet, see L). The UI needs a "1 pending change" badge somewhere,
  plus per-item pending state.

## L. Engineering items the designer should be aware of

Not designer-blocked but worth surfacing because they affect UX:

* **Optimistic UI on save**: tapping Save closes the pane immediately
  and queues the network call. Failure surfaces as a toast + persistent
  pending indicator. Needs the indicator design.
* **Pre-warming hardware identity caches**: the first time a YubiKey is
  scanned in a session is slow (NFC enumeration). A "warming up..." state
  may need to appear.
* **Theme**: the app is dark-mode-only today. Light mode + system-follow
  needs a designer pass.
* **Localization / RTL**: strings are English-only. No RTL layout
  testing yet.
* **Dynamic type**: text scaling beyond ~140% breaks several screens.
  Needs a designer review of which texts can wrap and which need
  truncation.
* **Haptics**: no haptic feedback on the tap-reveal path. Standard for
  authenticator-flow apps.
* **Sound**: same -- "secret revealed" is silent. Designers' call
  whether to add subtle audio cues.

## Priority suggestion

If we can rank, my engineering read on impact-vs-cost is:

1. **Settings + identity management** (B) -- needed for re-enrollment, sign
   out, and trust-management; users will hit "where do I add a YubiKey"
   in the first 30 seconds.
2. **Onboarding step 2 + 3** (A) -- the app is currently single-recipient
   only because step 3 doesn't exist; everything else builds on this.
3. **Recipient picker** (C) + **Add new item** (D) -- core "create
   value" flow.
4. **Folders** (G) and **error/offline UX** (K).
5. Polish (E, F, H), advanced integration (I, J), nice-to-have (L
   non-engineering items).
