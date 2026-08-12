# design/ -- visual prototype

**This directory is a mockup. It is not the browser extension and it is not
shipped.** The extension's popup lives in
`ragemanifest/ext/popup/` and is written against the real
`ragemanifest/ext/glue/` bridge.

## What the build actually takes from here

`ragemanifest/build.mjs` copies exactly two things into `dist/<target>/popup/`:

| source | destination | why |
| --- | --- | --- |
| `colors_and_type.css` | `tokens.css` | design tokens (colours, type scale, spacing) |
| `fonts/` | `fonts/` | the webfaces `tokens.css` references |

Nothing executable from this directory reaches `dist/`.
`assertPopupIsNotThePrototype()` in `build.mjs` fails the build if a `.jsx`
file, a CDN `<script>`, an in-browser Babel tag, the sample vault or the
placeholder recovery word list ever appears in the shipped popup again.

## Why it is not the product

Until 2026-08 `build.mjs` copied this whole directory into the popup bundle and
compiled the JSX, so the mockup *was* the shipped UI. It is not functional:

- **`data.jsx`** is sample data -- fake logins with cleartext passwords, a fake
  recipient registry, a fake activity feed, and `RECOVERY_PHRASE`, a constant
  word list. `screens-extras.jsx`'s `PaperRecoveryWizard` rendered that
  constant on the paper-recovery screen while the *real* generated phrase went
  to `console.warn` (`RageDroid.html`, `handlePaperRecovery`). Anyone who wrote
  down what the popup showed them was permanently locked out of their vault.
  The list is now `sample-01 ... sample-24` and the screen carries a mockup
  warning, because a mockup must not be mistakable for the real screen.
- **`components.jsx`'s `ToastHost`** was `() => null`. Every screen's error
  handling calls `toast(...)`; none of it rendered. It now renders.
- **`LockScreen`** (`screens-misc.jsx`) accepts any input. There is no password
  to check against in a prototype.
- Sheets like `RecipientPickerSheet` and `MoveToFolderSheet` call
  `toast('Recipients updated...')` without writing anything.
- The folder chip strip is the hardcoded list `['All','Work','Personal','Infrastructure']`.

Those are all reasonable things for a mockup to do. They are not reasonable
things for a password manager to do, which is why the shipped popup is separate
code.

## Running the prototype

```sh
cd design && python3 -m http.server
# then open http://localhost:8000/RageDroid.html
```

It pulls React and Babel from unpkg, so it needs network access. The extension
does neither -- its CSP forbids both.
