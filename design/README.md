# design/ -- visual prototype

Run `./fetch-fonts.sh` once to populate `fonts/` (Source Serif 4 from the pinned @fontsource-variable tarball; the files are not tracked).

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
placeholder recovery word list appears in the shipped popup.

## Why it is not the product

It is a visual mockup, not working code:

- `data.jsx` is sample data -- fake logins with cleartext passwords, a fake recipient
  registry, a fake activity feed, and a placeholder recovery word list
  (`sample-01 ... sample-24`); the paper-recovery screen carries a mockup warning so it
  cannot be mistaken for the real one.
- `LockScreen` (`screens-extras.jsx`) accepts any input; sheets such as
  `RecipientPickerSheet` and `MoveToFolderSheet` toast without writing anything; the
  folder chips are a hardcoded list.

The shipped popup is separate code (`ragemanifest/ext/popup/`), and `ragedroid` translates
the same design to Compose.

## Running the prototype

```sh
cd design && python3 -m http.server
# then open http://localhost:8000/RageDroid.html
```

It pulls React and Babel from unpkg, so it needs network access. The extension
does neither -- its CSP forbids both.
