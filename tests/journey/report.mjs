#!/usr/bin/env node
/*
 * Render a journey manifest into an annotated HTML page.
 *
 * Input is one or more directories containing a `manifest.json` written by
 * ragedroid's Journal.kt (or by another client emitting the same shape). Output
 * is a single self-contained page: every step is a row showing the state BEFORE
 * the interaction beside the state AFTER it.
 *
 * The before/after pairing is the whole point. A gallery of "after" states shows
 * what the app looks like; only the pair shows what a tap actually did -- and,
 * more usefully for a UX review, the steps where the two are IDENTICAL. Those
 * are the taps that gave the user no feedback at all, and the report flags them
 * rather than leaving you to spot them by eye.
 *
 * TWO ARTIFACT KINDS. `manifest.artifact` says which:
 *
 *   "semantics"  before/after are .txt dumps of the accessibility (Compose
 *                semantics) tree. This is what the Android journey emits.
 *   "screenshot" before/after are .png frames. Kept for any client that can
 *                actually be photographed.
 *
 * WHY ANDROID EMITS TEXT -- AND A CORRECTION. This file used to warn that blank
 * Android frames were an emulator bug: that under `-gpu swiftshader_indirect
 * -no-window` the in-process screenshot APIs return a constant frame while
 * host-side `adb exec-out screencap` captures correctly. THAT WAS WRONG, and
 * it is recorded here because it cost someone a hunt for an emulator bug that
 * does not exist.
 *
 * The real cause is `ragedroid/app/src/main/kotlin/ragewarden/ragedroid/ui/
 * SecureWindow.kt`: MainActivity sets FLAG_SECURE, and Android blanks screen
 * capture of secure windows BY DESIGN. Not the GPU, not headless mode, not the
 * capture API. `adb exec-out screencap` only looked like it worked because it
 * had only ever been pointed at the launcher and the Settings app. Pointed at
 * ragedroid -- launch it, wait for `mCurrentFocus=...ragewarden.ragedroid...`, then
 * capture -- it returns 15,580 bytes of solid black, while the launcher captured
 * seconds later on the same emulator with the same command returns a 1.3 MB
 * screenshot. `dumpsys window` shows that window as `fl=... SECURE ...`, and a
 * `uiautomator dump` taken at the same instant returns the fully drawn screen:
 * the content is there, the pixels are not.
 *
 * FLAG_SECURE is correct for a password manager and is not the thing to change.
 * The journey annotates from the semantics tree instead, which diffs far better
 * than screenshots did anyway.
 *
 * Screenshots, where a client does produce them, are inlined as data URIs so the
 * artifact survives being copied off the machine or attached to an issue.
 */

import { readFileSync, writeFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, basename, resolve } from 'node:path';
import { createHash } from 'node:crypto';

const args = process.argv.slice(2);
if (args.length < 2) {
    console.error('usage: report.mjs <out.html> <journey-dir> [<journey-dir> ...]');
    process.exit(2);
}
const outPath = args[0];
const dirs = args.slice(1);

/* A tree dump is long; collapse runs of untouched lines to this many either side. */
const DIFF_CONTEXT = 3;

/* Above this, the O(n*m) LCS below stops being worth the wait. Trees are ~200
 * lines in practice, so this only trips on something pathological. */
const DIFF_MAX_LINES = 2000;

function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => (
        { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
}

function dataUri(file) {
    const buf = readFileSync(file);
    return `data:image/png;base64,${buf.toString('base64')}`;
}

/** Identical content before and after means the interaction changed nothing. */
function digest(file) {
    return createHash('sha256').update(readFileSync(file)).digest('hex');
}

const isImage = (f) => !!f && f.toLowerCase().endsWith('.png');

/**
 * Longest-common-subsequence line diff.
 *
 * A set difference would be cheaper and wrong: semantics dumps repeat lines
 * (dozens of identical `Actions = [OnClick]` entries), so "which lines are in b
 * but not a" reports nothing where a real change moved a node. The LCS keeps
 * position, which is what makes the output readable.
 */
function diffLines(a, b) {
    if (a.length + b.length > DIFF_MAX_LINES) return null;
    const n = a.length, m = b.length;
    const lcs = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
    for (let i = n - 1; i >= 0; i--) {
        for (let j = m - 1; j >= 0; j--) {
            lcs[i][j] = a[i] === b[j]
                ? lcs[i + 1][j + 1] + 1
                : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
        }
    }
    const out = [];
    let i = 0, j = 0;
    while (i < n && j < m) {
        if (a[i] === b[j]) { out.push({ tag: ' ', text: a[i] }); i++; j++; }
        else if (lcs[i + 1][j] >= lcs[i][j + 1]) { out.push({ tag: '-', text: a[i] }); i++; }
        else { out.push({ tag: '+', text: b[j] }); j++; }
    }
    while (i < n) out.push({ tag: '-', text: a[i++] });
    while (j < m) out.push({ tag: '+', text: b[j++] });
    return out;
}

/** Drop long runs of unchanged lines so the change is the thing you see. */
function collapse(rows) {
    const keep = new Array(rows.length).fill(false);
    rows.forEach((r, idx) => {
        if (r.tag === ' ') return;
        for (let k = idx - DIFF_CONTEXT; k <= idx + DIFF_CONTEXT; k++) {
            if (k >= 0 && k < rows.length) keep[k] = true;
        }
    });
    const out = [];
    let skipped = 0;
    rows.forEach((r, idx) => {
        if (keep[idx]) {
            if (skipped) { out.push({ tag: '...', text: `${skipped} unchanged lines` }); skipped = 0; }
            out.push(r);
        } else {
            skipped++;
        }
    });
    if (skipped) out.push({ tag: '...', text: `${skipped} unchanged lines` });
    return out;
}

function loadJourney(dir) {
    const manifestPath = join(dir, 'manifest.json');
    if (!existsSync(manifestPath)) {
        // Be specific: an empty journey dir almost always means the artifacts
        // were written to getExternalFilesDir() and died with the uninstall.
        throw new Error(
            `${manifestPath} not found. If this is an Android run, check the Journal wrote to ` +
            `the additionalTestOutputDir argument -- artifacts under ` +
            `/sdcard/Android/data/<pkg>/files are deleted when AGP uninstalls the app.`
        );
    }
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    const steps = (manifest.steps || []).map((s) => {
        const beforeFile = s.before ? join(dir, s.before) : null;
        const afterFile = s.after ? join(dir, s.after) : null;
        const unchanged = beforeFile && afterFile
            && existsSync(beforeFile) && existsSync(afterFile)
            && digest(beforeFile) === digest(afterFile);
        return { ...s, beforeFile, afterFile, unchanged };
    });
    const handoffs = readdirSync(dir)
        .filter(f => f.startsWith('handoff-') && f.endsWith('.txt'))
        .map(f => ({ name: f.replace(/^handoff-|\.txt$/g, ''), size: statSync(join(dir, f)).size }));
    // Trust the manifest, but a directory of PNGs from an older run should still
    // render rather than being shown as text.
    const artifact = manifest.artifact
        || (steps.some(s => isImage(s.afterFile)) ? 'screenshot' : 'semantics');
    return { name: manifest.journey || basename(dir), dir, steps, handoffs, artifact };
}

const journeys = dirs.map(d => loadJourney(resolve(d)));

/*
 * Distinguish "this tap produced no feedback" from "the journey never went
 * anywhere", because they look identical in the data and mean opposite things.
 *
 * If EVERY capture in a journey is byte-identical, the per-step "no change"
 * flags are worthless -- reporting them as UX findings would send someone
 * hunting for five bugs that do not exist. For a semantics journey it means the
 * run never left one screen; for a screenshot journey it means the frames are
 * stale or the window is capture-blocked (which, for ragedroid, is exactly what
 * FLAG_SECURE does -- see the header).
 */
for (const j of journeys) {
    const captures = new Set(
        j.steps.flatMap(s => [s.beforeFile, s.afterFile])
            .filter(f => f && existsSync(f))
            .map(digest)
    );
    j.distinctCaptures = captures.size;
    j.stuck = captures.size <= 1 && j.steps.length > 1;
    if (j.stuck) {
        // Do not let one frozen screen masquerade as a row of findings.
        for (const s of j.steps) s.unchanged = false;
    }
}

const totals = journeys.reduce((acc, j) => {
    acc.steps += j.steps.length;
    acc.failed += j.steps.filter(s => s.failure).length;
    acc.silent += j.steps.filter(s => s.unchanged).length;
    return acc;
}, { steps: 0, failed: 0, silent: 0 });

const css = `
:root { color-scheme: light dark; --bg:#faf6ee; --fg:#1a1a1a; --dim:#666; --line:#ddd;
        --warn:#8a5a00; --warnbg:#fff4dd; --bad:#a1211a; --badbg:#ffe9e7;
        --add:#0f6b2f; --addbg:#e6f5ea; --del:#9a2020; --delbg:#fdeaea; --code:#f3efe6; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#121212; --fg:#faf6ee; --dim:#9a9a9a; --line:#2c2c2c;
          --warn:#e0a33e; --warnbg:#2a2312; --bad:#ff8a7a; --badbg:#2e1614;
          --add:#7ee2a0; --addbg:#122417; --del:#ff9d92; --delbg:#2a1514; --code:#191919; }
}
* { box-sizing: border-box; }
body { margin:0; padding:32px; background:var(--bg); color:var(--fg);
       font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; line-height:1.5; }
h1 { font-size:24px; margin:0 0 4px; }
.sub { color:var(--dim); font-size:14px; margin-bottom:24px; }
.summary { display:flex; gap:24px; flex-wrap:wrap; margin-bottom:32px; }
.stat { border:1px solid var(--line); border-radius:8px; padding:12px 18px; min-width:120px; }
.stat b { display:block; font-size:26px; }
.stat span { color:var(--dim); font-size:12px; text-transform:uppercase; letter-spacing:.06em; }
h2 { font-size:18px; margin:36px 0 12px; padding-bottom:6px; border-bottom:1px solid var(--line); }
.step { border:1px solid var(--line); border-radius:10px; margin-bottom:20px; overflow:hidden; }
.step-head { padding:10px 14px; display:flex; gap:12px; align-items:baseline; flex-wrap:wrap; }
.n { font-family:ui-monospace,monospace; color:var(--dim); }
.label { font-weight:600; }
.ms { color:var(--dim); font-size:12px; margin-left:auto; font-family:ui-monospace,monospace; }
.frames { display:grid; grid-template-columns:1fr 1fr; gap:12px; padding:0 14px 14px; }
.frame { min-width:0; }
.frame figcaption { font-size:11px; text-transform:uppercase; letter-spacing:.06em;
                    color:var(--dim); margin-bottom:6px; }
.frame img { width:100%; height:auto; border:1px solid var(--line); border-radius:6px;
             display:block; background:#000; }
.note, .flag { margin:0 14px 12px; padding:8px 12px; border-radius:6px; font-size:13px; }
.note { background:rgba(128,128,128,.12); }
.flag { background:var(--warnbg); color:var(--warn); }
.fail { background:var(--badbg); color:var(--bad); font-family:ui-monospace,monospace;
        white-space:pre-wrap; }
.single .frames { grid-template-columns:minmax(0,480px); }
@media (max-width:820px) { .frames { grid-template-columns:1fr; } }
.tree { margin:0 14px 14px; }
.tree pre { margin:0; padding:10px 12px; background:var(--code); border:1px solid var(--line);
            border-radius:6px; overflow-x:auto; font-family:ui-monospace,monospace;
            font-size:11.5px; line-height:1.45; white-space:pre; }
.tree pre i { font-style:normal; display:block; }
.tree pre i.add { background:var(--addbg); color:var(--add); }
.tree pre i.del { background:var(--delbg); color:var(--del); }
.tree pre i.gap { color:var(--dim); }
.tree summary, .tree .cap { font-size:11px; text-transform:uppercase;
                letter-spacing:.06em; color:var(--dim); margin-bottom:6px; }
.tree summary { cursor:pointer; }
`;

function renderImages(s) {
    const single = !s.beforeFile;
    const frames = [
        s.beforeFile && existsSync(s.beforeFile)
            ? `<figure class="frame"><figcaption>before</figcaption><img loading="lazy" src="${dataUri(s.beforeFile)}" alt="before ${esc(s.label)}"></figure>`
            : '',
        s.afterFile && existsSync(s.afterFile)
            ? `<figure class="frame"><figcaption>${single ? 'state' : 'after'}</figcaption><img loading="lazy" src="${dataUri(s.afterFile)}" alt="after ${esc(s.label)}"></figure>`
            : '',
    ].join('');
    return `<div class="frames">${frames}</div>`;
}

function renderTrees(s) {
    const readLines = f => (f && existsSync(f) ? readFileSync(f, 'utf8').split('\n') : null);
    const before = readLines(s.beforeFile);
    const after = readLines(s.afterFile);
    if (!after) return '';

    const full = `<details class="tree"><summary>full tree after this step (${after.length} lines)</summary>` +
        `<pre>${esc(after.join('\n'))}</pre></details>`;
    if (!before) {
        // A snapshot has no "before"; the tree itself is the record.
        return `<div class="tree"><div class="cap">state</div><pre>${esc(after.join('\n'))}</pre></div>`;
    }
    const rows = diffLines(before, after);
    if (!rows) {
        return `<div class="tree"><div class="note">Tree too large to diff (${before.length} -> ${after.length} lines).</div></div>${full}`;
    }
    const body = collapse(rows).map(r => {
        if (r.tag === '...') return `<i class="gap">      ⋯ ${esc(r.text)} ⋯</i>`;
        const cls = r.tag === '+' ? 'add' : r.tag === '-' ? 'del' : '';
        return `<i class="${cls}">${esc(r.tag + ' ' + r.text)}</i>`;
    }).join('');
    return `<div class="tree"><div class="cap">what this step changed in the accessibility tree</div>` +
        `<pre>${body}</pre></div>${full}`;
}

const rows = journeys.map(j => {
    const steps = j.steps.map(s => {
        const body = j.artifact === 'screenshot' ? renderImages(s) : renderTrees(s);
        return `
<section class="step${!s.beforeFile ? ' single' : ''}">
  <div class="step-head">
    <span class="n">${String(s.n).padStart(3, '0')}</span>
    <span class="label">${esc(s.label)}</span>
    <span class="ms">${s.durationMs ?? 0} ms</span>
  </div>
  ${s.note ? `<div class="note">${esc(s.note)}</div>` : ''}
  ${s.unchanged ? `<div class="flag">${j.artifact === 'screenshot'
        ? 'The screen is byte-identical before and after this interaction -- the user received no visible feedback.'
        : 'The accessibility tree is identical before and after this interaction -- nothing the user could see or a screen reader could announce changed.'}</div>` : ''}
  ${s.failure ? `<div class="note fail">${esc(s.failure)}</div>` : ''}
  ${body}
</section>`;
    }).join('');
    const stuck = j.stuck ? `
<div class="flag" style="margin:0 0 16px">
  <b>This journey never left one screen.</b>
  All ${j.steps.length * 2} captures are byte-identical, including steps where the
  test asserted something changed. Per-step &ldquo;no change&rdquo; flags are
  suppressed because they would be meaningless.
  ${j.artifact === 'screenshot' ? `For a screenshot journey the other explanation is a
  capture-blocked window: ragedroid sets <code>FLAG_SECURE</code>
  (<code>ui/SecureWindow.kt</code>), and Android blanks capture of secure windows by
  design -- including host-side <code>adb exec-out screencap</code>. That is why the
  Android journey records semantics trees instead of pixels.`
        : `Either the run wedged on the first screen, or a system-owned window (the
  IME, a permission dialog) is on top: those are outside the Compose semantics
  tree, so they look like nothing happening.`}
</div>` : '';
    const kind = j.artifact === 'screenshot' ? 'screenshots' : 'accessibility trees';
    const handoffs = j.handoffs.length
        ? `<div class="note">handoffs: ${j.handoffs.map(h => `${esc(h.name)} (${h.size} B)`).join(', ')}</div>`
        : '';
    return `<h2>${esc(j.name)} -- ${j.steps.length} steps, ${kind}</h2>${stuck}${handoffs}${steps}`;
}).join('');

const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ragewarden journey</title><style>${css}</style></head><body>
<h1>ragewarden -- end-to-end journey</h1>
<div class="sub">Every interaction, with the state before and after it.</div>
<div class="summary">
  <div class="stat"><b>${totals.steps}</b><span>steps</span></div>
  <div class="stat"><b>${totals.failed}</b><span>failed</span></div>
  <div class="stat"><b>${totals.silent}</b><span>no visible change</span></div>
  <div class="stat"><b>${journeys.length}</b><span>clients</span></div>
</div>
${rows}
</body></html>`;

writeFileSync(outPath, html);
console.log(
    `[report] ${outPath} -- ${totals.steps} steps across ${journeys.length} journey(s), ` +
    `${totals.failed} failed, ${totals.silent} with no visible change`
);
