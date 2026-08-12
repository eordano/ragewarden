/**
 * The Ragewarden popup.
 *
 * Everything on screen here comes from `window.RagewardenVault` (the glue in
 * ../glue/) or from the snapshot the glue publishes on `window.VAULT`,
 * `window.ITEMS_BY_KIND` and `window.FOLDERS`. There is no sample data in this
 * directory and no code path that substitutes a placeholder when a bridge call
 * fails: a failure is shown as a failure.
 *
 * design/ is the visual prototype and is not shipped. Its tokens
 * (colors_and_type.css + fonts) are, and that is the whole of the relationship.
 */

import {
    banner, button, clear, createToaster, errorText, eyebrow, field, h,
    initials, relTime, row, sheet, textInput,
} from './ui.js';
import { writeClipboard, clearClipboardSync } from '../glue/clipboard.js';

/*
 * A pending clipboard wipe has to survive the screen that scheduled it, and
 * cannot survive the popup itself. Chromium builds open as a side panel and do
 * keep running; Firefox and Safari open a `default_popup` that closes on any
 * outside click, taking its timers with it. This flag lets the one `pagehide`
 * listener below make the last synchronous attempt available on the way out.
 */
let clipboardHoldsSecret = false;

window.addEventListener('pagehide', () => {
    if (!clipboardHoldsSecret) return;
    clipboardHoldsSecret = false;
    try { clearClipboardSync(); } catch {}
});

const screenEl = document.getElementById('screen');
const toast = createToaster(document.getElementById('toasts'));

const app = {
    route: 'boot',
    payload: null,
    unlocked: false,
    init: { phase: 'starting', error: null, result: null },
    query: '',
    folder: null,
};

function bridge() {
    return (typeof window !== 'undefined' && window.RagewardenVault) || null;
}

/** Fail-closed accessor: a missing bridge method is an error, never a no-op. */
function need(name) {
    const b = bridge();
    const fn = b && b[name];
    if (typeof fn !== 'function') {
        throw new Error(`the vault bridge does not expose ${name}() -- this build is incomplete`);
    }
    return fn.bind(b);
}

async function guard(label, promise) {
    try {
        return await promise;
    } catch (err) {
        toast.error(`${label}: ${errorText(err)}`);
        throw err;
    }
}

function go(route, payload = null) {
    app.route = route;
    app.payload = payload;
    render();
}

function logins() {
    return Array.isArray(window.VAULT) ? window.VAULT : [];
}
function otherItems() {
    return Array.isArray(window.ITEMS_BY_KIND) ? window.ITEMS_BY_KIND : [];
}
function allItems() {
    return [...logins().map(i => ({ ...i, kind: 'login' })), ...otherItems()];
}
function folders() {
    return Array.isArray(window.FOLDERS) ? window.FOLDERS : [];
}
function itemById(id) {
    return allItems().find(i => i.id === id) || null;
}

function appBar(title, subtitle, opts = {}) {
    return h('div', { class: 'appbar' },
        opts.back ? button('‹', opts.back, { variant: 'icon', title: 'Back' }) : null,
        h('div', { class: 'appbar-titles' },
            h('div', { class: 'appbar-title', text: title }),
            subtitle ? h('div', { class: 'appbar-sub', text: subtitle }) : null),
        h('div', { class: 'appbar-actions' }, ...(opts.actions || [])));
}

function body(...kids) {
    return h('div', { class: 'body' }, ...kids);
}

function footer(...kids) {
    return h('div', { class: 'footer' }, ...kids);
}

/* ── master-password gate ───────────────────────────────────────────────── */

/**
 * Resolve true only after the server has confirmed the password. Every other
 * path -- cancel, missing bridge method, network failure, wrong password --
 * resolves false. There is no branch that resolves true without a completed
 * `verifyMasterPassword` call.
 */
function requireMasterPassword({ title, body: prose, action = 'Confirm' }) {
    return new Promise((resolve) => {
        const input = textInput({ type: 'password', placeholder: 'Master password', mono: true });
        const status = h('div', { class: 'hint hint-danger' });
        let settled = false;
        const finish = (value) => {
            if (settled) return;
            settled = true;
            resolve(value);
        };

        const confirmBtn = button(action, async () => {
            status.textContent = '';
            let verify;
            try {
                verify = need('verifyMasterPassword');
            } catch (err) {
                status.textContent = errorText(err);
                return;
            }
            confirmBtn.disabled = true;
            confirmBtn.textContent = 'Checking...';
            try {
                const ok = await verify(input.value);
                if (ok !== true) throw new Error('the server did not confirm this password');
                finish(true);
                s.close();
            } catch (err) {
                status.textContent = errorText(err);
                confirmBtn.disabled = false;
                confirmBtn.textContent = action;
            }
        }, { variant: 'danger', full: true });

        input.addEventListener('keydown', e => { if (e.key === 'Enter') confirmBtn.click(); });

        const s = sheet({
            title: title || 'Confirm with your master password',
            body: h('div', {},
                prose ? h('p', { class: 'prose', text: prose }) : null,
                field('Master password', input),
                status,
                h('div', { class: 'hint', text: 'Checked against your Bitwarden server. Requires connectivity.' })),
            actions: [
                button('Cancel', () => { finish(false); s.close(); }, { variant: 'ghost' }),
                confirmBtn,
            ],
            onClose: () => finish(false),
        });
        document.querySelector('.phone').appendChild(s.el);
        input.focus();
    });
}

/**
 * A plain yes/no, with no password and no network.
 *
 * `requireMasterPassword` is a round trip to the Bitwarden server, so it is
 * reserved for the one action that destroys data there and cannot be undone:
 * deleting an item. It used to guard signing out, removing a recipient, and
 * *leaving the paper-recovery screen* -- a screen whose entire purpose is to
 * work when the server is unreachable, so the gate could trap the user on it.
 * Everything that needs a "did you mean that?" and nothing more uses this.
 */
function confirmAction({ title, body: prose, action = 'Confirm', variant = 'danger' }) {
    return new Promise((resolve) => {
        let settled = false;
        const finish = (value) => {
            if (settled) return;
            settled = true;
            resolve(value);
        };
        const s = sheet({
            title,
            body: h('div', {}, prose ? h('p', { class: 'prose', text: prose }) : null),
            actions: [
                button('Cancel', () => { finish(false); s.close(); }, { variant: 'ghost' }),
                button(action, () => { finish(true); s.close(); }, { variant, full: true }),
            ],
            onClose: () => finish(false),
        });
        document.querySelector('.phone').appendChild(s.el);
    });
}

/* ── screens ────────────────────────────────────────────────────────────── */

function bootScreen() {
    if (app.init.phase === 'failed' || app.init.phase === 'cancelled') {
        return h('div', { class: 'centered' },
            h('div', { class: 'brand', text: 'Ragewarden' }),
            banner('danger', app.init.phase === 'cancelled' ? 'Sign-in cancelled' : 'Could not start',
                app.init.error || 'unknown error'),
            button('Try again', () => location.reload(), { variant: 'primary', full: true }));
    }
    return h('div', { class: 'centered' },
        h('div', { class: 'brand', text: 'Ragewarden' }),
        h('div', { class: 'muted', text: 'Loading the vault...' }));
}

function lockScreen() {
    const email = app.init.result?.email || bridge()?.status?.().email || '';
    const input = textInput({ type: 'password', placeholder: 'Master password', mono: true });
    const status = h('div', { class: 'hint hint-danger' });

    const unlock = button('Unlock', async () => {
        status.textContent = '';
        let verify;
        try {
            verify = need('verifyMasterPassword');
        } catch (err) {
            status.textContent = errorText(err);
            toast.error(errorText(err));
            return;
        }
        if (!input.value) { status.textContent = 'Enter your master password.'; return; }
        unlock.disabled = true;
        unlock.textContent = 'Checking...';
        try {
            const ok = await verify(input.value);
            if (ok !== true) throw new Error('the server did not confirm this password');
            input.value = '';
            app.unlocked = true;
            go('vault');
        } catch (err) {
            status.textContent = errorText(err);
        } finally {
            unlock.disabled = false;
            unlock.textContent = 'Unlock';
        }
    }, { variant: 'primary', full: true });

    input.addEventListener('keydown', e => { if (e.key === 'Enter') unlock.click(); });

    const mock = app.init.mockTap
        ? banner('danger', 'MOCK TAP BUILD', app.init.backendLabel || 'This build can fabricate hardware taps.')
        : null;

    const node = h('div', { class: 'centered' },
        mock,
        h('div', { class: 'brand', text: 'Ragewarden' }),
        h('div', { class: 'muted', text: email ? `Signed in as ${email}` : 'Signed in' }),
        field('Master password', input),
        status,
        unlock,
        button('Sign out', async () => {
            try {
                await guard('Sign out', need('logout')());
                location.reload();
            } catch {}
        }, { variant: 'ghost', full: true }));
    setTimeout(() => input.focus(), 0);
    return node;
}

function vaultScreen() {
    const items = allItems();
    const unprotected = items.filter(i => !i.rage);

    const search = textInput({ placeholder: 'Search name, username, site', value: app.query });
    search.addEventListener('input', () => {
        app.query = search.value;
        const list = document.getElementById('vault-list');
        if (list) renderList(list);
    });

    function renderList(host) {
        clear(host);
        const qq = app.query.trim().toLowerCase();
        const rows = items.filter(it => {
            if (app.folder && (it.folder || null) !== app.folder) return false;
            if (!qq) return true;
            return [it.name, it.username, it.site, it.folder]
                .some(v => typeof v === 'string' && v.toLowerCase().includes(qq));
        });
        if (rows.length === 0) {
            host.appendChild(h('div', { class: 'empty', text: items.length === 0
                ? 'This vault has no items yet.'
                : 'No items match.' }));
            return;
        }
        for (const it of rows) host.appendChild(vaultRow(it));
    }

    const list = h('div', { class: 'list', id: 'vault-list' });
    renderList(list);

    const chips = h('div', { class: 'chips' },
        chip('All', app.folder === null, () => { app.folder = null; render(); }),
        ...folders().map(f => chip(`${f.name} (${f.count})`, app.folder === f.name,
            () => { app.folder = f.name; render(); })));

    return h('div', { class: 'col' },
        appBar('Vault', `${items.length} item${items.length === 1 ? '' : 's'} · ${items.length - unprotected.length} protected`, {
            actions: [
                button('↻', async () => {
                    try {
                        await guard('Refresh', need('refresh')());
                        toast.ok('Synced');
                        render();
                    } catch {}
                }, { variant: 'icon', title: 'Refresh from server' }),
                button('+', () => go('edit', { create: true }), { variant: 'icon', title: 'Add item' }),
                button('⚙', () => go('settings'), { variant: 'icon', title: 'Settings' }),
            ],
        }),
        h('div', { class: 'pad-x' }, search),
        chips,
        unprotected.length > 0
            ? h('div', { class: 'pad-x' }, banner('warning',
                `${unprotected.length} item${unprotected.length === 1 ? '' : 's'} not hardware-protected`,
                'Re-wrap them to your enrolled recipients.',
                { label: 'Protect', onClick: () => go('bulk', { from: 'vault' }) }))
            : null,
        body(list));
}

function chip(label, active, onClick) {
    return h('button', {
        class: `chip${active ? ' chip-on' : ''}`, type: 'button', onclick: onClick,
    }, label);
}

// Only unprotected items carry a tag. Badging every row RAGE or plain made the
// exception -- the item the server can still read -- no louder than the rule.
function vaultRow(it) {
    return h('button', { class: 'vrow', type: 'button', onclick: () => go('detail', it.id) },
        h('div', { class: 'avatar', text: initials(it.name) }),
        h('div', { class: 'vrow-main' },
            h('div', { class: 'vrow-name', text: it.name || '(unnamed)' }),
            h('div', { class: 'vrow-sub', text: [it.username, it.site].filter(Boolean).join(' · ') || (it.kind || '') })),
        it.rage ? null : h('span', { class: 'tag', text: 'plain' }));
}

function detailScreen(id) {
    const item = itemById(id);
    if (!item) {
        return h('div', { class: 'col' },
            appBar('Item', null, { back: () => go('vault') }),
            body(banner('danger', 'Gone', 'This item is no longer in the vault snapshot.')));
    }

    const secretHost = h('div', { class: 'secret-host' });
    let clearTimer = null;
    let tickTimer = null;

    /**
     * Stop the cosmetic countdown only.
     *
     * `clearTimer` is the 30-second clipboard wipe and is deliberately NOT
     * cancelled here. Navigating away from the item does not un-copy the
     * password, so the wipe has to outlive the screen that scheduled it; the
     * old `stopTimers()` cancelled both, which meant leaving the detail screen
     * after a Copy left the password on the clipboard indefinitely.
     */
    function stopTicker() {
        if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
    }

    /** Both timers -- only for paths that have already wiped the clipboard. */
    function stopTimers() {
        if (clearTimer) { clearTimeout(clearTimer); clearTimer = null; }
        stopTicker();
    }

    function idleSecret() {
        stopTicker();
        clear(secretHost);
        secretHost.appendChild(h('div', { class: 'secret-idle' },
            h('span', { class: 'mono dim', text: '••••••••••••' })));
    }

    async function doReveal() {
        clear(secretHost);
        secretHost.appendChild(h('div', { class: 'muted', text: 'Waiting for your hardware tap...' }));
        let value;
        try {
            value = await need('revealPassword')(item.id, 'password');
        } catch (err) {
            toast.error(`Reveal: ${errorText(err)}`);
            idleSecret();
            return;
        }
        let left = 10;
        const countdown = h('span', { class: 'mono dim', text: `hides in ${left}s` });
        const shown = h('div', { class: 'secret-value mono', text: value });
        clear(secretHost);
        secretHost.appendChild(h('div', { class: 'secret-open' },
            shown,
            row(
                button('Copy', async () => {
                    try {
                        await writeClipboard(value);
                        toast.ok('Copied to the clipboard.');
                    } catch (err) { toast.error(`Copy: ${errorText(err)}`); }
                }, {}),
                button('Hide', () => { value = ''; idleSecret(); }, { variant: 'ghost' }),
                countdown)));
        tickTimer = setInterval(() => {
            left -= 1;
            countdown.textContent = `hides in ${left}s`;
            if (left <= 0) { value = ''; idleSecret(); }
        }, 1000);
    }

    async function doCopy() {
        clear(secretHost);
        secretHost.appendChild(h('div', { class: 'muted', text: 'Waiting for your hardware tap...' }));
        let res;
        try {
            res = await need('copyPassword')(item.id);
        } catch (err) {
            toast.error(`Copy: ${errorText(err)}`);
            idleSecret();
            return;
        }
        toast.ok(`Copied ${res && res.chars ? `${res.chars} characters` : 'the password'} to the clipboard.`);
        clipboardHoldsSecret = true;
        let left = 30;
        const label = h('span', { class: 'mono dim', text: `clipboard cleared in ${left}s` });
        clear(secretHost);
        secretHost.appendChild(h('div', { class: 'secret-open' },
            h('div', { class: 'muted', text: 'The password is on your clipboard. It was never rendered here.' }),
            row(button('Clear now', async () => {
                stopTimers();
                clipboardHoldsSecret = false;
                await bridge()?.clearClipboard?.();
                toast.info('Clipboard overwritten.');
                idleSecret();
            }, {}), label)));
        tickTimer = setInterval(() => {
            left -= 1;
            label.textContent = `clipboard cleared in ${left}s`;
        }, 1000);
        clearTimer = setTimeout(async () => {
            stopTimers();
            clipboardHoldsSecret = false;
            const ok = await bridge()?.clearClipboard?.();
            if (ok) toast.info('Clipboard overwritten.');
            else toast.warn('Could not overwrite the clipboard -- clear it yourself.');
            idleSecret();
        }, 30_000);
    }

    async function doAutofill() {
        let tab = null;
        try {
            tab = await activeTab();
        } catch (err) {
            toast.error(`Autofill: ${errorText(err)}`);
            return;
        }
        if (!tab) {
            toast.error('Autofill: no active tab to fill.');
            return;
        }
        let host = '';
        try { host = new URL(tab.url).host; } catch { host = ''; }
        clear(secretHost);
        secretHost.appendChild(h('div', { class: 'muted', text: `Waiting for your hardware tap to fill ${host || 'the active tab'}...` }));
        let value;
        try {
            value = await need('autofillPassword')(item.id, host || item.site || '');
        } catch (err) {
            toast.error(`Autofill: ${errorText(err)}`);
            idleSecret();
            return;
        }
        try {
            const resp = await sendToTab(tab.id, {
                kind: 'ragewarden.fill',
                username: item.username || '',
                password: value,
            });
            if (!resp || !resp.ok) throw new Error((resp && resp.error) || 'the page did not accept the fill');
            toast.ok(`Filled ${resp.host || host}.`);
        } catch (err) {
            toast.error(`Autofill: ${errorText(err)}`);
        } finally {
            value = '';
            idleSecret();
        }
    }

    idleSecret();

    const historyHost = h('div', { class: 'list-sub' });
    loadHistory(item.id, historyHost);

    return h('div', { class: 'col' },
        appBar(item.name || '(unnamed)', item.site || item.folder || '', {
            back: () => { stopTicker(); go('vault'); },
            // stopTicker here too: leaving via Edit used to leave the reveal
            // countdown ticking against a detached node, so a later render
            // could be clobbered by a timer belonging to a screen that is gone.
            actions: [button('✎', () => { stopTicker(); go('edit', { id: item.id }); },
                { variant: 'icon', title: 'Edit' })],
        }),
        body(
            item.rage
                ? banner('success', 'Hardware-protected', 'Each use needs a fresh tap on an enrolled authenticator.')
                : banner('warning', 'Not hardware-protected',
                    'The server can read this item. Protect it to wrap it in the rage layer.',
                    { label: 'Protect', onClick: () => go('bulk', { only: item.id, from: 'detail' }) }),
            item.username
                ? field('Username', h('div', { class: 'readout' },
                    h('span', { class: 'mono', text: item.username }),
                    button('Copy', async () => {
                        try {
                            await writeClipboard(item.username);
                            toast.ok('Username copied.');
                        } catch (err) { toast.error(`Copy: ${errorText(err)}`); }
                    }, { variant: 'ghost' })))
                : null,
            field('Password', h('div', {},
                secretHost,
                row(
                    button('Autofill', doAutofill, { variant: 'primary' }),
                    button('Copy', doCopy),
                    button('Reveal', doReveal)))),
            item.site
                ? field('Site', h('div', { class: 'readout' },
                    h('span', { class: 'mono', text: item.site }),
                    button('Copy', async () => {
                        try {
                            await writeClipboard(item.site);
                            toast.ok('Site copied.');
                        } catch (err) { toast.error(`Copy: ${errorText(err)}`); }
                    }, { variant: 'ghost' })))
                : null,
            eyebrow('History'),
            historyHost,
            h('div', { class: 'spacer' }),
            button('Delete item', async () => {
                if (!await requireMasterPassword({
                    title: 'Delete this item?',
                    body: `"${item.name}" will be removed from the Bitwarden server. This cannot be undone.`,
                    action: 'Delete',
                })) return;
                try {
                    await guard('Delete', need('deleteCipher')(item.id));
                    toast.ok('Deleted.');
                    go('vault');
                } catch {}
            }, { variant: 'danger', full: true })));
}

async function loadHistory(id, host) {
    clear(host);
    host.appendChild(h('div', { class: 'muted', text: 'Loading...' }));
    const b = bridge();
    if (!b || !b.history || typeof b.history.load !== 'function') {
        clear(host);
        host.appendChild(h('div', { class: 'muted', text: 'History is unavailable in this build.' }));
        return;
    }
    let entries = [];
    try {
        entries = await b.history.load(id);
    } catch (err) {
        clear(host);
        host.appendChild(banner('danger', 'History failed', errorText(err)));
        return;
    }
    clear(host);
    if (!Array.isArray(entries) || entries.length === 0) {
        host.appendChild(h('div', { class: 'muted', text: 'No earlier revisions recorded.' }));
        return;
    }
    for (const e of entries.slice(0, 20)) {
        host.appendChild(h('div', { class: 'srow' },
            h('span', { class: 'mono dim', text: relTime(e.recordedAt) }),
            h('span', { text: Array.isArray(e.recipientsSummary) && e.recipientsSummary.length
                ? `${e.recipientsSummary.length} recipient(s)` : 'revision' })));
    }
}

function editScreen(payload) {
    const creating = !payload || payload.create;
    const existing = creating ? null : itemById(payload.id);
    if (!creating && !existing) {
        return h('div', { class: 'col' },
            appBar('Edit', null, { back: () => go('vault') }),
            body(banner('danger', 'Gone', 'That item is no longer in the vault snapshot.')));
    }

    const name = textInput({ value: existing ? existing.name : '', placeholder: 'GitHub' });
    const secret = h('textarea', {
        class: 'input mono textarea', rows: '4',
        placeholder: creating ? 'the secret to protect' : 'leave blank to keep the stored secret',
    });
    const type = h('select', { class: 'input' },
        h('option', { value: 'login', text: 'Login' }),
        h('option', { value: 'note', text: 'Secure note' }));
    if (existing && existing.kind && existing.kind !== 'login') type.value = 'note';

    const coverage = h('div', { class: 'list-sub' });
    renderCoverage(coverage);

    const save = button(creating ? 'Create' : 'Save', async () => {
        if (!name.value.trim()) { toast.error('Give the item a name.'); return; }
        if (creating && !secret.value) { toast.error('Enter the secret to store.'); return; }
        save.disabled = true;
        save.textContent = 'Encrypting...';
        try {
            if (creating) {
                const saved = await guard('Create', need('setCipher')(
                    name.value.trim(), secret.value, { type: type.value }));
                secret.value = '';
                toast.ok('Created and wrapped.');
                go('detail', saved && (saved.id || saved.Id));
            } else {
                /*
                 * Not trimmed and not coerced: a secret may legitimately begin
                 * or end in whitespace, and only a genuinely empty box means
                 * "keep it". `editCipher` takes null as "re-wrap what is
                 * already stored", so a rename does not need the plaintext --
                 * which is just as well, because this screen has no Reveal and
                 * never prefills. It used to refuse to save without it, so
                 * renaming an item was impossible from here.
                 */
                const replacement = secret.value.length > 0 ? secret.value : null;
                await guard('Save', need('editCipher')(
                    existing.id, name.value.trim(), replacement, { type: type.value }));
                secret.value = '';
                toast.ok(replacement === null ? 'Renamed and re-wrapped.' : 'Saved and re-wrapped.');
                go('detail', existing.id);
            }
        } catch {
            save.disabled = false;
            save.textContent = creating ? 'Create' : 'Save';
        }
    }, { variant: 'primary', full: true });

    return h('div', { class: 'col' },
        appBar(creating ? 'New item' : 'Edit item', existing ? existing.name : null, {
            back: () => (existing ? go('detail', existing.id) : go('vault')),
        }),
        body(
            field('Name', name),
            field('Type', type),
            // The re-wrap path unlocks the stored secret once, so it taps too --
            // say so for both cases rather than let the hardware prompt be a
            // surprise on what the user thinks is only a rename.
            field('Secret', secret, creating
                ? 'Stored wrapped. Reading it back always costs a hardware tap.'
                : 'Blank keeps the stored secret; typing a new one replaces it. Saving '
                  + 're-wraps the item either way, which costs one hardware tap.'),
            eyebrow('Will be wrapped to'),
            coverage),
        footer(save));
}

/**
 * Name the devices a write would reach, and nothing else.
 *
 * This used to print "N recipient stanza(s) (policy: every default-encrypt
 * registry entry)" -- a count of age stanzas and the name of the policy that
 * produced it, neither of which is a thing the user owns -- and then a "Coverage
 * hole" banner claiming "Items written here will not open on that device". The
 * banner was wrong in the commonest case: an enrolled browser's own passkey is
 * always skipped as `no_local_authenticator` (wraps do not tap), while the
 * paired Software entry `enrollPasskey` publishes covers that device anyway. It
 * fired on every visit to New item, Edit item and Recipients, and offered no
 * action.
 *
 * Names come from the registry minus what policy skipped, which is the same
 * covered/dropped split the bulk-protect pips already draw.
 */
async function renderCoverage(host) {
    clear(host);
    host.appendChild(h('div', { class: 'muted', text: 'Checking the recipient policy...' }));
    let preview;
    let registry;
    try {
        [preview, registry] = await Promise.all([
            need('previewEncryptRecipients')(),
            need('listRecipients')(),
        ]);
    } catch (err) {
        clear(host);
        host.appendChild(banner('danger', 'Recipient policy unavailable', errorText(err)));
        return;
    }
    clear(host);
    if (preview.recipients.length === 0) {
        host.appendChild(h('div', { class: 'hint hint-danger', text:
            'No recipients -- a save would produce something nothing can open. '
            + 'Enrol a passkey or paper recovery first.' }));
        return;
    }
    const skipped = new Set(preview.skipped.map(s => String(s.id)));
    const names = registry
        .filter(e => !skipped.has(String(e.id)))
        .map(e => e.displayName || e.id);
    host.appendChild(h('div', { class: 'hint', text: names.length > 0
        ? names.join(', ')
        : `${preview.recipients.length} recipient(s) held by this browser` }));
}

function settingsScreen() {
    const email = app.init.result?.email || bridge()?.status?.().email || '';
    return h('div', { class: 'col' },
        appBar('Settings', email, { back: () => go('vault') }),
        body(
            navRow('Recipients', 'Who can open your protected items', () => go('recipients')),
            navRow('Paper recovery', 'Create or use an offline recovery phrase', () => go('recovery')),
            navRow('Folders', 'Organise the vault', () => go('folders')),
            navRow('Bulk protect', 'Re-wrap unprotected items', () => go('bulk', { from: 'settings' })),
            navRow('Audit log', 'What this extension did, locally', () => go('audit')),
            h('div', { class: 'spacer' }),
            button('Lock', () => { app.unlocked = false; go('lock'); }, { variant: 'secondary', full: true }),
            // Signing out destroys nothing but a session envelope, and demanding
            // the master password for it meant you could not sign out of a
            // server you could not reach -- the exact case where you want to.
            button('Sign out', async () => {
                if (!await confirmAction({
                    title: 'Sign out?',
                    body: 'The stored session envelope is dropped. You will sign in to Bitwarden again.',
                    action: 'Sign out',
                })) return;
                try {
                    await guard('Sign out', need('logout')());
                    location.reload();
                } catch {}
            }, { variant: 'danger', full: true })));
}

function navRow(title, sub, onClick) {
    return h('button', { class: 'navrow', type: 'button', onclick: onClick },
        h('div', { class: 'navrow-main' },
            h('div', { class: 'navrow-title', text: title }),
            h('div', { class: 'navrow-sub', text: sub })),
        h('span', { class: 'chev', text: '›' }));
}

function recipientsScreen() {
    const host = h('div', { class: 'list-sub' });
    const coverage = h('div', { class: 'list-sub' });
    reloadRecipients(host);
    renderCoverage(coverage);

    return h('div', { class: 'col' },
        appBar('Recipients', 'Cross-device registry', { back: () => go('settings') }),
        body(
            eyebrow('Registry'),
            host,
            eyebrow('What a write wraps to'),
            coverage,
            h('div', { class: 'spacer' }),
            button('Enrol a passkey on this browser', async () => {
                try {
                    const res = await guard('Enrol passkey', need('enrollPasskey')({}));
                    toast.ok(`Enrolled ${res?.passkeyRecord?.label || 'passkey'}.`);
                    reloadRecipients(host);
                    renderCoverage(coverage);
                } catch {}
            }, { variant: 'primary', full: true })));
}

async function reloadRecipients(host) {
    clear(host);
    host.appendChild(h('div', { class: 'muted', text: 'Loading the registry...' }));
    let entries;
    try {
        entries = await need('listRecipients')();
    } catch (err) {
        clear(host);
        host.appendChild(banner('danger', 'Registry unavailable', errorText(err)));
        return;
    }
    clear(host);
    if (!entries.length) {
        host.appendChild(h('div', { class: 'muted', text: 'No recipients published yet.' }));
        return;
    }
    for (const e of entries) {
        host.appendChild(h('div', { class: 'srow srow-tall' },
            h('div', { class: 'srow-main' },
                h('div', { text: e.displayName || e.id }),
                h('div', { class: 'mono dim', text: `${e.kind} · ${e.id}` }),
                // Only the exception is worth a line. "defaultEncrypt: on" was
                // printed under every row and said nothing the list did not.
                e.defaultEncrypt === false
                    ? h('div', { class: 'mono dim', text: 'new items are NOT wrapped to this' })
                    : null),
            // No master password: this sheet's own body says the action does
            // not break anything already stored, so the gate was contradicting
            // the text next to it.
            button('Remove', async () => {
                if (!await confirmAction({
                    title: 'Remove this recipient?',
                    body: `${e.displayName || e.id} will stop being wrapped into new writes. `
                        + 'Items already wrapped to it keep working.',
                    action: 'Remove',
                })) return;
                try {
                    await guard('Remove recipient', need('removeRecipient')(e.id));
                    toast.ok('Removed.');
                    reloadRecipients(host);
                } catch {}
            }, { variant: 'danger' })));
    }
}

/* ── paper recovery ─────────────────────────────────────────────────────── */

function recoveryScreen() {
    return h('div', { class: 'col' },
        appBar('Paper recovery', null, { back: () => go('settings') }),
        body(
            h('p', { class: 'prose', text:
                'A recovery identity is an age key derived from a phrase. Written on paper and '
                + 'kept offline, it opens your protected items when every enrolled device is gone.' }),
            button('Create a recovery phrase', () => go('recovery-new'), { variant: 'primary', full: true }),
            h('div', { class: 'spacer' }),
            eyebrow('Already have a phrase?'),
            button('Open an item with a phrase', () => go('recovery-use'), { variant: 'secondary', full: true })));
}

/**
 * Discard a recovery identity that was published but never written down.
 *
 * `enrollRecovery()` publishes the registry entry and *then* returns the phrase
 * for display, so from the moment the words appear there is a recipient in the
 * registry whose private half exists only on this screen. Leaving without
 * writing them down does not undo that: every later write is wrapped to a
 * recipient nobody can ever open, and the coverage readout counts it as
 * protection. Removing the entry is the only way back to a true state.
 */
async function discardUnconfirmedRecovery(res) {
    if (!res || !res.registryEntryId) return false;
    try {
        await need('removeRecipient')(res.registryEntryId);
        return true;
    } catch (err) {
        toast.error(
            `Could not remove the unconfirmed recovery recipient (${errorText(err)}). `
            + `Remove ${res.registryEntryId} from Settings -> Recipients by hand, or new items `
            + 'will be wrapped to a key nobody holds.',
        );
        return false;
    }
}

function recoveryNewScreen() {
    const host = h('div', {});
    // Set once the phrase is on screen; drives the guarded exit in the app bar.
    let live = null;
    const start = button('Generate and publish', async () => {
        start.disabled = true;
        start.textContent = 'Generating...';
        let res;
        try {
            res = await need('enrollRecovery')('Paper recovery');
        } catch (err) {
            toast.error(`Enrol recovery: ${errorText(err)}`);
            start.disabled = false;
            start.textContent = 'Generate and publish';
            return;
        }
        if (!res || typeof res.phrase !== 'string' || res.phrase.trim().length === 0) {
            toast.error('The recovery generator returned no phrase -- nothing was written down.');
            start.disabled = false;
            start.textContent = 'Generate and publish';
            return;
        }
        clear(host);
        live = res;
        host.appendChild(phrasePanel(res, () => { live = null; }));
    }, { variant: 'primary', full: true });

    host.appendChild(h('div', {},
        h('div', { class: 'hint', text:
            'Generated in WASM. Only the public key is published.' }),
        start));

    // Local confirm, not requireMasterPassword: this screen exists for the day
    // the server is gone, and a gate that needs the server to answer could pin
    // the user to it with an unwritten phrase on screen.
    const back = async () => {
        if (!live) { go('recovery'); return; }
        const res = live;
        if (!await confirmAction({
            title: 'Leave without writing the phrase down?',
            body: 'This recovery key is already published as a recipient. If you leave now the '
                + 'words are gone, so it will be removed again -- otherwise every item you save '
                + 'afterwards would be wrapped to a key nobody holds.',
            action: 'Remove it and leave',
        })) return;
        live = null;
        if (await discardUnconfirmedRecovery(res)) {
            toast.info('Unconfirmed recovery recipient removed.');
        }
        go('recovery');
    };

    return h('div', { class: 'col' },
        appBar('New recovery phrase', null, { back }),
        body(host));
}

/**
 * Show the phrase that `enrollRecovery()` actually generated.
 *
 * The prototype rendered a constant word list from design/data.jsx and dumped
 * the real phrase to `console.warn`. Anyone who wrote down what the screen said
 * was permanently locked out. The words below come from `res.phrase` and from
 * nowhere else.
 *
 * The three-word check gates the *confirmation*, not the exit: a popup can be
 * dismissed by clicking outside it and no script can stop that. So the panel
 * also offers an explicit discard, and the app bar's back action removes the
 * published recipient rather than stranding it. `onConfirmed` tells the screen
 * the entry is now the user's problem and no longer needs cleaning up.
 */
function phrasePanel(res, onConfirmed) {
    const words = res.phrase.trim().split(/\s+/);
    const grid = h('div', { class: 'phrase-grid' });
    words.forEach((w, i) => {
        grid.appendChild(h('div', { class: 'phrase-word' },
            h('span', { class: 'phrase-idx', text: String(i + 1) }),
            h('span', { class: 'mono', text: w })));
    });

    const checkIdx = pickDistinct(words.length, Math.min(3, words.length));
    const inputs = checkIdx.map(() => textInput({ mono: true, placeholder: 'word' }));
    const status = h('div', { class: 'hint hint-danger' });

    const done = button('I have written it down', () => {
        const wrong = checkIdx.filter((idx, n) =>
            inputs[n].value.trim().toLowerCase() !== words[idx].toLowerCase());
        if (wrong.length > 0) {
            status.textContent = `Word ${wrong.map(i => i + 1).join(', ')} does not match. `
                + 'Check the copy you wrote down.';
            return;
        }
        status.textContent = '';
        onConfirmed?.();
        toast.ok('Recovery identity published and verified.');
        go('settings');
    }, { variant: 'primary', full: true });

    const discard = button('I did not write it down -- remove it', async () => {
        if (!await confirmAction({
            title: 'Remove this recovery identity?',
            body: 'It is already published as a recipient. Removing it now is the safe outcome: '
                + 'the alternative is items wrapped to a key nobody holds.',
            action: 'Remove it',
        })) return;
        onConfirmed?.();
        if (await discardUnconfirmedRecovery(res)) toast.info('Recovery recipient removed.');
        go('recovery');
    }, { variant: 'ghost', full: true });

    return h('div', {},
        banner('warning', 'Write these down now',
            'Closing this popup destroys the only copy. If that happens, remove the recipient '
            + 'from Settings -> Recipients, or new items will be wrapped to a key nobody holds.'),
        eyebrow(`Recovery phrase · ${words.length} words`),
        grid,
        row(
            button('Copy phrase', async () => {
                try {
                    await writeClipboard(res.phrase);
                    toast.ok('Phrase copied. Paste it somewhere offline, then clear the clipboard.');
                } catch (err) { toast.error(`Copy: ${errorText(err)}`); }
            }, {}),
            button('Clear clipboard', async () => {
                await bridge()?.clearClipboard?.();
                toast.info('Clipboard overwritten.');
            }, { variant: 'ghost' })),
        h('div', { class: 'spacer' }),
        eyebrow('Confirm three words'),
        ...checkIdx.map((idx, n) => field(`Word ${idx + 1}`, inputs[n])),
        status,
        done,
        discard,
        h('div', { class: 'hint', text: res.registryEntryId
            ? `Registry entry: ${res.registryEntryId}` : '' }));
}

function pickDistinct(n, k) {
    const pool = Array.from({ length: n }, (_, i) => i);
    const out = [];
    const rand = new Uint32Array(k);
    (globalThis.crypto || {}).getRandomValues?.(rand);
    for (let i = 0; i < k && pool.length > 0; i++) {
        const r = rand[i] === undefined ? Math.floor(Math.random() * pool.length) : rand[i] % pool.length;
        out.push(pool.splice(r, 1)[0]);
    }
    return out.sort((a, b) => a - b);
}

function recoveryUseScreen() {
    const items = allItems().filter(i => i.rage);
    const pick = h('select', { class: 'input' },
        ...items.map(i => h('option', { value: i.id, text: i.name || i.id })));
    const phrase = h('textarea', { class: 'input mono textarea', rows: '3', placeholder: 'your recovery phrase' });
    const out = h('div', {});

    const run = button('Open the item', async () => {
        if (!pick.value) { toast.error('Pick an item.'); return; }
        if (!phrase.value.trim()) { toast.error('Paste your recovery phrase.'); return; }
        run.disabled = true;
        run.textContent = 'Decrypting...';
        clear(out);
        try {
            const value = await need('recoverFromPhrase')(pick.value, phrase.value.trim(), 'password');
            phrase.value = '';
            out.appendChild(h('div', { class: 'secret-open' },
                h('div', { class: 'secret-value mono', text: value }),
                button('Copy', async () => {
                    try {
                        await writeClipboard(value);
                        toast.ok('Copied.');
                    } catch (err) { toast.error(`Copy: ${errorText(err)}`); }
                }, {})));
        } catch (err) {
            out.appendChild(banner('danger', 'Recovery failed', errorText(err)));
        } finally {
            run.disabled = false;
            run.textContent = 'Open the item';
        }
    }, { variant: 'primary', full: true });

    return h('div', { class: 'col' },
        appBar('Recover with a phrase', null, { back: () => go('recovery') }),
        body(
            items.length === 0
                ? banner('warning', 'Nothing to recover', 'No hardware-protected items in this vault.')
                : null,
            field('Item', pick),
            field('Recovery phrase', phrase, 'Never leaves this page; the age identity is derived in WASM.'),
            run,
            out));
}

/* ── folders ────────────────────────────────────────────────────────────── */

function foldersScreen() {
    const name = textInput({ placeholder: 'New folder name' });
    const list = h('div', { class: 'list-sub' });
    for (const f of folders()) {
        const rename = textInput({ value: f.name });
        list.appendChild(h('div', { class: 'srow srow-tall' },
            h('div', { class: 'srow-main' }, rename,
                h('div', { class: 'mono dim', text: `${f.count} item(s)` })),
            button('Rename', async () => {
                if (!rename.value.trim()) { toast.error('Folder name required.'); return; }
                try {
                    await guard('Rename folder', need('renameFolder')(f.id, rename.value.trim()));
                    toast.ok('Renamed.');
                    render();
                } catch {}
            }, {}),
            // Eight pixels from Rename, in the same row, and it was one
            // unguarded tap. Say what survives it -- the folder is a label, not
            // a container, and nothing in it is deleted.
            button('Delete', async () => {
                if (!await confirmAction({
                    title: `Delete the folder "${f.name}"?`,
                    body: `The ${f.count} item(s) in it are not deleted -- they move to no folder `
                        + 'and stay in the vault. Only the folder itself goes.',
                    action: 'Delete folder',
                })) return;
                try {
                    await guard('Delete folder', need('deleteFolder')(f.id));
                    toast.ok('Deleted.');
                    render();
                } catch {}
            }, { variant: 'danger' })));
    }
    if (folders().length === 0) {
        list.appendChild(h('div', { class: 'muted', text: 'No folders.' }));
    }

    return h('div', { class: 'col' },
        appBar('Folders', null, { back: () => go('settings') }),
        body(
            field('Create', name),
            button('Create folder', async () => {
                if (!name.value.trim()) { toast.error('Folder name required.'); return; }
                try {
                    await guard('Create folder', need('createFolder')(name.value.trim()));
                    toast.ok('Created.');
                    render();
                } catch {}
            }, { variant: 'primary', full: true }),
            h('div', { class: 'spacer' }),
            list));
}

/* ── bulk protect ───────────────────────────────────────────────────────── */

/**
 * Back out of bulk-protect to wherever the user actually came from.
 *
 * The back arrow used to be `go(only ? 'detail' : 'settings')`, which inferred
 * the origin from the payload and got it wrong for the commonest entrance: the
 * "Protect" banner on the vault screen passes no payload, so anyone who tapped
 * it was returned to a Settings screen they had never opened.
 */
function bulkBack(payload) {
    const only = payload && payload.only;
    const from = payload && payload.from;
    if (from === 'detail' && only) return () => go('detail', only);
    if (from === 'vault') return () => go('vault');
    if (from === 'settings') return () => go('settings');
    return only ? () => go('detail', only) : () => go('settings');
}

function bulkScreen(payload) {
    const only = payload && payload.only;
    const targets = allItems().filter(i => (only ? i.id === only : !i.rage));
    const coverage = h('div', { class: 'list-sub' });
    const progress = h('div', { class: 'list-sub' });
    let coveredIds = null;

    (async () => {
        clear(coverage);
        coverage.appendChild(h('div', { class: 'muted', text: 'Reading the recipient policy...' }));
        try {
            const [preview, registry] = await Promise.all([
                need('previewEncryptRecipients')(),
                need('listRecipients')(),
            ]);
            const skipped = new Set(preview.skipped.map(s => String(s.id)));
            coveredIds = registry.map(e => String(e.id)).filter(id => !skipped.has(id));
            clear(coverage);
            for (const e of registry) {
                const drop = preview.skipped.find(s => String(s.id) === String(e.id));
                coverage.appendChild(h('div', { class: 'srow' },
                    h('span', { class: `pip ${drop ? 'pip-off' : 'pip-on'}` }),
                    h('span', { class: 'srow-main', text: e.displayName || e.id }),
                    h('span', { class: 'mono dim', text: drop ? drop.reason : 'covered' })));
            }
        } catch (err) {
            clear(coverage);
            coverage.appendChild(banner('danger', 'Recipient policy unavailable', errorText(err)));
        }
    })();

    const onProgress = (ev) => {
        const d = ev.detail || {};
        progress.appendChild(h('div', { class: 'srow' },
            h('span', { class: 'mono dim', text: `${(d.current ?? 0) + 1}/${d.total ?? '?'}` }),
            h('span', { class: 'srow-main', text: itemById(d.cipherId)?.name || d.cipherId || '' }),
            h('span', { class: d.status === 'failed' ? 'mono danger' : 'mono dim',
                text: d.status === 'failed' ? (d.error || 'failed') : d.status })));
        progress.scrollTop = progress.scrollHeight;
    };

    const run = button(`Protect ${targets.length} item${targets.length === 1 ? '' : 's'}`, async () => {
        if (targets.length === 0) { toast.error('Nothing to protect.'); return; }
        run.disabled = true;
        run.textContent = 'Working...';
        clear(progress);
        window.addEventListener('ragewarden:bulk-progress', onProgress);
        try {
            const res = await need('bulkProtect')(coveredIds, targets.map(i => i.id));
            const failed = (res.failed || []).length;
            if (failed > 0) {
                toast.warn(`${res.protected} protected, ${failed} failed. See the list.`);
                for (const f of res.failed) {
                    progress.appendChild(h('div', { class: 'srow' },
                        h('span', { class: 'mono danger', text: 'failed' }),
                        h('span', { class: 'srow-main', text: itemById(f.id)?.name || f.id }),
                        h('span', { class: 'mono dim', text: f.error })));
                }
            } else {
                toast.ok(`${res.protected} item(s) re-wrapped to ${res.recipientsUsed} recipient(s).`);
            }
            if (Array.isArray(res.alsoWrappedTo) && res.alsoWrappedTo.length > 0) {
                toast.info('Also wrapped to: '
                    + res.alsoWrappedTo.map(r => r.displayName || r.id).join(', '));
            }
            render();
        } catch (err) {
            toast.error(`Bulk protect: ${errorText(err)}`);
        } finally {
            window.removeEventListener('ragewarden:bulk-progress', onProgress);
            run.disabled = false;
            run.textContent = `Protect ${targets.length} item${targets.length === 1 ? '' : 's'}`;
        }
    }, { variant: 'primary', full: true });

    return h('div', { class: 'col' },
        appBar('Bulk protect', `${targets.length} target(s)`, { back: bulkBack(payload) }),
        body(
            banner('warning', 'Each item costs a tap',
                'Re-wrapping decrypts and re-encrypts every item, so every item needs its own '
                + 'hardware tap. Do not start this if you cannot stay at the key.'),
            eyebrow('Coverage'),
            coverage,
            eyebrow('Items'),
            h('div', { class: 'list-sub' },
                ...targets.map(i => h('div', { class: 'srow' },
                    h('span', { class: 'srow-main', text: i.name || i.id }),
                    h('span', { class: 'mono dim', text: i.folder || '' })))),
            eyebrow('Progress'),
            progress),
        footer(run));
}

/* ── audit ──────────────────────────────────────────────────────────────── */

function auditScreen() {
    const list = h('div', { class: 'list-sub' });
    (async () => {
        clear(list);
        list.appendChild(h('div', { class: 'muted', text: 'Loading...' }));
        const b = bridge();
        if (!b || !b.audit || typeof b.audit.tail !== 'function') {
            clear(list);
            list.appendChild(banner('danger', 'Unavailable', 'This build exposes no audit log.'));
            return;
        }
        let entries = [];
        try {
            entries = await b.audit.tail(200);
        } catch (err) {
            clear(list);
            list.appendChild(banner('danger', 'Audit log failed', errorText(err)));
            return;
        }
        clear(list);
        if (!entries.length) {
            list.appendChild(h('div', { class: 'muted', text: 'Nothing recorded yet.' }));
            return;
        }
        for (const e of entries) {
            list.appendChild(h('div', { class: 'srow' },
                h('span', { class: 'mono dim', text: relTime(e.recordedAt) }),
                h('span', { class: 'srow-main', text: e.kind }),
                h('span', { class: 'mono dim', text: e.detail || e.target || '' })));
        }
    })();

    // No Clear button. It erased the record of everything this extension had
    // done -- the one thing that would show a user an unexpected tap or an
    // unexpected write -- on a single tap with no confirmation, and an audit log
    // a stranger at your keyboard can wipe is not an audit log.
    return h('div', { class: 'col' },
        appBar('Audit log', 'Local to this browser profile', { back: () => go('settings') }),
        body(list));
}

/* ── chrome plumbing ────────────────────────────────────────────────────── */

function activeTab() {
    return new Promise((resolve, reject) => {
        if (typeof chrome === 'undefined' || !chrome.tabs || !chrome.tabs.query) {
            reject(new Error('chrome.tabs is unavailable -- open the popup from the toolbar'));
            return;
        }
        try {
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                const err = chrome.runtime && chrome.runtime.lastError;
                if (err) reject(new Error(err.message));
                else resolve((tabs && tabs[0]) || null);
            });
        } catch (e) { reject(e); }
    });
}

function sendToTab(tabId, message) {
    return new Promise((resolve, reject) => {
        try {
            chrome.tabs.sendMessage(tabId, message, (resp) => {
                const err = chrome.runtime && chrome.runtime.lastError;
                if (err) reject(new Error(err.message));
                else resolve(resp);
            });
        } catch (e) { reject(e); }
    });
}

/* ── router ─────────────────────────────────────────────────────────────── */

const ROUTES = {
    boot: bootScreen,
    lock: lockScreen,
    vault: vaultScreen,
    detail: () => detailScreen(app.payload),
    edit: () => editScreen(app.payload),
    settings: settingsScreen,
    recipients: recipientsScreen,
    recovery: recoveryScreen,
    'recovery-new': recoveryNewScreen,
    'recovery-use': recoveryUseScreen,
    folders: foldersScreen,
    bulk: () => bulkScreen(app.payload),
    audit: auditScreen,
};

function render() {
    let node;
    try {
        const fn = ROUTES[app.route] || bootScreen;
        node = fn();
    } catch (err) {
        toast.error(errorText(err));
        node = h('div', { class: 'centered' },
            banner('danger', 'This screen failed to render', errorText(err)),
            button('Back to the vault', () => go('vault'), { variant: 'primary', full: true }));
    }
    clear(screenEl);
    screenEl.appendChild(node);
}

function applyInit(state) {
    if (!state) return;
    app.init = state;
    if (app.init.phase === 'ready') {
        if (app.init.mockTap) {
            toast.error(app.init.backendLabel || 'MOCK TAP BUILD -- no device is ever touched.');
        }
        if (app.route === 'boot') go(app.unlocked ? 'vault' : 'lock');
        else render();
    } else {
        go('boot');
    }
}

window.addEventListener('ragewarden:init', ev => applyInit(ev.detail));

/*
 * The glue is a separate module script. If it happens to execute before this
 * one, its `ragewarden:init` event fires with no listener attached, so the
 * popup would sit on the boot screen forever. Poll the state it also parks on
 * `window.RagewardenInit` until it settles.
 */
const initPoll = setInterval(() => {
    const state = window.RagewardenInit;
    if (!state) return;
    if (state === app.init && app.init.phase !== 'starting') { clearInterval(initPoll); return; }
    if (state.phase !== 'starting') {
        clearInterval(initPoll);
        applyInit(state);
    }
}, 200);
setTimeout(() => clearInterval(initPoll), 120_000);

window.addEventListener('ragewarden:vault-updated', () => {
    if (app.route === 'vault') render();
});

/*
 * The console, not the toaster.
 *
 * Every path the user can start already reports its own failure through
 * `guard()` or a local catch, so these handlers only ever caught internal
 * throws -- and turned each one into a sticky red toast of raw internal text
 * that named a function the user has never heard of and offered nothing to do
 * about it. A stack trace belongs where stack traces go.
 */
window.addEventListener('unhandledrejection', (ev) => {
    console.error('ragewarden popup: unhandled rejection', ev.reason);
});
window.addEventListener('error', (ev) => {
    console.error('ragewarden popup: script error', ev.message, ev.error);
});

if (window.RagewardenInit) {
    app.init = window.RagewardenInit;
}
render();

export { app };
