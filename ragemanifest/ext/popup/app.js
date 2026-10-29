/**
 * The Ragewarden popup.
 *
 * Everything on screen here comes from `window.RagewardenVault` (the glue in
 * ../glue/), including the decrypted item list (`items()`, `folders()`). There is no sample data in this
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
import { writeClipboard } from '../glue/clipboard.js';
import { siteMatchesOrigin } from '../glue/origin-match.js';
import { pickDistinct } from './random.js';
import { requestServerPermission } from '../glue/host-permission.js';
import { ITEM_KINDS, fieldLabel, isTypedKind, primaryField } from '../glue/item-types.js';

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

function allItems() {
    const b = bridge();
    return (b && typeof b.items === 'function') ? b.items() : [];
}
function folders() {
    const b = bridge();
    return (b && typeof b.folders === 'function') ? b.folders() : [];
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
                if (ok !== true) throw new Error('wrong master password');
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
                h('div', { class: 'hint', text: 'Checked on this device; no network needed.' })),
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
    const legacy = !!app.init.result?.legacy;
    const input = textInput({ type: 'password', placeholder: 'Master password', mono: true });
    const status = h('div', { class: 'hint hint-danger' });

    const unlock = button('Unlock', async () => {
        status.textContent = '';
        let doUnlock;
        try {
            doUnlock = need('unlock');
        } catch (err) {
            status.textContent = errorText(err);
            return;
        }
        if (!input.value) { status.textContent = 'Enter your master password.'; return; }
        unlock.disabled = true;
        unlock.textContent = 'Unlocking...';
        try {
            const r = await doUnlock(input.value);
            input.value = '';
            app.unlocked = true;
            if (r && r.offline) toast.warn(`Unlocked, but the vault could not be fetched: ${r.offline}`);
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
        h('div', { class: 'muted', text: email ? `Locked · ${email}` : 'Locked' }),
        field('Master password', input),
        status,
        legacy
            ? h('div', { class: 'hint', text: 'This one unlock is checked with your server; later unlocks work offline.' })
            : h('div', { class: 'hint', text: 'Unlocks on this device; no network needed.' }),
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

/**
 * What the next tap authorizes, on screen before the authenticator is asked:
 * the action, the item and where the secret goes. A mock build says so on the
 * same line.
 */
function ceremonyBlock(action, item, destination) {
    const mock = !!bridge()?.hardware?.isMock?.();
    return h('div', { class: 'ceremony', role: 'status', 'aria-live': 'polite' },
        h('div', { class: 'ceremony-action', text: `${action} ${item.name || '(unnamed)'}` }),
        h('div', { class: 'ceremony-dest mono', text: `to ${destination}` }),
        h('div', { class: 'muted', text: `${mock ? 'MOCK TAP -- no device is touched. ' : ''}`
            + 'Tap your key to authorize exactly this.' }));
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
        const scoped = !qq && !app.folder && app.tabOrigin
            ? rows.filter(it => siteMatchesOrigin(it.site, app.tabOrigin)) : [];
        if (scoped.length > 0) {
            host.appendChild(eyebrow(`For this site · ${app.tabHost}`));
            for (const it of scoped) host.appendChild(vaultRow(it));
            host.appendChild(eyebrow('All items'));
        }
        for (const it of rows) if (!scoped.includes(it)) host.appendChild(vaultRow(it));
    }

    const list = h('div', { class: 'list', id: 'vault-list' });
    renderList(list);
    if (app.tabOrigin === undefined) {
        app.tabOrigin = null;
        activeTab().then((tab) => {
            if (!tab || !/^https?:/.test(tab.url || '')) return;
            const url = new URL(tab.url);
            app.tabOrigin = url.origin;
            app.tabHost = url.hostname;
            const host = document.getElementById('vault-list');
            if (host) renderList(host);
        }).catch(() => {});
    }

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
        app.init.hostPermissionMissing
            ? h('div', { class: 'pad-x' }, banner('warning',
                'Ragewarden cannot reach your server',
                `Allow access to ${app.init.hostPermissionMissing} so the vault can sync.`,
                { label: 'Allow', onClick: () => {
                    requestServerPermission(app.init.hostPermissionMissing)
                        .then(() => location.reload())
                        .catch(err => toast.error(errorText(err)));
                } }))
            : null,
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
            h('div', { class: 'vrow-sub', text: [it.username, it.site].filter(Boolean).join(' · ')
                || ((ITEM_KINDS[it.kind] && ITEM_KINDS[it.kind].label) || it.kind || '') })),
        it.rage ? null : h('span', { class: 'tag', text: 'plain' }),
        it.legacyWrap ? h('span', { class: 'tag', text: 're-save' }) : null);
}

function detailScreen(id) {
    const item = itemById(id);
    if (!item) {
        return h('div', { class: 'col' },
            appBar('Item', null, { back: () => go('vault') }),
            body(banner('danger', 'Gone', 'This item is no longer in the vault snapshot.')));
    }

    const stoppers = [];
    const stopAll = () => { for (const stop of stoppers) stop(); };

    /*
     * One secret field: Reveal, Copy (and Autofill for a login's password) each
     * run their own ceremony for exactly this field, and a revealed value hides
     * itself. A card or an SSH key has several of these on one screen.
     */
    function secretField(fieldName, label, opts = {}) {
        const secretHost = h('div', { class: 'secret-host' });
        let tickTimer = null;

        function stopTicker() {
            if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
        }

        function idleSecret() {
            stopTicker();
            clear(secretHost);
            secretHost.appendChild(h('div', { class: 'secret-idle' },
                h('span', { class: 'mono dim', text: '••••••••••••' })));
        }

        async function doReveal() {
            clear(secretHost);
            secretHost.appendChild(ceremonyBlock('Reveal', item, 'this screen'));
            let value;
            try {
                value = await need('revealPassword')(item.id, fieldName);
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
                            await need('copySecret')(value);
                            toast.ok('Copied. The clipboard is cleared in 30 seconds.');
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
            secretHost.appendChild(ceremonyBlock('Copy', item, 'the clipboard'));
            let res;
            try {
                res = await need('copyPassword')(item.id, fieldName);
            } catch (err) {
                toast.error(`Copy: ${errorText(err)}`);
                idleSecret();
                return;
            }
            toast.ok(`Copied ${res && res.chars ? `${res.chars} characters` : `the ${label.toLowerCase()}`} to the clipboard.`);
            const clearAt = (res && res.clearAt) || (Date.now() + 30_000);
            const label = h('span', { class: 'mono dim' });
            const paint = () => {
                const left = Math.max(0, Math.round((clearAt - Date.now()) / 1000));
                label.textContent = left > 0 ? `clipboard cleared in ${left}s` : 'clipboard cleared';
                if (left <= 0) idleSecret();
            };
            clear(secretHost);
            secretHost.appendChild(h('div', { class: 'secret-open' },
                h('div', { class: 'muted', text: `The ${label.toLowerCase()} is on your clipboard. It was never rendered here.` }),
                row(button('Clear now', async () => {
                    stopTicker();
                    await bridge()?.clearClipboard?.();
                    toast.info('Clipboard overwritten.');
                    idleSecret();
                }, {}), label)));
            paint();
            tickTimer = setInterval(paint, 1000);
        }

        async function doAutofill() {
            let tab = null;
            try {
                tab = await activeTab();
            } catch (err) {
                toast.error(`Autofill: ${errorText(err)}`);
                return;
            }
            let origin = '';
            try { origin = new URL(tab && tab.url).origin; } catch { origin = ''; }
            if (!tab || !origin || origin === 'null') {
                toast.error('Autofill: the active tab has no web origin to fill.');
                return;
            }
            if (!siteMatchesOrigin(item.site, origin)) {
                const ok = await confirmAction({
                    title: 'Fill into a different site?',
                    body: item.site
                        ? `"${item.name}" is saved for ${item.site}. The active tab is ${origin}. `
                          + 'Filling it there sends this password to a site it was not saved for.'
                        : `"${item.name}" has no site saved. The active tab is ${origin}.`,
                    action: `Fill ${new URL(origin).host}`,
                });
                if (!ok) return;
            }
            clear(secretHost);
            secretHost.appendChild(ceremonyBlock('Autofill', item, origin));
            let value;
            try {
                value = await need('autofillPassword')(item.id, origin);
            } catch (err) {
                toast.error(`Autofill: ${errorText(err)}`);
                idleSecret();
                return;
            }
            try {
                const resp = await sendToTab(tab.id, {
                    kind: 'ragewarden.fill',
                    expectedOrigin: origin,
                    username: item.username || '',
                    password: value,
                });
                if (!resp || !resp.ok) throw new Error((resp && resp.error) || 'the page did not accept the fill');
                toast.ok(`Filled ${resp.host || origin}.`);
            } catch (err) {
                toast.error(`Autofill: ${errorText(err)}`);
            } finally {
                value = '';
                idleSecret();
            }
        }

        idleSecret();
        stoppers.push(stopTicker);
        return field(label, h('div', { 'data-field': fieldName },
            secretHost,
            row(
                opts.autofill ? button('Autofill', doAutofill, { variant: 'primary' }) : null,
                button('Copy', doCopy),
                button('Reveal', doReveal),
                item.protectedFields.includes(fieldName) ? h('span', { class: 'tag', text: 'protected' }) : null)));
    }

    function plainReadout(label, value, opts = {}) {
        return field(label, h('div', { class: 'readout' },
            h('span', { class: opts.wrap ? 'mono wrap' : 'mono', text: value }),
            button('Copy', async () => {
                try {
                    await writeClipboard(value);
                    toast.ok(`${label} copied.`);
                } catch (err) { toast.error(`Copy: ${errorText(err)}`); }
            }, { variant: 'ghost' })));
    }

    /* A card, identity or SSH key: descriptive fields read with no tap, secrets behind a ceremony. */
    function typedFields() {
        const spec = ITEM_KINDS[item.kind];
        const host = h('div', { class: 'col' });
        const plainHosts = new Map();
        for (const f of spec.fields) {
            if (f.secret || item.protectedFields.includes(f.name)) {
                host.appendChild(secretField(f.name, f.label));
            } else {
                const slot = h('div', {});
                plainHosts.set(f.name, slot);
                host.appendChild(slot);
            }
        }
        need('itemDetails')(item.id).then((values) => {
            for (const f of spec.fields) {
                const slot = plainHosts.get(f.name);
                if (slot && values && values[f.name]) slot.appendChild(plainReadout(f.label, values[f.name], { wrap: !!f.multiline }));
            }
        }).catch(err => toast.error(`Details: ${errorText(err)}`));
        return host;
    }

    /* Protected fields this screen does not lay out itself (written by another client). */
    function otherProtected(shown) {
        return item.protectedFields
            .filter(n => !shown.includes(n))
            .map(n => secretField(n, fieldLabel(item.kind, n)));
    }

    const historyHost = h('div', { class: 'list-sub' });
    loadHistory(item.id, historyHost);

    const totpHost = h('div', {});
    let totpTimer = null;
    const idleTotp = () => {
        if (totpTimer) { clearInterval(totpTimer); totpTimer = null; }
        clear(totpHost);
    };
    async function doTotp() {
        idleTotp();
        totpHost.appendChild(ceremonyBlock('Show the TOTP code of', item, 'this screen'));
        let res;
        try {
            res = await need('totpCode')(item.id);
        } catch (err) {
            toast.error(`TOTP: ${errorText(err)}`);
            idleTotp();
            return;
        }
        let left = Math.max(1, Math.round(res.secondsRemaining || 0));
        const countdown = h('span', { class: 'mono dim', text: `${left}s` });
        clear(totpHost);
        totpHost.appendChild(h('div', { class: 'secret-open' },
            h('div', { class: 'secret-value mono totp-code', text: res.code }), countdown));
        totpTimer = setInterval(() => {
            left -= 1;
            countdown.textContent = `${left}s`;
            if (left <= 0) idleTotp();
        }, 1000);
    }

    return h('div', { class: 'col' },
        appBar(item.name || '(unnamed)', item.site || item.folder || '', {
            back: () => { stopAll(); idleTotp(); go('vault'); },
            // stopAll here too: leaving via Edit used to leave the reveal
            // countdown ticking against a detached node, so a later render
            // could be clobbered by a timer belonging to a screen that is gone.
            actions: [button('✎', () => { stopAll(); go('edit', { id: item.id }); },
                { variant: 'icon', title: 'Edit' })],
        }),
        body(
            item.legacyWrap
                ? banner('warning', 'Older wrapping',
                    'This item was wrapped before every secret got its own salt. Re-save it to wrap '
                    + 'it again in the current format (one tap to open it, one to write it).',
                    { label: 'Re-save', onClick: async () => {
                        try {
                            await guard('Re-save', need('rotateCipher')(item.id));
                            toast.ok('Re-saved in the current format.');
                            render();
                        } catch {}
                    } })
                : null,
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
            ...(isTypedKind(item.kind)
                ? [typedFields(), ...otherProtected(ITEM_KINDS[item.kind].fields.map(f => f.name))]
                // A note's body is its secret (how rageterm stores one), so it
                // reads, fills and yields a TOTP code like a login's password.
                : [
                    secretField(primaryField(item.kind), 'Password', { autofill: true }),
                    ...otherProtected([primaryField(item.kind), 'totp']),
                    field('One-time code', h('div', {},
                        totpHost,
                        row(button('Show TOTP code', doTotp, { variant: item.hasTotp ? 'primary' : 'secondary' })))),
                ]),
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
        const tags = Array.isArray(e.stanzaTags) && e.stanzaTags.length ? ` · ${e.stanzaTags.join(', ')}` : '';
        host.appendChild(h('div', { class: 'srow', 'data-history': e.deleted ? 'deletion' : 'revision' },
            h('span', { class: 'mono dim', text: relTime(e.recordedAt) }),
            h('span', { text: `${e.deleted ? 'deleted' : 'earlier secret'}${tags}` })));
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
        ...Object.entries(ITEM_KINDS).map(([k, spec]) => h('option', { value: k, text: spec.label })));
    if (existing) type.value = ITEM_KINDS[existing.kind] ? existing.kind : 'note';
    const username = textInput({ value: existing ? (existing.username || '') : '', placeholder: 'you@example.com' });
    const site = textInput({ value: existing ? (existing.site || '') : '', placeholder: 'https://example.com' });
    const folder = h('select', { class: 'input' },
        h('option', { value: '', text: 'No folder' }),
        ...folders().filter(f => f.id).map(f => h('option', { value: f.id, text: f.name })));
    folder.value = (existing && existing.folderId) || '';
    const kind = () => type.value;
    const isLogin = () => kind() === 'login';

    /*
     * A card, identity or SSH key: one input per field and a Protect toggle.
     * Protected and secret fields start blank (blank keeps what is stored);
     * the rest are filled from the item with no tap.
     */
    const typedInputs = new Map();
    function typedForm(k) {
        typedInputs.clear();
        const wasProtected = existing ? existing.protectedFields : null;
        const rows = ITEM_KINDS[k].fields.map((f) => {
            const sealed = wasProtected ? wasProtected.includes(f.name) : !!f.protect;
            const keep = !creating && (f.secret || sealed);
            const input = f.multiline
                ? h('textarea', { class: 'input mono textarea', rows: '4' })
                : textInput({ mono: !!f.secret });
            input.placeholder = keep ? 'blank keeps the stored value' : '';
            const protect = h('input', { type: 'checkbox', checked: sealed, 'aria-label': `Protect ${f.label}` });
            typedInputs.set(f.name, { input, protect });
            return h('div', { class: 'field', 'data-edit-field': f.name },
                h('span', { class: 'eyebrow', text: f.label }),
                input,
                h('label', { class: 'row hint' }, protect, h('span', { text: 'Protect with your keys' })));
        });
        if (existing) {
            need('itemDetails')(existing.id).then((values) => {
                for (const [n, { input }] of typedInputs) {
                    if (values && typeof values[n] === 'string' && !input.value) input.value = values[n];
                }
            }).catch(err => toast.error(`Details: ${errorText(err)}`));
        }
        return rows;
    }

    const generators = row(
        button('Generate password', async () => {
            try { secret.value = await need('generatePassword')({ length: 20 }); } catch (err) {
                toast.error(`Generate: ${errorText(err)}`);
            }
        }, { variant: 'ghost' }),
        button('Generate passphrase', async () => {
            try { secret.value = await need('generatePassphrase')({ words: 6, separator: '-' }); } catch (err) {
                toast.error(`Generate: ${errorText(err)}`);
            }
        }, { variant: 'ghost' }));
    const multiField = existing && !isTypedKind(existing.kind)
        && existing.protectedFields.some(n => n !== (existing.kind === 'note' ? 'notes' : 'password'));

    const kindHost = h('div', { class: 'col' });
    function renderKind() {
        clear(kindHost);
        if (isTypedKind(kind())) {
            for (const r of typedForm(kind())) kindHost.appendChild(r);
            return;
        }
        if (isLogin()) {
            kindHost.appendChild(field('Username', username));
            kindHost.appendChild(field('Site', site));
        }
        if (multiField) {
            kindHost.appendChild(banner('info', 'Several protected fields',
                `This item protects ${existing.protectedFields.join(', ')}. It was written by another `
                + 'client; a new secret here would replace them all, so this screen only renames it.'));
            return;
        }
        kindHost.appendChild(generators);
        kindHost.appendChild(field('Secret', secret, creating
            ? 'Stored wrapped. Reading it back always costs a hardware tap.'
            : 'Blank keeps the stored secret and needs no tap. A new secret is wrapped to '
              + 'your current recipients; the old one is kept in the item\'s history.'));
    }
    type.addEventListener('change', renderKind);
    renderKind();

    const coverage = h('div', { class: 'list-sub' });
    renderCoverage(coverage);

    async function saveTyped() {
        const values = {};
        const protect = [];
        for (const [n, { input, protect: box }] of typedInputs) {
            values[n] = input.value;
            if (box.checked) protect.push(n);
        }
        const saved = await guard('Save', need('saveItem')(existing ? existing.id : null, {
            kind: kind(), name: name.value.trim(), values, protect,
            folderId: creating ? (folder.value || null) : null,
        }));
        for (const { input } of typedInputs.values()) input.value = '';
        return saved;
    }

    const save = button(creating ? 'Create' : 'Save', async () => {
        if (!name.value.trim()) { toast.error('Give the item a name.'); return; }
        if (creating && !isTypedKind(kind()) && !secret.value) { toast.error('Enter the secret to store.'); return; }
        save.disabled = true;
        save.textContent = 'Encrypting...';
        try {
            if (isTypedKind(kind())) {
                const saved = await saveTyped();
                const id = existing ? existing.id : (saved && (saved.id || saved.Id));
                if (existing && folder.value !== (existing.folderId || '')) {
                    await guard('Folder', need('setFolder')(existing.id, folder.value || null));
                }
                toast.ok(creating ? 'Created.' : 'Saved.');
                go('detail', id);
            } else if (creating) {
                const saved = await guard('Create', need('setCipher')(
                    name.value.trim(), secret.value, {
                        type: kind(),
                        ...(isLogin() ? { username: username.value.trim(), site: site.value.trim() } : {}),
                    }));
                secret.value = '';
                const newId = saved && (saved.id || saved.Id);
                if (newId && folder.value) await guard('Folder', need('setFolder')(newId, folder.value));
                toast.ok('Created and wrapped.');
                go('detail', newId);
            } else {
                /*
                 * Not trimmed and not coerced: a secret may legitimately begin
                 * or end in whitespace, and only a genuinely empty box means
                 * "keep it". `editCipher` takes null as "keep what is stored",
                 * so a rename does not need the plaintext.
                 */
                const replacement = secret.value.length > 0 ? secret.value : null;
                await guard('Save', need('editCipher')(existing.id, name.value.trim(), replacement,
                    isLogin() ? { username: username.value.trim(), site: site.value.trim() } : {}));
                if (folder.value !== (existing.folderId || '')) {
                    await guard('Folder', need('setFolder')(existing.id, folder.value || null));
                }
                secret.value = '';
                toast.ok(replacement === null ? 'Saved.' : 'Saved and re-wrapped.');
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
            creating ? field('Type', type) : null,
            kindHost,
            field('Folder', folder),
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
            button('Lock', async () => {
                try { await need('lock')(); } catch (err) { toast.error(`Lock: ${errorText(err)}`); }
                app.unlocked = false;
                go('lock');
            }, { variant: 'secondary', full: true }),
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
    let stale = new Set();
    try {
        stale = new Set((await need('staleBrowserRecipients')()).map(e => e.id));
    } catch {}
    if (stale.size > 0) {
        host.appendChild(banner('warning',
            `${stale.size} browser recipient${stale.size === 1 ? '' : 's'} not held by this browser`,
            'New items are still wrapped to them. If they belonged to an earlier install of this '
            + 'browser, remove them; if another browser holds them, keep them.'));
    }
    for (const e of entries) {
        host.appendChild(h('div', { class: 'srow srow-tall' },
            h('div', { class: 'srow-main' },
                h('div', { text: e.displayName || e.id }),
                h('div', { class: 'mono dim', text: `${e.kind} · ${e.id}` }),
                stale.has(String(e.id))
                    ? h('div', { class: 'mono dim', text: 'no key for this on this browser' })
                    : null,
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

function recoveryNewScreen() {
    const host = h('div', {});
    const bar = h('div', {}, appBar('New recovery phrase', null, { back: () => go('recovery') }));
    const start = button('Generate a phrase', async () => {
        start.disabled = true;
        start.textContent = 'Generating...';
        let res;
        try {
            res = await need('generateRecovery')();
        } catch (err) {
            toast.error(`Recovery phrase: ${errorText(err)}`);
            start.disabled = false;
            start.textContent = 'Generate a phrase';
            return;
        }
        if (!res || typeof res.phrase !== 'string' || res.phrase.trim().length === 0) {
            toast.error('The recovery generator returned no phrase.');
            start.disabled = false;
            start.textContent = 'Generate a phrase';
            return;
        }
        clear(bar);
        bar.appendChild(appBar('New recovery phrase', null, {}));
        clear(host);
        host.appendChild(phrasePanel(res));
    }, { variant: 'primary', full: true });

    host.appendChild(h('div', {},
        h('div', { class: 'hint', text:
            'Generated in WASM. Nothing is published until you confirm three of the words; '
            + 'then only the public key is.' }),
        start));

    return h('div', { class: 'col' }, bar, body(host));
}

/**
 * The words of a phrase that is not published yet. The recipient reaches the
 * registry only from the confirm handler, after three words match, so closing
 * the popup at any point before that leaves nothing behind.
 */
function phrasePanel(res) {
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
    const panel = h('div', {});

    const done = button('I have written it down', async () => {
        const wrong = checkIdx.filter((idx, n) =>
            inputs[n].value.trim().toLowerCase() !== words[idx].toLowerCase());
        if (wrong.length > 0) {
            status.textContent = `Word ${wrong.map(i => i + 1).join(', ')} does not match. `
                + 'Check the copy you wrote down.';
            return;
        }
        status.textContent = '';
        done.disabled = true;
        done.textContent = 'Publishing...';
        let published;
        try {
            published = await need('publishRecovery')(res.armoredPubkey, 'Paper recovery');
        } catch (err) {
            toast.error(`Publish recovery: ${errorText(err)}`);
            done.disabled = false;
            done.textContent = 'I have written it down';
            return;
        }
        clear(panel);
        panel.appendChild(h('div', {},
            banner('success', 'Recovery phrase published',
                'New items are wrapped to it from now on. Earlier phrases stay valid recipients '
                + 'until you remove them in Settings -> Recipients.'),
            h('div', { class: 'hint', text: published && published.registryEntryId
                ? `Registry entry: ${published.registryEntryId}` : '' }),
            button('Test it now', () => go('recovery-use', { test: true }), { variant: 'primary', full: true }),
            button('Done', () => go('settings'), { variant: 'ghost', full: true })));
        toast.ok('Recovery phrase verified and published.');
    }, { variant: 'primary', full: true });

    const discard = button('Discard these words', async () => {
        if (!await confirmAction({
            title: 'Discard this phrase?',
            body: 'Nothing has been published yet, so discarding leaves your vault unchanged.',
            action: 'Discard',
        })) return;
        go('recovery');
    }, { variant: 'ghost', full: true });

    panel.appendChild(h('div', {},
        banner('warning', 'Write these down on paper',
            'Do not copy, photograph or type them anywhere. They are published only after you '
            + 'confirm three of them below.'),
        eyebrow(`Recovery phrase · ${words.length} words`),
        grid,
        h('div', { class: 'spacer' }),
        eyebrow('Confirm three words'),
        ...checkIdx.map((idx, n) => field(`Word ${idx + 1}`, inputs[n])),
        status,
        done,
        discard));
    return panel;
}

function recoveryUseScreen(payload) {
    const items = allItems().filter(i => i.rage);
    const pick = h('select', { class: 'input' },
        ...items.map(i => h('option', { value: i.id, text: i.name || i.id })));
    const phrase = h('textarea', { class: 'input mono textarea', rows: '3', placeholder: 'your recovery phrase' });
    const out = h('div', {});
    let hideTimer = null;
    const hide = () => {
        if (hideTimer) { clearInterval(hideTimer); hideTimer = null; }
        clear(out);
    };

    const run = button('Open the item', async () => {
        if (!pick.value) { toast.error('Pick an item.'); return; }
        if (!phrase.value.trim()) { toast.error('Type your recovery phrase.'); return; }
        run.disabled = true;
        run.textContent = 'Decrypting...';
        hide();
        try {
            let value = await need('recoverFromPhrase')(pick.value, phrase.value.trim());
            phrase.value = '';
            let left = 10;
            const countdown = h('span', { class: 'mono dim', text: `hides in ${left}s` });
            out.appendChild(h('div', { class: 'secret-open' },
                h('div', { class: 'secret-value mono', text: value }),
                row(
                    button('Copy', async () => {
                        try {
                            await need('copySecret')(value);
                            toast.ok('Copied. The clipboard is cleared in 30 seconds.');
                        } catch (err) { toast.error(`Copy: ${errorText(err)}`); }
                    }, {}),
                    button('Hide', () => { value = ''; hide(); }, { variant: 'ghost' }),
                    countdown)));
            hideTimer = setInterval(() => {
                left -= 1;
                countdown.textContent = `hides in ${left}s`;
                if (left <= 0) { value = ''; hide(); }
            }, 1000);
        } catch (err) {
            out.appendChild(banner('danger', 'Recovery failed', errorText(err)));
        } finally {
            run.disabled = false;
            run.textContent = 'Open the item';
        }
    }, { variant: 'primary', full: true });

    return h('div', { class: 'col' },
        appBar(payload && payload.test ? 'Test your paper backup' : 'Recover with a phrase', null,
            { back: () => { hide(); go('recovery'); } }),
        body(
            payload && payload.test
                ? banner('info', 'Type the phrase from your paper',
                    'Opening any protected item proves the copy you wrote down works.')
                : null,
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
            banner('info', 'One tap for the whole batch',
                'Your key is tapped once to open this browser\'s identity; every item is then '
                + 're-wrapped with it. An item that identity cannot open asks for its own tap.'),
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
            chrome.tabs.sendMessage(tabId, message, { frameId: 0 }, (resp) => {
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
    'recovery-use': () => recoveryUseScreen(app.payload),
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
        app.unlocked = !state.locked;
        if (app.route === 'boot' || (!app.unlocked && app.route !== 'lock')) go(app.unlocked ? 'vault' : 'lock');
        else render();
    } else {
        go('boot');
    }
}

window.addEventListener('ragewarden:init', ev => applyInit(ev.detail));
window.addEventListener('ragewarden:locked', () => {
    app.unlocked = false;
    if (app.route !== 'lock') go('lock');
});

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
