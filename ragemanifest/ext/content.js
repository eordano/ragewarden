const BUILD_FLAGS = Object.freeze(Object.assign(
    { profile: 'release', allowMockTap: false, forceMockTap: false, testHooks: false },
    (typeof globalThis !== 'undefined' && globalThis.__RAGEWARDEN_BUILD_FLAGS) || {},
));

const HOST_ID = 'ragewarden-content-host';
const CHIP_TAG = 'ragewarden-autofill-chip';
const PROMPT_TAG = 'ragewarden-autofill-prompt';
const AUTOFILL_KEYSTROKE_DELAY_MS = 12;

const state = {
    host: null,
    shadow: null,
    chipEl: null,
    promptEl: null,
    activeField: null,
    matches: [],
    origin: location.origin,
    domain: location.hostname,
    chipBound: false,
    debounceTimer: null,
    pendingFill: null,
};

function targetStillValid(el, mustBePassword) {
    if (!el || !el.isConnected) return false;
    if (el.ownerDocument !== document) return false;
    if (el.tagName !== 'INPUT') return false;
    if (el.disabled || el.readOnly) return false;
    if (mustBePassword && !isPasswordField(el)) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return false;
    try {
        const st = getComputedStyle(el);
        if (st.visibility === 'hidden' || st.display === 'none') return false;
        if (Number(st.opacity) < 0.1) return false;
    } catch {}
    return true;
}

function isPasswordField(el) {
    return el && el.tagName === 'INPUT' && (el.type || '').toLowerCase() === 'password';
}

function isLikelyUsernameField(el) {
    if (!el || el.tagName !== 'INPUT') return false;
    const type = (el.type || '').toLowerCase();
    if (type === 'email') return true;
    const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
    if (ac === 'username' || ac === 'email') return true;
    const haystacks = [el.name, el.id, el.placeholder, ariaOrLabel(el)].filter(Boolean).map(s => s.toLowerCase());
    return haystacks.some(s => /(user|email|login|account)/.test(s));
}

function ariaOrLabel(el) {
    const aria = el.getAttribute('aria-label');
    if (aria) return aria;
    if (el.id) {
        const lbl = document.querySelector(`label[for="${cssEscape(el.id)}"]`);
        if (lbl && lbl.textContent) return lbl.textContent;
    }
    let parent = el.parentElement;
    let depth = 0;
    while (parent && depth < 3) {
        if (parent.tagName === 'LABEL' && parent.textContent) return parent.textContent;
        parent = parent.parentElement;
        depth += 1;
    }
    return '';
}

function cssEscape(s) {
    if (window.CSS && typeof window.CSS.escape === 'function') return window.CSS.escape(s);
    return String(s).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
}

function findCredentialPair(focusedEl) {
    let usernameEl = null;
    let passwordEl = null;
    if (isPasswordField(focusedEl)) {
        passwordEl = focusedEl;
        usernameEl = findSiblingUsername(focusedEl);
    } else if (isLikelyUsernameField(focusedEl)) {
        usernameEl = focusedEl;
        passwordEl = findSiblingPassword(focusedEl);
    }
    return { usernameEl, passwordEl };
}

function findSiblingUsername(passwordEl) {
    const form = passwordEl.form || document;
    const inputs = form.querySelectorAll('input');
    let last = null;
    for (const i of inputs) {
        if (i === passwordEl) return last;
        if (isLikelyUsernameField(i)) last = i;
    }
    return last;
}

function findSiblingPassword(usernameEl) {
    const form = usernameEl.form || document;
    const inputs = form.querySelectorAll('input');
    let seen = false;
    for (const i of inputs) {
        if (i === usernameEl) { seen = true; continue; }
        if (seen && isPasswordField(i)) return i;
    }
    for (const i of inputs) if (isPasswordField(i)) return i;
    return null;
}

function ensureShadowHost() {
    if (state.host && state.host.isConnected) return state.shadow;
    const host = document.createElement('div');
    host.id = HOST_ID;
    host.setAttribute('aria-hidden', 'true');
    host.style.cssText = 'all: initial; position: absolute; top: 0; left: 0; z-index: 2147483646; pointer-events: none;';
    const shadow = host.attachShadow({ mode: 'closed' });
    const style = document.createElement('style');
    style.textContent = SHADOW_CSS;
    shadow.appendChild(style);
    if (document.body) {
        document.body.appendChild(host);
    } else {
        document.documentElement.appendChild(host);
    }
    state.host = host;
    state.shadow = shadow;
    return shadow;
}

const SHADOW_CSS = `
:host { all: initial; }
.chip {
    position: fixed;
    z-index: 2147483647;
    pointer-events: auto;
    background: #1d1d1d;
    color: #faf6ee;
    border: 1px solid #2c2c2c;
    border-radius: 8px;
    padding: 4px 10px 4px 8px;
    font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
    font-size: 12px;
    line-height: 18px;
    cursor: pointer;
    box-shadow: 0 4px 14px rgba(0,0,0,0.35);
    display: inline-flex;
    align-items: center;
    gap: 6px;
    user-select: none;
}
.chip:hover { background: #2a2a2a; }
.chip-dot { width: 8px; height: 8px; border-radius: 50%; background: #6a8fff; }
.chip-label { font-weight: 500; letter-spacing: 0.01em; }
.chip-meta { opacity: 0.65; font-size: 11px; }
.prompt-backdrop {
    position: fixed; inset: 0; z-index: 2147483647;
    background: rgba(0,0,0,0.55);
    pointer-events: auto;
    display: flex; align-items: center; justify-content: center;
    font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
}
.prompt-card {
    background: #1d1d1d;
    color: #faf6ee;
    border: 1px solid #2c2c2c;
    border-radius: 12px;
    padding: 22px 20px 18px;
    width: min(360px, 92vw);
    box-shadow: 0 24px 60px rgba(0,0,0,0.5);
}
.prompt-title {
    font-size: 16px; font-weight: 600; margin: 0 0 6px;
}
.prompt-domain {
    font-family: ui-monospace, "SF Mono", Menlo, monospace;
    color: #6a8fff;
    word-break: break-all;
}
.prompt-sub {
    font-size: 12px; opacity: 0.72; margin: 4px 0 18px;
}
.prompt-actions {
    display: flex; gap: 10px; justify-content: flex-end;
}
.prompt-btn {
    border-radius: 8px;
    border: 1px solid #2c2c2c;
    background: #121212;
    color: #faf6ee;
    padding: 8px 14px;
    font-size: 13px;
    cursor: pointer;
    font-family: inherit;
}
.prompt-btn-primary {
    background: #6a8fff;
    color: #0e0e16;
    border-color: #6a8fff;
    font-weight: 600;
}
.prompt-btn:disabled { opacity: 0.6; cursor: default; }
.prompt-status { margin-top: 10px; font-size: 12px; opacity: 0.7; min-height: 16px; }
`;

function showChip(field, match) {
    const shadow = ensureShadowHost();
    if (state.chipEl) state.chipEl.remove();
    const chip = document.createElement('div');
    chip.className = 'chip';
    chip.setAttribute('data-ragewarden-chip', '1');
    chip.setAttribute('role', 'button');
    chip.setAttribute('tabindex', '0');
    chip.setAttribute('aria-label', `Ragewarden autofill into ${state.domain}`);
    const dot = document.createElement('span');
    dot.className = 'chip-dot';
    const label = document.createElement('span');
    label.className = 'chip-label';
    label.textContent = 'ragewarden';
    const meta = document.createElement('span');
    meta.className = 'chip-meta';
    meta.textContent = match.name || state.domain;
    chip.append(dot, label, meta);
    positionChip(chip, field);
    chip.addEventListener('click', onChipClick);
    chip.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onChipClick(); }
    });
    shadow.appendChild(chip);
    state.chipEl = chip;
    state.activeField = field;
}

function positionChip(chip, field) {
    const r = field.getBoundingClientRect();
    chip.style.top = `${Math.max(4, r.top - 28)}px`;
    chip.style.left = `${r.right - 110}px`;
}

function hideChip() {
    if (state.chipEl) {
        state.chipEl.remove();
        state.chipEl = null;
    }
}

async function onChipClick() {
    const match = state.matches[0];
    if (!match) return;
    const { usernameEl, passwordEl } = findCredentialPair(state.activeField)
        || { usernameEl: null, passwordEl: null };
    state.pendingFill = {
        usernameEl,
        passwordEl,
        origin: location.origin,
        href: location.href,
        at: Date.now(),
    };
    showPromptSheet(match);
}

function showPromptSheet(match) {
    const shadow = ensureShadowHost();
    if (state.promptEl) state.promptEl.remove();
    const backdrop = document.createElement('div');
    backdrop.className = 'prompt-backdrop';
    backdrop.setAttribute('data-ragewarden-prompt', '1');
    const card = document.createElement('div');
    card.className = 'prompt-card';
    const title = document.createElement('h2');
    title.className = 'prompt-title';
    title.setAttribute('data-ragewarden-action', 'autofill');
    const dom = document.createElement('span');
    dom.className = 'prompt-domain';
    dom.textContent = state.domain;
    title.append(document.createTextNode('Autofill into '), dom, document.createTextNode('?'));
    const sub = document.createElement('div');
    sub.className = 'prompt-sub';
    sub.textContent = match.rage
        ? 'Continue opens a separate Ragewarden window, outside this page, where you tap '
          + 'your security key to decrypt this item for one fill.'
        : 'This item is NOT hardware-encrypted. Continue opens a separate Ragewarden '
          + 'window, outside this page, where you tap your security key to authorize '
          + 'releasing it for one fill.';
    const actions = document.createElement('div');
    actions.className = 'prompt-actions';
    const cancel = document.createElement('button');
    cancel.className = 'prompt-btn';
    cancel.type = 'button';
    cancel.textContent = 'Cancel';
    const go = document.createElement('button');
    go.className = 'prompt-btn prompt-btn-primary';
    go.type = 'button';
    go.setAttribute('data-ragewarden-confirm', '1');
    go.textContent = 'Continue';
    const status = document.createElement('div');
    status.className = 'prompt-status';
    status.setAttribute('data-ragewarden-status', '1');
    actions.append(cancel, go);
    card.append(title, sub, actions, status);
    backdrop.appendChild(card);
    shadow.appendChild(backdrop);
    state.promptEl = backdrop;
    /*
     * A hardware tap is spent the instant it happens, so nothing may throw the
     * result of one away behind the user's back.
     *
     * Dismissing the backdrop mid-ceremony used to be allowed: the go-handler
     * disables the two buttons but the backdrop kept its listener, and one
     * stray click ran closePromptSheet(), which nulls state.pendingFill and
     * detaches this card. The unlock kept running to completion -- the user
     * really tapped, the worker really settled ok with plaintext, the release
     * was really recorded -- and then fillCredentialPair() threw "no fill target
     * was captured when you authorized" into a status node that was no longer
     * in the document. Real tap, real release, nothing filled, nothing said.
     * While the request is in flight the backdrop stops dismissing; Cancel is
     * already disabled across the same window.
     */
    let inFlight = false;
    cancel.addEventListener('click', () => closePromptSheet());
    backdrop.addEventListener('click', e => {
        if (inFlight || e.target !== backdrop) return;
        closePromptSheet();
    });
    go.addEventListener('click', async () => {
        go.disabled = true;
        cancel.disabled = true;
        inFlight = true;
        status.textContent = 'Opening the Ragewarden authorization window '
            + '(look outside this page)...';
        let resp = null;
        try {
            resp = await sendBg({
                kind: 'vault.unlock',
                cipherId: match.id,
                action: 'autofill',
            });
            if (!resp || !resp.ok) {
                status.textContent = (resp && resp.error) || 'failed';
                cancel.disabled = false;
                return;
            }
            if (!resp.ceremony || !(resp.ceremony.taps > 0)) {
                status.textContent = 'refused: no hardware tap was recorded for this release';
                cancel.disabled = false;
                return;
            }
            if (resp.ceremony.mock) {
                status.textContent = 'MOCK TAP BUILD -- NO DEVICE WAS TOUCHED. '
                    + 'Filling anyway because this is a development build.';
                console.warn(
                    '[ragewarden] autofill authorized by a MOCK hardware tap -- '
                    + 'this build is not safe for real secrets',
                );
            }
            await fillCredentialPair(resp.plaintext);
            closePromptSheet();
        } catch (err) {
            status.textContent = (err && err.message) || String(err);
            cancel.disabled = false;
        } finally {
            inFlight = false;
            if (resp && resp.plaintext && typeof resp.plaintext === 'object') {
                resp.plaintext.username = '';
                resp.plaintext.password = '';
            }
            go.disabled = false;
        }
    });
}

function closePromptSheet() {
    if (state.promptEl) {
        state.promptEl.remove();
        state.promptEl = null;
    }
    state.pendingFill = null;
}

async function fillCredentialPair(plaintext) {
    if (!plaintext) return;
    const pending = state.pendingFill;
    if (!pending) {
        throw new Error('no fill target was captured when you authorized -- nothing was filled');
    }
    if (pending.origin !== location.origin) {
        throw new Error(
            `page navigated from ${pending.origin} to ${location.origin} while you were `
            + 'authorizing -- nothing was filled',
        );
    }
    const passTarget = pending.passwordEl;
    const userTarget = pending.usernameEl;
    if (!passTarget && !userTarget) {
        throw new Error('no input field was identified when you authorized -- nothing was filled');
    }
    if (passTarget && !targetStillValid(passTarget, true)) {
        throw new Error(
            'the password field you authorized is gone, hidden or disabled -- nothing was filled',
        );
    }
    if (userTarget && !targetStillValid(userTarget, false)) {
        throw new Error(
            'the username field you authorized is gone, hidden or disabled -- nothing was filled',
        );
    }
    if (userTarget && plaintext.username) {
        await typeInto(userTarget, plaintext.username);
    }
    if (passTarget && plaintext.password) {
        await typeInto(passTarget, plaintext.password);
    }
}

async function typeInto(el, value) {
    el.focus();
    const proto = el.tagName === 'TEXTAREA'
        ? window.HTMLTextAreaElement.prototype
        : window.HTMLInputElement.prototype;
    const nativeSetter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
    let current = '';
    if (nativeSetter) nativeSetter.call(el, '');
    else el.value = '';
    el.dispatchEvent(new Event('focus', { bubbles: true }));
    for (const ch of value) {
        current += ch;
        if (nativeSetter) nativeSetter.call(el, current);
        else el.value = current;
        el.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, cancelable: true, data: ch, inputType: 'insertText' }));
        el.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: false, data: ch, inputType: 'insertText' }));
        if (AUTOFILL_KEYSTROKE_DELAY_MS > 0) await new Promise(r => setTimeout(r, AUTOFILL_KEYSTROKE_DELAY_MS));
    }
    el.dispatchEvent(new Event('change', { bubbles: true }));
    el.dispatchEvent(new Event('blur', { bubbles: true }));
}

function sendBg(message) {
    return new Promise((resolve, reject) => {
        try {
            chrome.runtime.sendMessage(message, response => {
                const err = chrome.runtime.lastError;
                if (err) reject(new Error(err.message || 'runtime error'));
                else resolve(response);
            });
        } catch (e) { reject(e); }
    });
}

async function lookupForOrigin() {
    try {
        const resp = await sendBg({ kind: 'vault.lookup' });
        if (resp && resp.ok && Array.isArray(resp.matches)) {
            state.matches = resp.matches;
            return resp.matches;
        }
    } catch {}
    state.matches = [];
    return [];
}

async function maybeShowChip(field) {
    if (!field) return;
    const matches = await lookupForOrigin();
    if (!matches.length) return;
    showChip(field, matches[0]);
}

function debounceShowChip(field) {
    if (state.debounceTimer) clearTimeout(state.debounceTimer);
    state.debounceTimer = setTimeout(() => maybeShowChip(field), 20);
}

function bindFocusListener() {
    if (state.chipBound) return;
    state.chipBound = true;
    document.addEventListener('focusin', e => {
        const el = e.target;
        if (isPasswordField(el) || isLikelyUsernameField(el)) {
            debounceShowChip(el);
        }
    }, true);
    document.addEventListener('focusout', e => {
        const next = e.relatedTarget;
        if (!next) {
            setTimeout(() => {
                const a = document.activeElement;
                if (!isPasswordField(a) && !isLikelyUsernameField(a)) hideChip();
            }, 150);
        }
    }, true);
    window.addEventListener('scroll', () => {
        if (state.chipEl && state.activeField) positionChip(state.chipEl, state.activeField);
    }, true);
    window.addEventListener('resize', () => {
        if (state.chipEl && state.activeField) positionChip(state.chipEl, state.activeField);
    });
}

/**
 * Fill a credential pair pushed from an extension page (the popup), after the
 * popup has already run the tap ceremony for this exact item.
 *
 * Only extension pages can reach this: `chrome.tabs.sendMessage` is not
 * available to content scripts, and `sender.tab` is set for anything that came
 * from a page. The target fields are resolved here, at fill time, so the popup
 * never gets to name a field.
 */
async function fillFromExtensionPage(msg) {
    const active = document.activeElement;
    let pair = (isPasswordField(active) || isLikelyUsernameField(active))
        ? findCredentialPair(active)
        : { usernameEl: null, passwordEl: null };
    if (!pair.passwordEl) {
        for (const i of document.querySelectorAll('input')) {
            if (isPasswordField(i) && targetStillValid(i, true)) {
                pair = { passwordEl: i, usernameEl: findSiblingUsername(i) };
                break;
            }
        }
    }
    if (!pair.passwordEl && !pair.usernameEl) {
        throw new Error(`no login field found on ${location.host}`);
    }
    state.pendingFill = {
        usernameEl: pair.usernameEl,
        passwordEl: pair.passwordEl,
        origin: location.origin,
        href: location.href,
        at: Date.now(),
    };
    try {
        await fillCredentialPair({
            username: msg.username || '',
            password: msg.password || '',
        });
    } finally {
        state.pendingFill = null;
    }
    return { filled: true, host: location.host };
}

function bindExtensionFillListener() {
    if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.onMessage) return;
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
        if (!msg || msg.kind !== 'ragewarden.fill') return false;
        if (!sender || sender.id !== chrome.runtime.id || sender.tab) {
            sendResponse({ ok: false, error: 'rejected: not an extension page' });
            return false;
        }
        fillFromExtensionPage(msg).then(
            r => sendResponse({ ok: true, ...r }),
            e => sendResponse({ ok: false, error: (e && e.message) || String(e) }),
        );
        return true;
    });
}

function init() {
    if (window.top !== window) {
        return;
    }
    bindFocusListener();
    bindExtensionFillListener();
    if (BUILD_FLAGS.testHooks !== true) {
        return;
    }
    window.__ragewardenContent = {
        forceLookup: lookupForOrigin,
        showChipFor: maybeShowChip,
        getState: () => ({
            origin: state.origin,
            domain: state.domain,
            chipPresent: !!state.chipEl,
            promptPresent: !!state.promptEl,
            matches: state.matches,
        }),
        clickChip: () => state.chipEl ? state.chipEl.click() : null,
        readPromptText: () => {
            if (!state.promptEl) return null;
            const t = state.promptEl.querySelector('.prompt-title');
            return t ? t.textContent : null;
        },
        confirmPrompt: () => {
            if (!state.promptEl) throw new Error('no prompt visible');
            const btn = state.promptEl.querySelector('[data-ragewarden-confirm="1"]');
            if (!btn) throw new Error('confirm button missing');
            btn.click();
        },
        waitForPromptClosed: () => new Promise((resolve) => {
            if (!state.promptEl) return resolve();
            const i = setInterval(() => {
                if (!state.promptEl) { clearInterval(i); resolve(); }
            }, 30);
        }),
        snapshotInternalState: () => {
            const shadowText = state.shadow ? walkShadowText(state.shadow) : '';
            return {
                hasMatches: state.matches.length > 0,
                chipPresent: !!state.chipEl,
                promptPresent: !!state.promptEl,
                matchesJson: JSON.stringify(state.matches),
                shadowTextLength: shadowText.length,
                shadowTextSample: shadowText.slice(0, 256),
            };
        },
    };
}

function walkShadowText(root) {
    return root.textContent || '';
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
} else {
    init();
}
