const BUILD_FLAGS = Object.freeze(Object.assign(
    { profile: 'release', allowMockTap: false, forceMockTap: false, testHooks: false },
    (typeof globalThis !== 'undefined' && globalThis.__RAGEWARDEN_BUILD_FLAGS) || {},
));

const HOST_ID = `rw-${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
const AUTOFILL_KEYSTROKE_DELAY_MS = 12;

const state = {
    host: null,
    shadow: null,
    chipEl: null,
    activeField: null,
    matches: [],
    origin: location.origin,
    domain: location.hostname,
    chipBound: false,
    debounceTimer: null,
    pendingFill: null,
    lastCredentialField: null,
    busy: false,
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
.picker-backdrop {
    position: fixed; inset: 0; z-index: 2147483647; pointer-events: auto;
    background: rgba(0,0,0,0.55);
    display: flex; align-items: center; justify-content: center;
    font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
}
.picker-card {
    background: #1d1d1d; color: #faf6ee; border: 1px solid #2c2c2c; border-radius: 12px;
    padding: 18px; width: min(360px, 92vw); box-shadow: 0 24px 60px rgba(0,0,0,0.5);
}
.picker-title { font-size: 15px; font-weight: 600; margin: 0 0 10px; }
.picker-list { display: grid; gap: 6px; margin-bottom: 12px; }
.picker-btn {
    border-radius: 8px; border: 1px solid #2c2c2c; background: #121212; color: #faf6ee;
    padding: 8px 12px; font: inherit; font-size: 13px; cursor: pointer; text-align: left;
}
`;

function showChip(field, match) {
    const shadow = ensureShadowHost();
    if (state.chipEl) state.chipEl.remove();
    const chip = document.createElement('div');
    chip.className = 'chip';
    chip.setAttribute('data-ragewarden-chip', '1');
    chip.setAttribute('role', 'button');
    chip.setAttribute('tabindex', '0');
    const count = state.matches.length;
    chip.setAttribute('aria-label', count > 1
        ? `Ragewarden: ${count} logins for ${state.domain}`
        : `Ragewarden autofill into ${state.domain}`);
    const dot = document.createElement('span');
    dot.className = 'chip-dot';
    const label = document.createElement('span');
    label.className = 'chip-label';
    label.textContent = 'ragewarden';
    const meta = document.createElement('span');
    meta.className = 'chip-meta';
    meta.textContent = count > 1 ? `${count} logins` : (match.name || state.domain);
    chip.append(dot, label, meta);
    chip.addEventListener('click', onChipClick);
    chip.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onChipClick(); }
    });
    shadow.appendChild(chip);
    positionChip(chip, field);
    state.chipEl = chip;
    state.activeField = field;
}

function positionChip(chip, field) {
    const r = field.getBoundingClientRect();
    const width = chip.offsetWidth || 110;
    const height = chip.offsetHeight || 24;
    const maxLeft = Math.max(4, window.innerWidth - width - 4);
    chip.style.left = `${Math.min(maxLeft, Math.max(4, r.right - width))}px`;
    const above = r.top - height - 4;
    chip.style.top = `${above >= 4 ? above : Math.min(window.innerHeight - height - 4, r.bottom + 4)}px`;
}

function hideChip() {
    if (state.chipEl) {
        state.chipEl.remove();
        state.chipEl = null;
    }
}

function setChipStatus(text) {
    if (!state.chipEl) return;
    const meta = state.chipEl.querySelector('.chip-meta');
    if (meta) meta.textContent = text;
}

/*
 * The chip goes straight to the Ragewarden authorization window: that window,
 * outside this page, is the consent. An in-page "Continue?" sheet added a
 * click a hostile page could imitate and no security.
 */
async function onChipClick() {
    if (state.matches.length === 0 || state.busy) return;
    if (state.matches.length > 1) {
        showPicker();
        return;
    }
    await requestFill(state.matches[0]);
}

function closePicker() {
    if (state.pickerEl) {
        state.pickerEl.remove();
        state.pickerEl = null;
    }
    if (state.chipEl) state.chipEl.focus();
}

/**
 * Which of several logins for this origin to fill. Choosing is not consent:
 * the Ragewarden window that opens next names the chosen item and asks for the tap.
 */
function showPicker() {
    const shadow = ensureShadowHost();
    if (state.pickerEl) state.pickerEl.remove();
    const backdrop = document.createElement('div');
    backdrop.className = 'picker-backdrop';
    backdrop.setAttribute('data-ragewarden-picker', '1');
    const card = document.createElement('div');
    card.className = 'picker-card';
    card.setAttribute('role', 'dialog');
    card.setAttribute('aria-modal', 'true');
    card.setAttribute('aria-labelledby', 'ragewarden-picker-title');
    const title = document.createElement('h2');
    title.className = 'picker-title';
    title.id = 'ragewarden-picker-title';
    title.textContent = `Which login for ${state.domain}?`;
    const list = document.createElement('div');
    list.className = 'picker-list';
    for (const m of state.matches) {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'picker-btn';
        b.setAttribute('data-ragewarden-pick', m.id);
        b.textContent = [m.name, m.username].filter(Boolean).join(' · ') || m.id;
        b.addEventListener('click', () => { closePicker(); requestFill(m); });
        list.appendChild(b);
    }
    const cancel = document.createElement('button');
    cancel.className = 'picker-btn';
    cancel.type = 'button';
    cancel.textContent = 'Cancel';
    cancel.addEventListener('click', closePicker);
    card.append(title, list, cancel);
    backdrop.appendChild(card);
    backdrop.addEventListener('click', e => { if (e.target === backdrop) closePicker(); });
    card.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') { e.preventDefault(); closePicker(); return; }
        if (e.key !== 'Tab') return;
        const items = [...card.querySelectorAll('button')];
        const active = card.getRootNode().activeElement;
        if (e.shiftKey && active === items[0]) { e.preventDefault(); items[items.length - 1].focus(); }
        else if (!e.shiftKey && active === items[items.length - 1]) { e.preventDefault(); items[0].focus(); }
    });
    shadow.appendChild(backdrop);
    state.pickerEl = backdrop;
    list.firstChild.focus();
}

async function requestFill(match) {
    const { usernameEl, passwordEl } = findCredentialPair(state.activeField)
        || { usernameEl: null, passwordEl: null };
    state.pendingFill = {
        usernameEl,
        passwordEl,
        origin: location.origin,
        href: location.href,
        at: Date.now(),
    };
    state.busy = true;
    setChipStatus('opening Ragewarden...');
    let resp = null;
    try {
        resp = await sendBg({ kind: 'vault.unlock', cipherId: match.id, action: 'autofill' });
        if (!resp || !resp.ok) {
            setChipStatus((resp && resp.error) || 'not filled');
            return;
        }
        if (!resp.ceremony || !(resp.ceremony.taps > 0)) {
            setChipStatus('refused: no hardware tap was recorded');
            return;
        }
        if (resp.ceremony.mock) {
            console.warn('[ragewarden] autofill authorized by a MOCK hardware tap -- not safe for real secrets');
        }
        await fillCredentialPair(resp.plaintext);
        setChipStatus(match.name || state.domain);
    } catch (err) {
        setChipStatus((err && err.message) || String(err));
    } finally {
        state.busy = false;
        state.pendingFill = null;
        if (resp && resp.plaintext && typeof resp.plaintext === 'object') {
            resp.plaintext.username = '';
            resp.plaintext.password = '';
        }
    }
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
            state.lastCredentialField = el;
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

function visiblePasswordFields() {
    return Array.from(document.querySelectorAll('input')).filter(i => isPasswordField(i) && targetStillValid(i, true));
}

/*
 * The field to fill for a popup-initiated fill: the credential field that has
 * focus, else the one the user last focused on this page, else the only
 * visible password field. Several candidates and no choice is a refusal --
 * guessing is how a password lands in the wrong form.
 */
function chosenCredentialPair() {
    for (const el of [document.activeElement, state.lastCredentialField]) {
        if ((isPasswordField(el) || isLikelyUsernameField(el)) && targetStillValid(el, false)) {
            return findCredentialPair(el);
        }
    }
    const candidates = visiblePasswordFields();
    if (candidates.length === 1) {
        return { passwordEl: candidates[0], usernameEl: findSiblingUsername(candidates[0]) };
    }
    if (candidates.length > 1) {
        throw new Error(
            `${location.host} has ${candidates.length} password fields -- click into the one `
            + 'to fill, then autofill again. Nothing was filled.',
        );
    }
    throw new Error(`no login field found on ${location.host}`);
}

/**
 * Fill a credential pair pushed from the popup after it ran the tap ceremony.
 * The popup pins the origin it captured before the tap; a page that navigated
 * away meanwhile is refused. Only extension pages reach this (sender.tab is
 * set for anything that came from a page).
 */
async function fillFromExtensionPage(msg) {
    if (!msg.expectedOrigin || msg.expectedOrigin !== location.origin) {
        throw new Error(
            `the tap was for ${msg.expectedOrigin || 'another page'} but this tab is now `
            + `${location.origin} -- nothing was filled`,
        );
    }
    const pair = chosenCredentialPair();
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
    bindFocusListener();
    bindExtensionFillListener();
    // test-hooks:begin
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
            promptPresent: false,
            matches: state.matches,
        }),
        clickChip: () => state.chipEl ? state.chipEl.click() : null,
        waitForFillSettled: () => new Promise((resolve) => {
            const i = setInterval(() => { if (!state.busy) { clearInterval(i); resolve(); } }, 30);
        }),
        snapshotInternalState: () => {
            const shadowText = state.shadow ? walkShadowText(state.shadow) : '';
            return {
                hasMatches: state.matches.length > 0,
                chipPresent: !!state.chipEl,
                promptPresent: false,
                matchesJson: JSON.stringify(state.matches),
                shadowTextLength: shadowText.length,
                shadowTextSample: shadowText.slice(0, 256),
            };
        },
    };
    // test-hooks:end
}

function walkShadowText(root) {
    return root.textContent || '';
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
} else {
    init();
}
