/**
 * DOM helpers for the popup.
 *
 * Nothing here ever assigns innerHTML: every string that reaches the document
 * goes through textContent or setAttribute, so a cipher named
 * `<img onerror=...>` is a name, not markup.
 */

export function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    if (props) {
        for (const [k, v] of Object.entries(props)) {
            if (v === null || v === undefined || v === false) continue;
            if (k === 'class') el.className = v;
            else if (k === 'text') el.textContent = String(v);
            else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
            else if (k === 'dataset') Object.assign(el.dataset, v);
            else if (k.startsWith('on') && typeof v === 'function') {
                el.addEventListener(k.slice(2).toLowerCase(), v);
            } else if (k === 'value') el.value = v;
            else if (k === 'disabled' || k === 'checked' || k === 'autofocus' || k === 'readOnly') {
                el[k] = !!v;
            } else el.setAttribute(k, String(v));
        }
    }
    append(el, kids);
    return el;
}

export function append(el, kids) {
    for (const kid of kids.flat(4)) {
        if (kid === null || kid === undefined || kid === false || kid === true) continue;
        el.appendChild(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
}

export function clear(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
    return el;
}

export function button(label, onClick, opts = {}) {
    const b = h('button', {
        class: `btn btn-${opts.variant || 'secondary'}${opts.full ? ' btn-full' : ''}`,
        type: 'button',
        disabled: !!opts.disabled,
        title: opts.title || null,
        onclick: onClick,
    }, label);
    return b;
}

export function eyebrow(text) {
    return h('div', { class: 'eyebrow', text });
}

export function field(label, control, hint) {
    return h('label', { class: 'field' },
        h('span', { class: 'eyebrow', text: label }),
        control,
        hint ? h('div', { class: 'hint', text: hint }) : null);
}

export function textInput(opts = {}) {
    return h('input', {
        class: `input${opts.mono ? ' mono' : ''}`,
        type: opts.type || 'text',
        value: opts.value || '',
        placeholder: opts.placeholder || '',
        autocomplete: opts.autocomplete || 'off',
        spellcheck: 'false',
        readOnly: !!opts.readOnly,
    });
}

export function row(...kids) {
    return h('div', { class: 'row' }, ...kids);
}

export function banner(tone, title, body, action) {
    return h('div', { class: `banner banner-${tone}` },
        h('div', { class: 'banner-body' },
            title ? h('div', { class: 'banner-title', text: title }) : null,
            body ? h('div', { class: 'banner-text', text: body }) : null),
        action ? button(action.label, action.onClick, { variant: 'ghost' }) : null);
}

/**
 * Visible failure channel.
 *
 * The design prototype's ToastHost was `() => null`, so every `show(...)` in
 * every error path rendered nothing at all. Errors here are sticky and must be
 * dismissed by hand -- an error that vanishes on a timer is an error the user
 * never read.
 *
 * The whole toast is the dismiss target, and it is a real `<button>` so the
 * keyboard reaches it. It used to carry a separate `x` that computed to about
 * 15x15 px -- under the WCAG 2.2 24x24 floor, and, because warn/error never
 * expire, the only way out of them. The body is the full width of the panel, so
 * dismissing is the same gesture with none of the aiming.
 *
 * Sticky is kept and the *host* was moved out of the way instead (see
 * .toast-host in popup.css): the toast used to sit on top of the footer and
 * cover about 32 of the 37 px of the retry button an error was telling the user
 * to press.
 */
export function createToaster(host) {
    host.setAttribute('aria-live', 'polite');
    function push(message, tone, sticky) {
        const el = h('button', {
            class: `toast toast-${tone}`, type: 'button', title: 'Dismiss',
            onclick: () => el.remove(),
        }, h('div', { class: 'toast-text', text: String(message) }));
        host.appendChild(el);
        while (host.childElementCount > 4) host.firstElementChild.remove();
        if (!sticky) setTimeout(() => el.remove(), 3200);
        return el;
    }
    return {
        info: (m) => push(m, 'info', false),
        ok: (m) => push(m, 'ok', false),
        warn: (m) => push(m, 'warn', true),
        error: (m) => push(m, 'error', true),
    };
}

export function errorText(err) {
    if (!err) return 'unknown error';
    if (typeof err === 'string') return err;
    return err.message || String(err);
}

export function sheet({ title, body, actions, onClose }) {
    const card = h('div', { class: 'sheet-card', onclick: e => e.stopPropagation() },
        h('div', { class: 'sheet-grab' }),
        title ? h('div', { class: 'sheet-title', text: title }) : null,
        body,
        h('div', { class: 'sheet-actions' }, ...(actions || [])));
    const root = h('div', {
        class: 'sheet',
        onclick: () => { root.remove(); onClose?.(); },
    }, card);
    return {
        el: root,
        close: () => { root.remove(); onClose?.(); },
    };
}

export function relTime(ms) {
    if (!ms) return '';
    const d = Date.now() - ms;
    if (d < 45_000) return 'just now';
    if (d < 3_600_000) return `${Math.round(d / 60_000)}m ago`;
    if (d < 86_400_000) return `${Math.round(d / 3_600_000)}h ago`;
    return new Date(ms).toISOString().slice(0, 10);
}

export function initials(name) {
    const letters = String(name || '').replace(/[^a-zA-Z0-9]/g, '');
    return (letters.slice(0, 2) || 'XX').toUpperCase();
}
