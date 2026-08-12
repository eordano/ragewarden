/**
 * The clipboard write used to live in the design prototype's `completeAction`
 * handler, which the extension does not ship. Nothing in `ext/` ever touched a
 * clipboard, so every "Copy" in the popup silently copied nothing.
 *
 * It lives here now, next to the code that owns the plaintext, so `copyPassword`
 * can put the bytes on the clipboard and drop them without ever handing them to
 * the UI layer.
 */

function execCommandCopy(text) {
    if (typeof document === 'undefined' || !document.body) return false;
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.cssText = 'position:fixed;top:-1000px;left:-1000px;opacity:0;';
    document.body.appendChild(ta);
    let ok = false;
    try {
        ta.select();
        ta.setSelectionRange(0, ta.value.length);
        ok = document.execCommand('copy');
    } catch {
        ok = false;
    } finally {
        ta.value = '';
        ta.remove();
    }
    return ok;
}

/**
 * Write `text` to the system clipboard. Throws if the browser refused both the
 * async Clipboard API and the `execCommand` fallback -- a failed copy must be
 * loud, because the user's next action is to paste.
 */
export async function writeClipboard(text) {
    if (typeof text !== 'string' || text.length === 0) {
        throw new Error('clipboard: refusing to copy an empty value');
    }
    let asyncErr = null;
    if (typeof navigator !== 'undefined'
        && navigator.clipboard
        && typeof navigator.clipboard.writeText === 'function') {
        try {
            await navigator.clipboard.writeText(text);
            return 'navigator.clipboard';
        } catch (e) {
            asyncErr = e;
        }
    }
    if (execCommandCopy(text)) return 'execCommand';
    throw new Error(
        'clipboard write was refused by the browser'
        + (asyncErr ? `: ${(asyncErr && asyncErr.message) || asyncErr}` : '')
        + '. Nothing was copied.',
    );
}

/**
 * Overwrite the clipboard with a single space.
 *
 * This is unconditional: the extension has no `clipboardRead` permission, so it
 * cannot check whether the secret it wrote is still there. Callers must only
 * run this on a timer they started themselves.
 */
export async function clearClipboard() {
    try {
        await writeClipboard(' ');
        return true;
    } catch {
        return false;
    }
}

/**
 * Overwrite the clipboard without yielding to the event loop.
 *
 * `clearClipboard()` awaits `navigator.clipboard.writeText`, and inside a
 * `pagehide` handler nothing after the first await is guaranteed to run -- the
 * popup is already going away. On a Firefox/Safari `default_popup` build that
 * is the common case, not the edge case: any click outside the popup closes it,
 * taking the pending 30-second wipe with it and leaving the password on the
 * clipboard. `execCommand('copy')` completes within the handler, so this is the
 * only wipe that can happen at all on the way out.
 *
 * Best-effort by construction: it returns false if the browser refused, and
 * there is no way to retry once the page is gone.
 */
export function clearClipboardSync() {
    return execCommandCopy(' ');
}
