import { loadSession } from './glue/storage.js';
import { hardwareInventory, unlockCipherField, isUserDecline } from './glue/unlock.js';
import { backendIsMock, performPrfEnroll, performPrfTap } from './glue/hardware-tap.js';
import { passkeyEnrollWithSoftwareKey } from './glue/passkey.js';
import * as wasmGlue from './glue/crypto.js';
import { assertReleaseSafe } from './glue/build-flags.js';

assertReleaseSafe();

/*
 * Enrolment runs its two WebAuthn ceremonies (register + PRF) here, in the
 * focused tap window, for the same reason reveals do: the side-panel UI is not
 * a reliable WebAuthn context -- an inline navigator.credentials.create() there
 * hangs and leaves a pending request. This window is a real top-level page, so
 * the ceremony completes. The pair is frozen so enrolment cannot bypass the gate.
 */
const ENROLL_CEREMONY = Object.freeze({ enroll: performPrfEnroll, prfTap: performPrfTap });

const api = (typeof chrome !== 'undefined' && chrome.runtime) ? chrome
    : ((typeof browser !== 'undefined' && browser.runtime) ? browser : null);

const el = id => document.getElementById(id);
let requestId = null;
let request = null;
let settled = false;

function send(message) {
    return new Promise((resolve, reject) => {
        if (!api) {
            reject(new Error('no extension runtime available in this context'));
            return;
        }
        try {
            api.runtime.sendMessage(message, r => {
                const err = api.runtime.lastError;
                if (err) reject(new Error(err.message));
                else resolve(r);
            });
        } catch (e) { reject(e); }
    });
}

function setStatus(text, isError = false) {
    const s = el('status');
    s.textContent = text || '';
    s.classList.toggle('err', !!isError);
}

/*
 * The foot of this window used to also carry `backend: <label>`, which in a
 * release build is the constant string "Security key / passkey (WebAuthn PRF)"
 * under every ceremony forever. A line that never changes teaches people the
 * foot of this dialog is ignorable, and the foot of this dialog is #status --
 * where "Fabricating a MOCK tap (no device involved)..." and "Tap 2 of up to 2"
 * have to be read. Deleted: what sits below the buttons now only ever says
 * something when there is something to say.
 */
function renderMockBanner() {
    if (!backendIsMock()) return;
    const b = el('mock-banner');
    b.textContent = 'MOCK HARDWARE TAP -- NO PHYSICAL DEVICE IS INVOLVED. '
        + 'THIS BUILD IS NOT SAFE FOR REAL SECRETS.';
    b.classList.add('on');
    document.title = 'Ragewarden -- MOCK TAP (NOT SECURE)';
}

function renderRequest(req) {
    el('action').textContent = req.action || 'reveal';
    el('item').textContent = req.cipherName || req.cipherId || '--';
    el('destination').textContent = req.destination;
    const p = el('protection');
    if (req.action === 'enroll') {
        p.textContent = 'enrolling this browser as a hardware recipient';
        p.className = 'hard';
        el('authorize').textContent = 'Tap your key to enrol';
    } else if (req.rage) {
        p.textContent = 'hardware-encrypted (your tap derives the key)';
        p.className = 'hard';
        el('authorize').textContent = 'Tap your key to decrypt';
    } else {
        p.textContent = 'NOT hardware-encrypted -- the tap only authorizes release';
        p.className = 'soft';
        el('authorize').textContent = 'Tap your key to authorize release';
    }
    el('headline').textContent = `Authorize ${req.action || 'reveal'}`;
}

async function finishOk(plaintext, receipts) {
    settled = true;
    await send({
        kind: 'tap.complete',
        requestId,
        plaintext,
        receipts,
    });
    plaintext.username = '';
    plaintext.password = '';
    window.close();
}

async function finishErr(code, message) {
    settled = true;
    try {
        await send({ kind: 'tap.fail', requestId, code, error: message });
    } catch {}
}

async function finishEnroll(enrollment) {
    settled = true;
    await send({ kind: 'tap.complete', requestId, enrollment });
    window.close();
}

/*
 * How many system dialogs one press of "Tap your key" will raise.
 *
 * A standard enrolment leaves two things behind that can open a hardware item:
 * this browser profile's software-wrap credential, and the passkey recipient
 * stanza carried inside the blob. glue/unlock.js taps for the first, then hands
 * the wasm layer a PRF callback that taps again for the second whenever the
 * blob carries PRF stanzas -- without checking that the first one already
 * opened it. So the ordinary case is two taps of the same key for one press.
 *
 * This is an upper bound, not a count: the second tap does not happen if the
 * blob turns out to carry no passkey stanza, and nothing reachable from this
 * page can tell in advance. Hence "up to" in the wording below -- an honest
 * over-count is fine, a promise of one tap followed by a second prompt is not.
 *
 * Saying it out loud is the entire point. A second authenticator prompt for a
 * click you only made once is exactly what something else asking looks like.
 */
async function plannedTaps() {
    if (!request.rage) return 1;
    try {
        const { recipients, software } = await hardwareInventory();
        return (software ? 1 : 0) + (recipients.length > 0 ? 1 : 0);
    } catch {
        // The unlock is about to fail on the same inventory read and say why;
        // narrating badly is not worth pre-empting that error with a worse one.
        return 1;
    }
}

function tapLine(done, planned) {
    if (backendIsMock()) return 'Fabricating a MOCK tap (no device involved)...';
    if (planned <= 1) return 'Waiting for your security key...';
    if (done < 1) {
        return `Waiting for your security key -- this item takes up to ${planned} taps of the `
            + 'same key, so a second prompt after the first one is expected.';
    }
    return `Tap ${done} of up to ${planned} -- waiting for your security key...`;
}

/*
 * Count the ceremonies as they are raised, so this window can say which tap the
 * user is on instead of freezing on one line across both of them.
 *
 * navigator.credentials.get() is the call that raises the dialog and the only
 * edge visible from here -- glue/unlock.js exposes no progress hook. The wrapper
 * is read-only: it forwards to the real method it captured and returns that
 * promise untouched, it is installed as an own property so removing it restores
 * the prototype method exactly, and it comes off before the ceremony's caller
 * returns. Every failure path here gives up and narrates less, because
 * narration must never be able to change what gets asserted. It also never sees
 * the mock backend, which fabricates taps without touching WebAuthn -- that is
 * why tapLine() states the plan up front rather than only on the first tap.
 */
function narrateTaps(planned) {
    const creds = (typeof navigator !== 'undefined') ? navigator.credentials : null;
    if (!creds || typeof creds.get !== 'function') return () => {};
    if (Object.prototype.hasOwnProperty.call(creds, 'get')) return () => {};
    const real = creds.get.bind(creds);
    let done = 0;
    try {
        creds.get = (...args) => {
            done += 1;
            setStatus(tapLine(done, planned));
            return real(...args);
        };
    } catch {
        return () => {};
    }
    return () => { try { delete creds.get; } catch {} };
}

async function onAuthorize() {
    el('authorize').disabled = true;
    el('cancel').disabled = true;
    if (request.action === 'enroll') {
        setStatus('Tap your key to enrol (register, then a second tap to confirm)...');
        try {
            const mod = await wasmGlue.init();
            const enrollment = await passkeyEnrollWithSoftwareKey(
                { rpId: request.rpId || undefined, label: request.label || 'Primary passkey' },
                mod,
                ENROLL_CEREMONY,
            );
            await finishEnroll(enrollment);
        } catch (err) {
            const message = (err && err.message) || String(err);
            setStatus(isUserDecline(err) ? 'Cancelled at the authenticator.' : message, true);
            el('cancel').disabled = false;
            el('authorize').disabled = false;
            if (isUserDecline(err)) {
                await finishErr('tap_declined', 'user declined at the authenticator');
                window.close();
            }
        }
        return;
    }
    setStatus(tapLine(0, 1));
    const planned = await plannedTaps();
    setStatus(tapLine(0, planned));
    const stopNarrating = narrateTaps(planned);
    try {
        const session = await loadSession();
        if (!session) throw new Error('not signed in');
        const out = await unlockCipherField({
            session,
            cipher: request.cipher,
            fieldName: request.fieldName || 'password',
            action: request.action,
            destination: request.destination,
            origin: request.origin,
        });
        const plaintext = {
            username: request.username || '',
            password: out.value,
        };
        await finishOk(plaintext, out.receipts);
    } catch (err) {
        const message = (err && err.message) || String(err);
        setStatus(isUserDecline(err) ? 'Cancelled at the authenticator.' : message, true);
        el('cancel').disabled = false;
        el('authorize').disabled = false;
        if (isUserDecline(err)) {
            await finishErr('tap_declined', 'user declined at the authenticator');
            window.close();
        }
    } finally {
        stopNarrating();
    }
}

async function main() {
    renderMockBanner();
    const params = new URLSearchParams(location.search);
    requestId = params.get('req');
    if (!requestId) {
        setStatus('missing request id', true);
        return;
    }
    let claim;
    try {
        claim = await send({ kind: 'tap.claim', requestId });
    } catch (e) {
        setStatus(`could not reach the extension worker: ${(e && e.message) || e}`, true);
        return;
    }
    if (!claim || !claim.ok) {
        setStatus((claim && claim.error) || 'this authorization request is no longer valid', true);
        return;
    }
    request = claim.request;
    // The hostname is now the one fact in this window that decides whether to
    // tap, so a request that cannot name one is not authorizable. Every real
    // caller carries it (background.js derives it from the sender's origin);
    // rendering "--" in its place would ask the user to authorize "some page".
    if (!request.destination) {
        setStatus(
            'this authorization request names no destination -- refusing to authorize it',
            true,
        );
        return;
    }
    renderRequest(request);
    el('authorize').disabled = false;
    el('authorize').addEventListener('click', onAuthorize);
    el('cancel').addEventListener('click', async () => {
        await finishErr('tap_cancelled', 'user cancelled in the Ragewarden prompt');
        window.close();
    });
}

window.addEventListener('pagehide', () => {
    if (settled || !requestId) return;
    settled = true;
    try {
        api.runtime.sendMessage({
            kind: 'tap.fail',
            requestId,
            code: 'tap_cancelled',
            error: 'authorization window closed',
        });
    } catch {}
});

main();
