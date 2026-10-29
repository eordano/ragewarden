import { loadSession } from './glue/storage.js';
import { unlockCipherField, isUserDecline, NoHardwareError } from './glue/unlock.js';
import { backendIsMock } from './glue/hardware-tap.js';
import { assertReleaseSafe } from './glue/build-flags.js';
import { init as initWasm } from './glue/crypto.js';
import { registryEntries } from './glue/inventory.js';
import { relayCredentialsFromRegistry } from './glue/prf-relay.js';

assertReleaseSafe();

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
    if (req.rage) {
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

function tapLine() {
    return backendIsMock()
        ? 'Fabricating a MOCK tap (no device involved)...'
        : 'Waiting for your security key...';
}

async function onAuthorize() {
    el('authorize').disabled = true;
    el('cancel').disabled = true;
    setStatus(tapLine());
    try {
        const session = await loadSession();
        if (!session) throw new Error('Ragewarden is locked -- unlock it from the toolbar first');
        const out = await unlockCipherField({
            session,
            cipher: request.cipher,
            fieldName: request.fieldName || 'password',
            relayCredentials: async () => relayCredentialsFromRegistry(
                await registryEntries(await initWasm(), session)),
            action: request.action,
            destination: request.destination,
            origin: request.origin,
            cipherId: request.cipherId,
        });
        const plaintext = {
            username: request.username || '',
            password: out.value,
        };
        await finishOk(plaintext, out.receipts);
    } catch (err) {
        const message = (err && err.message) || String(err);
        if (isUserDecline(err)) {
            setStatus('Cancelled at the authenticator. Nothing was released.', true);
            await finishErr('tap_declined', 'user declined at the authenticator');
            closeSoon();
            return;
        }
        const code = nonRetryableCode(err);
        setStatus(message, true);
        if (code) {
            await finishErr(code, message);
            offerEnrolment();
            el('cancel').textContent = 'Close';
            el('cancel').disabled = false;
            el('cancel').focus();
            return;
        }
        el('cancel').disabled = false;
        el('authorize').disabled = false;
        el('authorize').focus();
    }
}

const NON_RETRYABLE = new Set(['no_hardware', 'no_identity_available', 'no_matching_identity']);

function nonRetryableCode(err) {
    if (err instanceof NoHardwareError) return 'no_hardware';
    const code = err && err.code;
    if (NON_RETRYABLE.has(code)) return code;
    if (/none on this device|matched any stanza/.test(String((err && err.message) || ''))) {
        return 'no_matching_identity';
    }
    return null;
}

function closeSoon() {
    el('authorize').disabled = true;
    el('cancel').textContent = 'Close';
    el('cancel').disabled = false;
    el('cancel').focus();
    setTimeout(() => window.close(), 2500);
}

function offerEnrolment() {
    if (el('enrol')) return;
    const b = document.createElement('button');
    b.id = 'enrol';
    b.type = 'button';
    b.textContent = 'Enrol a passkey';
    b.addEventListener('click', () => {
        const url = api.runtime.getURL('popup/index.html');
        if (api.tabs && api.tabs.create) api.tabs.create({ url });
        else window.open(url, '_blank');
        window.close();
    });
    el('authorize').replaceWith(b);
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
    el('authorize').focus();
    el('cancel').addEventListener('click', async () => {
        if (!settled) await finishErr('tap_cancelled', 'user cancelled in the Ragewarden prompt');
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
