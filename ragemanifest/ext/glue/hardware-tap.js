import { BUILD_FLAGS, mockTapAllowed } from './build-flags.js';
import { passkeyEnroll, passkeyUnlockMulti, passkeyPresenceAssert } from './passkey.js';
import { loadAllPasskeyRecipients } from './passkey-store.js';
import { newPurpose } from './assertion.js';
import { b64ToBytes, bytesToB64 } from './b64.js';
import { RELAY_ORIGIN, sameCredentialId, verifyRelayAssertion } from './prf-relay.js';
import {
    BACKEND_MOCK, BACKEND_NATIVE_HOST, BACKEND_WEBAUTHN_PRF, NATIVE_HOST_TAP_BACKENDS,
    checkReceiptShape, publicKeysFromRecords, verifyReceipt,
} from './receipt-check.js';

export { mockTapAllowed, BACKEND_MOCK, BACKEND_NATIVE_HOST, BACKEND_WEBAUTHN_PRF, NATIVE_HOST_TAP_BACKENDS };

/*
 * A ceremony performed by a device this browser cannot reach, narrated back by
 * the rageterm native host (glue/native-host.js). The browser never sees the
 * authenticator here: it sees a `tap` block on a JSON reply. That is weaker
 * evidence than a WebAuthn assertion -- nothing here is signed, and a host
 * process that lied would not be caught by this file -- so the receipt is built
 * strictly from what the host claimed, with no field allowed to default to the
 * flattering value, and is then put through the same sealReceipt()/
 * assertReceiptIsRealTap() gate as everything else.
 */

/*
 * `tap.backend` values a native-host reply may carry. These are the stanza
 * families rageterm gates on a physical touch (`tag_is_hardware_gated` in
 * rageterm/src/native_host.rs). Anything else -- including a reply that names
 * `webauthn-prf-v1`, which this browser opens itself with a real assertion -- is
 * a malformed reply, not a new backend to trust.
 */


export class NoHardwareError extends Error {
    constructor(message, detail = {}) {
        super(message);
        this.name = 'NoHardwareError';
        this.code = 'no_hardware';
        this.detail = detail;
    }
}

export class TapDeclinedError extends Error {
    constructor(message) {
        super(message);
        this.name = 'TapDeclinedError';
        this.code = 'tap_declined';
    }
}

export function isUserDecline(err) {
    const name = (err && err.name) || '';
    return name === 'NotAllowedError' || name === 'AbortError'
        || (err && err.code === 'tap_declined');
}

export function webauthnAvailable() {
    return typeof navigator !== 'undefined'
        && !!navigator.credentials
        && typeof navigator.credentials.get === 'function';
}

export function selectedBackend() {
    if (mockTapAllowed() && (BUILD_FLAGS.forceMockTap === true || !webauthnAvailable())) {
        return BACKEND_MOCK;
    }
    return BACKEND_WEBAUTHN_PRF;
}

export function backendIsMock() {
    return selectedBackend() === BACKEND_MOCK;
}

export function backendLabel() {
    return backendIsMock()
        ? 'MOCK HARDWARE TAP -- NO DEVICE WAS TOUCHED (development build)'
        : 'Security key / passkey (WebAuthn PRF)';
}

async function loadMockBackend() {
    if (!mockTapAllowed()) {
        throw new Error(
            'hardware-tap: mock backend requested but this build does not allow it. '
            + 'This is a release build; there is no software substitute for a hardware tap.',
        );
    }
    let mod;
    try {
        mod = await import('./dev-only/mock-hardware-tap.js');
    } catch (e) {
        throw new Error(
            'hardware-tap: mock backend is enabled by build flags but '
            + 'glue/dev-only/mock-hardware-tap.js is not present in this bundle '
            + `(${(e && e.message) || e}). Refusing to continue -- a missing mock must `
            + 'never silently degrade into "no ceremony".',
        );
    }
    return mod;
}

function sealReceipt(receipt, expectMock) {
    if (!receipt || typeof receipt !== 'object') {
        throw new Error('hardware-tap: backend returned no receipt');
    }
    if (expectMock && receipt.mock !== true) {
        throw new Error('hardware-tap: mock backend returned a receipt not marked mock:true');
    }
    if (!expectMock && receipt.mock === true) {
        throw new Error('hardware-tap: real backend returned a receipt marked mock:true');
    }
    if (!expectMock && receipt.userPresent !== true) {
        throw new Error('hardware-tap: real backend produced no user-presence evidence');
    }
    // UV travels with UP, never behind it. The WebAuthn ceremonies request
    // userVerification:'required', so a receipt with UP set and UV clear is
    // either an authenticator that ignored the request or a caller that built
    // the receipt from flags it never checked -- both mean the tap proved a
    // touch and nothing about who touched it. The mock is exempt because its
    // receipts are honestly false on both counts (see mock-hardware-tap.js
    // receipt()) and are gated by `mock: true` instead.
    //
    // The native host inherits this rule unchanged and unexempted: a rageterm
    // unwrap that reports `touched: true, verified: false` -- a PIV slot with
    // touch policy but no PIN, say -- is refused here. That is a deliberate
    // narrowing of what the bridge can carry, not an oversight; loosening it
    // means deciding that "someone touched the key on that desk" authorises a
    // reveal, which is a different policy than this file has ever enforced.
    if (!expectMock && receipt.userVerified !== true) {
        throw new Error('hardware-tap: real backend produced no user-verification evidence');
    }
    return Object.freeze({ ...receipt });
}

async function knownPublicKeys() {
    try {
        return publicKeysFromRecords(await loadAllPasskeyRecipients());
    } catch {
        return {};
    }
}

async function sealVerified(receipt) {
    const { signatureVerified } = await verifyReceipt(receipt, {
        allowMock: false, publicKeys: await knownPublicKeys(),
    });
    return sealReceipt({ ...receipt, signatureVerified }, false);
}

export async function performPrfTap({ pairs, rpId, action, destination, origin, cipherId }) {
    if (!Array.isArray(pairs) || pairs.length === 0) {
        throw new NoHardwareError(
            'performPrfTap: this blob carries no webauthn-prf recipient stanza, '
            + 'so no hardware tap can open it',
        );
    }
    const purpose = newPurpose({ action, destination, cipherId, origin });
    const backend = selectedBackend();
    if (backend === BACKEND_MOCK) {
        const mod = await loadMockBackend();
        const r = await mod.mockPrfTap({ pairs, action, destination, origin });
        return {
            credentialId: r.credentialId,
            prfOutput: r.prfOutput,
            receipt: sealReceipt({ ...r.receipt, purpose }, true),
        };
    }
    if (!webauthnAvailable()) {
        throw new NoHardwareError(
            'WebAuthn is unavailable in this context. A hardware tap cannot be performed '
            + 'from a service worker or a page script -- it must run in an extension page.',
        );
    }
    const r = await passkeyUnlockMulti({ pairs, rpId, purpose });
    return {
        credentialId: r.credentialId,
        prfOutput: r.prfOutput,
        receipt: await sealVerified({
            backend: BACKEND_WEBAUTHN_PRF,
            mock: false,
            label: 'WebAuthn PRF assertion',
            at: Date.now(),
            action: String(action || ''),
            destination: String(destination || ''),
            origin: String(origin || ''),
            credentialIdB64: bytesToB64(r.credentialId),
            userPresent: !!(r.flags && r.flags.userPresent),
            userVerified: !!(r.flags && r.flags.userVerified),
            ...r.evidence,
        }),
    };
}

function askWorker(message) {
    const c = globalThis.chrome;
    if (!c || !c.runtime || typeof c.runtime.sendMessage !== 'function') {
        return Promise.reject(new NoHardwareError('the passkey relay needs the extension worker'));
    }
    return new Promise((resolve, reject) => {
        c.runtime.sendMessage(message, (r) => {
            const err = c.runtime.lastError;
            if (err) reject(new Error(err.message || 'worker port error'));
            else resolve(r);
        });
    });
}

/**
 * A phone passkey (rp id ragewarden.decent.foundation) through the relay page:
 * the worker opens it, checks the answer, and the answer is checked again here
 * against the passkey's published key before its PRF output is used.
 * `credentials` are the registry's phone passkeys (relayCredentialsFromRegistry).
 */
export async function performRelayPrfTap({ pairs, credentials, action, destination, origin, cipherId }) {
    const asked = [];
    for (const p of pairs || []) {
        const id = bytesToB64(p.credentialId);
        const c = (credentials || []).find(x => sameCredentialId(x.credentialIdB64, id));
        if (c) asked.push({ ...c, credentialIdB64: id, saltB64: bytesToB64(p.salt) });
    }
    if (asked.length === 0) {
        throw new NoHardwareError('this item names no phone passkey with a published key');
    }
    const purpose = newPurpose({ action, destination, cipherId, origin });
    const resp = await askWorker({
        kind: 'relay.prf', purpose, credentials: asked,
        action: String(action || ''), destination: String(destination || ''),
    });
    if (!resp || !resp.ok) throw new Error((resp && resp.error) || 'the passkey relay failed');
    const assertion = resp.assertion || {};
    const checked = await verifyRelayAssertion({
        result: { ...assertion, prfFirst: resp.prfOutputB64 }, purpose, credentials: asked,
    });
    const used = asked.find(c => sameCredentialId(c.credentialIdB64, checked.credentialIdB64));
    const receipt = {
        backend: BACKEND_WEBAUTHN_PRF,
        mock: false,
        label: 'WebAuthn PRF assertion through the passkey relay',
        relay: RELAY_ORIGIN,
        at: Date.now(),
        action: String(action || ''),
        destination: String(destination || ''),
        origin: String(origin || ''),
        credentialIdB64: used.credentialIdB64,
        userPresent: checked.flags.userPresent,
        userVerified: checked.flags.userVerified,
        purpose,
        clientDataJSON: assertion.clientDataJSON,
        authenticatorData: assertion.authenticatorData,
        signature: assertion.signature,
    };
    const { signatureVerified } = await verifyReceipt(receipt, {
        allowMock: false,
        publicKeys: { [used.credentialIdB64]: { spkiB64: used.spkiB64, alg: used.alg } },
    });
    if (!signatureVerified) throw new Error('the relayed assertion could not be verified -- refusing');
    return {
        credentialId: b64ToBytes(used.credentialIdB64),
        prfOutput: checked.prfOutput,
        receipt: sealReceipt({ ...receipt, signatureVerified }, false),
    };
}

export async function performPresenceTap({ credentialIds, rpId, action, destination, origin, cipherId }) {
    if (!Array.isArray(credentialIds) || credentialIds.length === 0) {
        throw new NoHardwareError(
            'performPresenceTap: no passkey is enrolled in this browser profile, so there is '
            + 'no hardware to tap. Enrol a passkey (or use paper recovery) before releasing '
            + 'any secret.',
        );
    }
    const purpose = newPurpose({ action, destination, cipherId, origin });
    const backend = selectedBackend();
    if (backend === BACKEND_MOCK) {
        const mod = await loadMockBackend();
        const r = await mod.mockPresenceTap({ credentialIds, action, destination, origin });
        return { receipt: sealReceipt({ ...r.receipt, purpose }, true) };
    }
    if (!webauthnAvailable()) {
        throw new NoHardwareError(
            'WebAuthn is unavailable in this context. A hardware tap cannot be performed '
            + 'from a service worker or a page script -- it must run in an extension page.',
        );
    }
    const r = await passkeyPresenceAssert({ credentialIds, rpId, purpose });
    return {
        receipt: await sealVerified({
            backend: BACKEND_WEBAUTHN_PRF,
            mock: false,
            label: 'WebAuthn presence assertion (item is NOT hardware-encrypted)',
            at: Date.now(),
            action: String(action || ''),
            destination: String(destination || ''),
            origin: String(origin || ''),
            credentialIdB64: bytesToB64(r.credentialId),
            userPresent: !!(r.flags && r.flags.userPresent),
            userVerified: !!(r.flags && r.flags.userVerified),
            ...r.evidence,
        }),
    };
}

/**
 * Refusal raised when a native-host reply cannot be turned into a receipt.
 *
 * Distinct from NoHardwareError on purpose: "there is no key here" is a state a
 * caller may recover from by trying another identity, whereas "a host answered
 * and its answer does not evidence a ceremony" must never be retried into a
 * success. Callers propagate this; nothing swallows it.
 */
export class NativeTapRefusedError extends Error {
    constructor(message) {
        super(`hardware-tap: ${message}`);
        this.name = 'NativeTapRefusedError';
        this.code = 'native_tap_refused';
    }
}

/**
 * Build a receipt for a ceremony performed by the rageterm native host.
 *
 * `tap` is CONTRACT 1: the block rageterm attaches to an `unwrap_stanza` reply
 * -- `{ backend, touched, verified, device, slot, at }`. Everything read out of
 * it is read strictly: `touched`/`verified` must be actual booleans, not
 * truthy, so an absent field cannot arrive as "yes" and a string "false" cannot
 * arrive as "yes" either. The truth VALUES are not judged here -- `touched:
 * false` produces `userPresent: false` and is refused by sealReceipt()'s
 * pre-existing real-backend rule, which is the rule this bridge was required to
 * pass rather than route around.
 *
 * Nothing in this receipt is verifiable by the browser. The host is a separate
 * process reached over a pipe, and a compromised or patched host can put
 * `touched: true` on a reply it read off disk. What this function buys is that
 * the browser fails closed on every reply that does NOT claim a ceremony, and
 * that the claim is recorded in the same evidence trail as a real assertion so
 * an audit can see which unlocks rested on it.
 */
export function performNativeHostTap({
    tap, attested = false, host = '', action = '', destination = '', origin = '', cipherId = '',
} = {}) {
    if (!tap || typeof tap !== 'object') {
        throw new NativeTapRefusedError(
            'the native host replied without a `tap` block, so nothing in the reply '
            + 'distinguishes a touched device from a key read off disk (rageterm serves '
            + 'exactly that shape under RAGEWARDEN_NATIVE_HOST_ALLOW_SOFTWARE=1)',
        );
    }
    const tapBackend = typeof tap.backend === 'string' ? tap.backend : '';
    if (!NATIVE_HOST_TAP_BACKENDS.includes(tapBackend)) {
        throw new NativeTapRefusedError(
            `the native host named tap.backend=${JSON.stringify(tap.backend)}, which is not `
            + `one of ${NATIVE_HOST_TAP_BACKENDS.join(', ')} -- refusing a ceremony this side `
            + 'cannot name',
        );
    }
    if (typeof tap.touched !== 'boolean' || typeof tap.verified !== 'boolean') {
        throw new NativeTapRefusedError(
            'tap.touched and tap.verified must be booleans; a missing or non-boolean flag '
            + 'is a malformed attestation, and this side does not guess in the direction '
            + 'that releases a secret',
        );
    }
    return sealReceipt({
        backend: BACKEND_NATIVE_HOST,
        mock: false,
        label: `rageterm native host (${tapBackend})`,
        at: Date.now(),
        action: String(action || ''),
        destination: String(destination || ''),
        origin: String(origin || ''),
        host: String(host || ''),
        tapBackend,
        device: String(tap.device || ''),
        slot: String(tap.slot || ''),
        hostAt: Number.isFinite(tap.at) ? tap.at : 0,
        attested: attested === true,
        purpose: newPurpose({ action, destination, cipherId, origin }),
        userPresent: tap.touched === true,
        userVerified: tap.verified === true,
    }, false);
}

/**
 * Create a credential, through the same backend gate as every other ceremony.
 *
 * Enrolment used to bypass this file entirely -- `vault.enrollPasskey` called
 * `navigator.credentials.create` directly. That left mock builds half-built: a
 * VM could fabricate a tap but could not fabricate the credential to tap, so it
 * could never publish a recipient, never write a rage-protected item, and never
 * reach the tap path the mock existed to exercise.
 *
 * The returned receipt is not a decrypt authorisation and no caller treats it
 * as one; it is here so an enrolment shows up in the same evidence trail.
 */
export async function performPrfEnroll(opts = {}) {
    const backend = selectedBackend();
    if (backend === BACKEND_MOCK) {
        const mod = await loadMockBackend();
        if (typeof mod.mockEnroll !== 'function') {
            throw new Error(
                'hardware-tap: the mock backend in this bundle predates mockEnroll(); '
                + 'rebuild the extension. Refusing to fall back to a real credential '
                + 'ceremony the caller did not ask for.',
            );
        }
        const r = await mod.mockEnroll(opts);
        return { record: r.record, receipt: sealReceipt(r.receipt, true) };
    }
    if (!webauthnAvailable() || typeof navigator.credentials.create !== 'function') {
        throw new NoHardwareError(
            'WebAuthn credential creation is unavailable in this context. Enrolment must run '
            + 'in an extension page with an authenticator reachable from this browser.',
        );
    }
    const { record, prfOutput } = await passkeyEnroll(opts);
    return {
        record,
        prfOutput,
        receipt: sealReceipt({
            backend: BACKEND_WEBAUTHN_PRF,
            mock: false,
            label: 'WebAuthn credential creation',
            at: Date.now(),
            action: 'enroll',
            destination: String(opts.label || ''),
            origin: String(opts.origin || ''),
            credentialIdB64: record.credential_id_b64,
            // navigator.credentials.create only resolves after the authenticator
            // has performed the user gesture it was asked for; there is no
            // attestation-free way to read UP/UV off a create() the way
            // authenticatorData gives it to us on get().
            userPresent: true,
            userVerified: true,
        }, false),
    };
}

export function assertReceiptIsRealTap(receipt) {
    checkReceiptShape(receipt, { allowMock: mockTapAllowed() });
}
