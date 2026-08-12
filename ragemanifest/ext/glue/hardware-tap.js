import { BUILD_FLAGS, mockTapAllowed } from './build-flags.js';
import { passkeyEnroll, passkeyUnlockMulti, passkeyPresenceAssert } from './passkey.js';

export { mockTapAllowed };

export const BACKEND_WEBAUTHN_PRF = 'webauthn-prf';
export const BACKEND_MOCK = 'MOCK-NO-DEVICE';

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
export const BACKEND_NATIVE_HOST = 'native-host-rageterm';

/*
 * `tap.backend` values a native-host reply may carry. These are the stanza
 * families rageterm gates on a physical touch (`tag_is_hardware_gated` in
 * rageterm/src/native_host.rs). Anything else -- including a reply that names
 * `webauthn-prf-v1`, which this browser opens itself with a real assertion -- is
 * a malformed reply, not a new backend to trust.
 */
export const NATIVE_HOST_TAP_BACKENDS = Object.freeze(['piv-p256', 'fido2-hmac']);

/*
 * Backends whose receipts assert a real ceremony. Membership here is the only
 * thing that gets a receipt past assertReceiptIsRealTap() without `mock: true`,
 * so adding a value is a security decision, not bookkeeping.
 */
const REAL_BACKENDS = Object.freeze([BACKEND_WEBAUTHN_PRF, BACKEND_NATIVE_HOST]);

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

function bytesToB64(bytes) {
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let s = '';
    for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
    return btoa(s);
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

export async function performPrfTap({ pairs, rpId, action, destination, origin }) {
    if (!Array.isArray(pairs) || pairs.length === 0) {
        throw new NoHardwareError(
            'performPrfTap: this blob carries no webauthn-prf recipient stanza, '
            + 'so no hardware tap can open it',
        );
    }
    const backend = selectedBackend();
    if (backend === BACKEND_MOCK) {
        const mod = await loadMockBackend();
        const r = await mod.mockPrfTap({ pairs, action, destination, origin });
        return {
            credentialId: r.credentialId,
            prfOutput: r.prfOutput,
            receipt: sealReceipt(r.receipt, true),
        };
    }
    if (!webauthnAvailable()) {
        throw new NoHardwareError(
            'WebAuthn is unavailable in this context. A hardware tap cannot be performed '
            + 'from a service worker or a page script -- it must run in an extension page.',
        );
    }
    const r = await passkeyUnlockMulti({ pairs, rpId, action, destination });
    return {
        credentialId: r.credentialId,
        prfOutput: r.prfOutput,
        receipt: sealReceipt({
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
        }, false),
    };
}

export async function performPresenceTap({ credentialIds, rpId, action, destination, origin }) {
    if (!Array.isArray(credentialIds) || credentialIds.length === 0) {
        throw new NoHardwareError(
            'performPresenceTap: no passkey is enrolled in this browser profile, so there is '
            + 'no hardware to tap. Enrol a passkey (or use paper recovery) before releasing '
            + 'any secret.',
        );
    }
    const backend = selectedBackend();
    if (backend === BACKEND_MOCK) {
        const mod = await loadMockBackend();
        const r = await mod.mockPresenceTap({ credentialIds, action, destination, origin });
        return { receipt: sealReceipt(r.receipt, true) };
    }
    if (!webauthnAvailable()) {
        throw new NoHardwareError(
            'WebAuthn is unavailable in this context. A hardware tap cannot be performed '
            + 'from a service worker or a page script -- it must run in an extension page.',
        );
    }
    const r = await passkeyPresenceAssert({ credentialIds, rpId });
    return {
        receipt: sealReceipt({
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
        }, false),
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
    tap, host = '', action = '', destination = '', origin = '',
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
    if (!receipt || typeof receipt !== 'object') {
        throw new Error('no tap receipt: refusing to release plaintext');
    }
    if (receipt.mock === true) {
        if (!mockTapAllowed()) {
            throw new Error(
                'tap receipt is marked mock:true but this build forbids mock taps -- '
                + 'refusing to release plaintext',
            );
        }
        return;
    }
    // Re-checked here rather than trusted from sealReceipt(): a receipt crosses
    // a message port (tap page -> background) before it reaches this gate, so
    // the last thing to read it must be the thing that decides.
    if (!REAL_BACKENDS.includes(receipt.backend)
        || receipt.userPresent !== true
        || receipt.userVerified !== true) {
        throw new Error(
            'tap receipt does not evidence a real, user-verified presence check',
        );
    }
    // A native-host receipt additionally has to name which hardware family
    // answered. performNativeHostTap() already checked this, but that ran
    // before the receipt crossed a port, and the whole point of this function
    // is that the last reader decides.
    if (receipt.backend === BACKEND_NATIVE_HOST
        && !NATIVE_HOST_TAP_BACKENDS.includes(receipt.tapBackend)) {
        throw new Error(
            'native-host tap receipt names no hardware backend -- refusing to release plaintext',
        );
    }
}
