/**
 * Software stand-in for a hardware authenticator.
 *
 * NOTHING HERE TOUCHES A DEVICE. Every "tap" below is a pure function of a
 * constant committed to this repository, so anyone holding a blob wrapped by
 * this backend can unwrap it with nothing but the source. It exists so a VM
 * with no USB, no NFC and no platform authenticator can drive the popup end to
 * end -- see `build.mjs --vm`.
 *
 * Three fences keep it out of a shipped extension:
 *   1. `build.mjs` deletes `glue/dev-only/` from any build without
 *      `--allow-mock-tap`, and `assertDistIsSane()` fails if it survives;
 *   2. `hardware-tap.js loadMockBackend()` refuses to import this module unless
 *      the build flags allow it;
 *   3. the module-scope check below throws on import if it is ever loaded into
 *      a build that forbids mock taps, so a strip bug fails hard at load time
 *      instead of silently downgrading a tap.
 *
 * Every receipt is stamped `mock: true`. `sealReceipt()` rejects a mock receipt
 * from the real backend and vice versa, and `assertReceiptIsRealTap()` refuses
 * to release plaintext against a mock receipt unless the build allows one.
 */

import { mockTapAllowed } from '../build-flags.js';

if (!mockTapAllowed()) {
    throw new Error(
        'glue/dev-only/mock-hardware-tap.js was loaded into a build that forbids mock taps. '
        + 'build.mjs strips this file from release bundles; if you are reading this error the '
        + 'strip did not happen. Refusing to substitute software for a hardware tap.',
    );
}

export const MOCK_BACKEND_ID = 'MOCK-NO-DEVICE';

const MOCK_DOMAIN = 'RAGEWARDEN-MOCK-TAP-NOT-A-DEVICE-v1';
const WARNING = 'MOCK HARDWARE TAP -- NO DEVICE WAS TOUCHED';

function subtle() {
    const c = globalThis.crypto;
    if (!c || !c.subtle) {
        throw new Error('mock-hardware-tap: WebCrypto is unavailable in this context');
    }
    return c.subtle;
}

function bytesToB64(bytes) {
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let s = '';
    for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
    return btoa(s);
}

/**
 * Coerce a credential id or salt to bytes.
 *
 * Both shapes really do arrive. The wasm PRF callback marshals
 * `{credentialId, salt}` as Uint8Array (src/wasm/sync.rs
 * invoke_prf_callback_multi), while the software-identity path in unlock.js
 * passes `software.wrap_credential_id_b64` / `wrap_salt_b64` -- base64 strings.
 *
 * The previous version did `new Uint8Array(value)` for both. On a string that
 * does not throw and does not warn -- it returns a Uint8Array of length ZERO.
 * So on the software-identity path the old mock hashed its domain constant and
 * nothing else, and every credential in every vault derived one single global
 * "PRF" output. It still round-tripped, because wrap and unwrap were wrong in
 * the same direction, so no test noticed and the mock modelled nothing.
 */
function toBytes(value, what) {
    if (value instanceof Uint8Array) return value;
    if (ArrayBuffer.isView(value)) {
        return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (typeof value === 'string') {
        const bin = atob(value);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }
    throw new Error(
        `mock-hardware-tap: ${what} must be Uint8Array or a base64 string, got ${typeof value}`,
    );
}

function concat(...parts) {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
}

function announce(what, detail) {
    // eslint-disable-next-line no-console
    console.warn(`[ragewarden] ${WARNING}: ${what}`, detail || '');
}

/**
 * The stand-in's PRF.
 *
 * Deterministic in (credentialId, salt) because a real PRF is: a secret wrapped
 * under one tap must be unwrappable by the next tap of the same credential with
 * the same salt. A random output here would make every wrap a one-way trip and
 * the round-trip half of any VM scenario untestable.
 *
 * Length-prefixed so that (cred=AB, salt=C) and (cred=A, salt=BC) cannot
 * collide the way a bare concatenation lets them.
 */
export async function mockPrfOutput(credentialId, salt) {
    const cred = toBytes(credentialId, 'credentialId');
    const saltBytes = toBytes(salt, 'salt');
    if (saltBytes.length !== 32) {
        throw new Error(
            `mock-hardware-tap: salt must be 32 bytes, got ${saltBytes.length}`,
        );
    }
    const domain = new TextEncoder().encode(MOCK_DOMAIN);
    const lengths = new Uint8Array(8);
    new DataView(lengths.buffer).setUint32(0, cred.length, false);
    new DataView(lengths.buffer).setUint32(4, saltBytes.length, false);
    const digest = await subtle().digest(
        'SHA-256', concat(domain, lengths, cred, saltBytes),
    );
    return new Uint8Array(digest);
}

function receipt(extra) {
    return {
        backend: MOCK_BACKEND_ID,
        mock: true,
        label: WARNING,
        at: Date.now(),
        // Deliberately false. No user was present and none was verified; the
        // mock branch of assertReceiptIsRealTap() does not read these, and
        // anything that starts reading them should see the truth.
        userPresent: false,
        userVerified: false,
        warning: 'This receipt evidences no physical action. Do not trust it.',
        ...extra,
    };
}

/**
 * Stand in for `performPrfTap`'s WebAuthn assertion.
 *
 * The real path hands the browser every (credentialId, salt) pair the blob
 * carries and lets the authenticator answer for the one it holds. There is one
 * stand-in authenticator, so it answers for the first pair -- the same selection
 * `passkeyUnlockMulti` gets from `allowCredentials` ordering.
 */
export async function mockPrfTap({ pairs, action, destination, origin }) {
    if (!Array.isArray(pairs) || pairs.length === 0) {
        throw new Error('mockPrfTap: pairs must not be empty');
    }
    const chosen = pairs[0];
    const credentialId = toBytes(chosen.credentialId, 'credentialId');
    const prfOutput = await mockPrfOutput(credentialId, chosen.salt);
    announce('PRF evaluation', { action, destination, origin, candidates: pairs.length });
    return {
        credentialId,
        prfOutput,
        receipt: receipt({
            action: String(action || ''),
            destination: String(destination || ''),
            origin: String(origin || ''),
            credentialIdB64: bytesToB64(credentialId),
            candidates: pairs.length,
        }),
    };
}

/** Stand in for `performPresenceTap` -- a receipt, never key material. */
export async function mockPresenceTap({ credentialIds, action, destination, origin }) {
    const first = Array.isArray(credentialIds) && credentialIds.length > 0
        ? toBytes(credentialIds[0], 'credentialId')
        : new Uint8Array(0);
    announce('presence assertion', { action, destination, origin });
    return {
        credentialId: first,
        receipt: receipt({
            label: `${WARNING} (item is NOT hardware-encrypted)`,
            action: String(action || ''),
            destination: String(destination || ''),
            origin: String(origin || ''),
            credentialIdB64: first.length ? bytesToB64(first) : '',
        }),
    };
}

/**
 * Stand in for `navigator.credentials.create`.
 *
 * Without this there is no fake mode at all: `enrollPasskey` reaches
 * `navigator.credentials.create` directly, so a VM with no authenticator can
 * never enrol, never publish a recipient, and therefore never write a
 * rage-protected item to open. The mock tap had nothing to tap.
 *
 * The credential id is derived from (rpId, seed) rather than drawn at random so
 * a re-run still opens the vault the last run wrote. `opts.mockSeed` is the
 * escape hatch for a scenario that wants two distinct stand-in credentials.
 */
export async function mockEnroll(opts = {}) {
    const rpId = opts.rpId || 'ragewarden-mock';
    const label = opts.label || 'Mock passkey';
    const seed = String(opts.mockSeed ?? label);
    const salt = opts.salt
        ? toBytes(opts.salt, 'salt')
        : new Uint8Array(await subtle().digest(
            'SHA-256', new TextEncoder().encode(`${MOCK_DOMAIN}|salt|${rpId}|${seed}`),
        ));
    if (salt.length !== 32) {
        throw new Error(`mockEnroll: salt must be 32 bytes, got ${salt.length}`);
    }
    const credentialId = new Uint8Array(await subtle().digest(
        'SHA-256', new TextEncoder().encode(`${MOCK_DOMAIN}|credential|${rpId}|${seed}`),
    ));
    announce('credential creation', { rpId, label });
    return {
        record: {
            kind: 'passkey_prf',
            credential_id_b64: bytesToB64(credentialId),
            salt_b64: bytesToB64(salt),
            rp_id: rpId,
            label: `${label} (MOCK -- NOT REAL HARDWARE)`,
        },
        receipt: receipt({
            action: 'enroll',
            destination: 'create a stand-in credential',
            origin: String(opts.origin || ''),
            credentialIdB64: bytesToB64(credentialId),
        }),
    };
}
