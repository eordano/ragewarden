import {
    authenticatorFlags, checkClientData, samePurpose, verifyAssertionSignature,
} from './assertion.js';
import { b64ToBytes } from './b64.js';

export const BACKEND_WEBAUTHN_PRF = 'webauthn-prf';
export const BACKEND_MOCK = 'MOCK-NO-DEVICE';
export const BACKEND_NATIVE_HOST = 'native-host-rageterm';
export const NATIVE_HOST_TAP_BACKENDS = Object.freeze(['piv-x25519-v2', 'piv-p256', 'fido2-hmac']);
const REAL_BACKENDS = Object.freeze([BACKEND_WEBAUTHN_PRF, BACKEND_NATIVE_HOST]);

export function checkReceiptShape(receipt, { allowMock }) {
    if (!receipt || typeof receipt !== 'object') {
        throw new Error('no tap receipt: refusing to release plaintext');
    }
    if (receipt.mock === true) {
        if (!allowMock) {
            throw new Error(
                'tap receipt is marked mock:true but this build forbids mock taps -- '
                + 'refusing to release plaintext',
            );
        }
        return;
    }
    if (!REAL_BACKENDS.includes(receipt.backend)
        || receipt.userPresent !== true
        || receipt.userVerified !== true) {
        throw new Error('tap receipt does not evidence a real, user-verified presence check');
    }
    if (receipt.backend === BACKEND_NATIVE_HOST
        && !NATIVE_HOST_TAP_BACKENDS.includes(receipt.tapBackend)) {
        throw new Error(
            'native-host tap receipt names no hardware backend -- refusing to release plaintext',
        );
    }
}

export async function verifyReceipt(receipt, { allowMock, request = null, publicKeys = {} }) {
    checkReceiptShape(receipt, { allowMock });
    if (receipt.mock === true) return { mock: true, signatureVerified: false };
    if (request && !samePurpose(receipt.purpose, request)) {
        throw new Error(
            'tap receipt was produced for a different action, item or destination than the '
            + 'one being released -- refusing',
        );
    }
    if (receipt.backend !== BACKEND_WEBAUTHN_PRF) return { mock: false, signatureVerified: false };
    if (!receipt.clientDataJSON || !receipt.authenticatorData || !receipt.signature) {
        throw new Error('WebAuthn receipt carries no assertion to check -- refusing');
    }
    await checkClientData(b64ToBytes(receipt.clientDataJSON), receipt.purpose);
    const flags = authenticatorFlags(b64ToBytes(receipt.authenticatorData));
    if (!flags.userPresent || !flags.userVerified) {
        throw new Error('WebAuthn receipt authenticatorData lacks user presence or verification');
    }
    const pk = publicKeys[receipt.credentialIdB64];
    if (!pk || !pk.spkiB64) return { mock: false, signatureVerified: false };
    const ok = await verifyAssertionSignature({
        publicKeySpki: pk.spkiB64,
        alg: pk.alg,
        authenticatorData: receipt.authenticatorData,
        clientDataJSON: receipt.clientDataJSON,
        signature: receipt.signature,
    });
    if (!ok) throw new Error('WebAuthn receipt signature does not verify -- refusing');
    return { mock: false, signatureVerified: true };
}

export function publicKeysFromRecords(records) {
    const out = {};
    for (const r of records || []) {
        if (r && r.credential_id_b64 && r.public_key_spki_b64) {
            out[r.credential_id_b64] = { spkiB64: r.public_key_spki_b64, alg: r.public_key_alg };
        }
    }
    return out;
}
