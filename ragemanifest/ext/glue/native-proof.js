/**
 * native-unwrap-proof-v1: the native host proves a device touch by signing a
 * fresh per-unwrap challenge with a key the device holds.
 *
 * Request:  { method: 'unwrap_stanza', stanza, context, challenge }
 *           challenge = base64 of 32 random bytes, new for every unwrap.
 * Response: tap.proof, one of
 *   { alg: 'ES256', public_key, signature }
 *       a P-256 PIV slot: signature = base64 of the 64-byte r||s ECDSA-SHA256
 *       signature over proofMessage();
 *   { kind: 'fido2-assertion', alg: 'ES256', public_key, authenticatorData, signature }
 *       a FIDO2 credential: its assertion with clientDataHash =
 *       SHA-256(proofMessage()), so signature (r||s) covers authenticatorData ||
 *       clientDataHash, and authenticatorData must carry the UP flag.
 *   public_key = base64 SPKI DER of the device's P-256 key.
 *
 * The browser trusts a proof only from the key the registry publishes as the
 * attestationPublicKey of the recipient the stanza is addressed to
 * (attestationKeysForStanza); when that recipient publishes one, a reply
 * without a valid proof is refused. A recipient that publishes none (an X25519
 * PIV slot, a FIDO2 credential not yet attested) yields an unattested receipt.
 */

import { b64ToBytes, bytesToB64, bytesToHex, hexToBytes, sha256Hex } from './b64.js';

export const PROOF_VERSION = 'ragewarden-native-unwrap-v1';
export const FIDO2_ASSERTION = 'fido2-assertion';

const enc = new TextEncoder();
const cryptoApi = () => globalThis.crypto.subtle;

export function newChallenge() {
    return bytesToB64(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

/** The exact bytes the device signs: the challenge, the stanza and what the key is for. */
export async function proofMessage({ challenge, stanza, action = '', destination = '' }) {
    const body = enc.encode(`${stanza.tag}\n${(stanza.args || []).join(' ')}\n${stanza.body || ''}`);
    return enc.encode([
        PROOF_VERSION, challenge, stanza.tag, await sha256Hex(body), action, destination,
    ].join('\n'));
}

/**
 * The attestation keys of the registry entries `stanza` is addressed to: a PIV
 * stanza names its slot by SHA-256(public key)[0..4] (the 6-character argument),
 * a fido2-hmac stanza its credential by args[0] (base64url).
 */
export async function attestationKeysForStanza(stanza, entries = []) {
    const keyed = (entries || []).filter(e => e && typeof e.attestationPublicKey === 'string');
    const args = (stanza && stanza.args) || [];
    if (stanza && stanza.tag === 'fido2-hmac') {
        const credHex = bytesToHex(b64ToBytes(args[0] || ''));
        return keyed.filter(e => String(e.fido2CredentialId || '').toLowerCase() === credHex)
            .map(e => e.attestationPublicKey);
    }
    if (stanza && (stanza.tag === 'piv-p256' || stanza.tag === 'piv-x25519-v2')) {
        const tag = args.find(a => a.length === 6);
        if (!tag) return [];
        const out = [];
        for (const e of keyed) {
            if (!e.pivPubkey) continue;
            const d = new Uint8Array(await cryptoApi().digest('SHA-256', hexToBytes(e.pivPubkey)));
            if (bytesToB64(d.subarray(0, 4)).replace(/=+$/, '') === tag) out.push(e.attestationPublicKey);
        }
        return out;
    }
    return [];
}

export class NativeProofError extends Error {
    constructor(message) {
        super(message);
        this.name = 'NativeProofError';
        this.code = 'native_proof_invalid';
    }
}

/**
 * Resolve { attested } or throw. attested:false only when no trusted key was
 * supplied and the host sent no proof -- an unsigned claim, recorded as such.
 */
export async function verifyUnwrapProof({ proof, challenge, stanza, context = {}, trustedKeys = [] }) {
    const trusted = new Set(trustedKeys.filter(Boolean));
    if (!proof) {
        if (trusted.size > 0) {
            throw new NativeProofError(
                'this recipient publishes an attestation key and the host sent no signed proof of the touch',
            );
        }
        return { attested: false };
    }
    if (proof.alg !== 'ES256') throw new NativeProofError(`unsupported proof alg ${JSON.stringify(proof.alg)}`);
    if (!trusted.has(proof.public_key)) {
        throw new NativeProofError('the proof is signed by a key no registry entry publishes for this recipient');
    }
    const key = await cryptoApi().importKey('spki', b64ToBytes(proof.public_key),
        { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const message = await proofMessage({
        challenge, stanza, action: context.action || '', destination: context.destination || '',
    });
    let signed;
    if (proof.kind === undefined || proof.kind === null) {
        signed = message;
    } else if (proof.kind === FIDO2_ASSERTION) {
        const auth = b64ToBytes(proof.authenticatorData || '');
        if (auth.length < 37) throw new NativeProofError('the FIDO2 proof has no authenticatorData');
        if ((auth[32] & 0x01) === 0) {
            throw new NativeProofError('the FIDO2 assertion does not carry the user-presence flag');
        }
        const clientDataHash = new Uint8Array(await cryptoApi().digest('SHA-256', message));
        signed = new Uint8Array(auth.length + clientDataHash.length);
        signed.set(auth);
        signed.set(clientDataHash, auth.length);
    } else {
        throw new NativeProofError(`unsupported proof kind ${JSON.stringify(proof.kind)}`);
    }
    const ok = await cryptoApi().verify({ name: 'ECDSA', hash: 'SHA-256' }, key,
        b64ToBytes(proof.signature), signed);
    if (!ok) throw new NativeProofError('the touch proof does not verify for this challenge, stanza and destination');
    return { attested: true };
}
