import { b64ToBytes, bytesToB64, bytesToB64Url } from './b64.js';

const PURPOSE_FIELDS = Object.freeze(['action', 'destination', 'cipherId', 'origin', 'nonce']);

export function canonicalPurpose(purpose) {
    const out = {};
    for (const k of PURPOSE_FIELDS) out[k] = String((purpose && purpose[k]) || '');
    return out;
}

export function newPurpose(fields) {
    const nonce = bytesToB64(crypto.getRandomValues(new Uint8Array(16)));
    return canonicalPurpose({ ...fields, nonce });
}

export async function purposeChallenge(purpose) {
    const json = JSON.stringify(canonicalPurpose(purpose));
    return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(json)));
}

export function samePurpose(a, b, fields = ['action', 'destination', 'cipherId', 'origin']) {
    const ca = canonicalPurpose(a);
    const cb = canonicalPurpose(b);
    return fields.every(k => ca[k] === cb[k]);
}

function derToRawEcdsa(der) {
    if (der.length === 64) return der;
    let i = 0;
    if (der[i++] !== 0x30) throw new Error('ECDSA signature is not a DER sequence');
    if (der[i] & 0x80) i += 1 + (der[i] & 0x7f); else i += 1;
    const readInt = () => {
        if (der[i++] !== 0x02) throw new Error('ECDSA signature component is not an INTEGER');
        const len = der[i++];
        let v = der.slice(i, i + len);
        i += len;
        while (v.length > 32 && v[0] === 0) v = v.slice(1);
        if (v.length > 32) throw new Error('ECDSA signature component longer than 32 bytes');
        const padded = new Uint8Array(32);
        padded.set(v, 32 - v.length);
        return padded;
    };
    const r = readInt();
    const s = readInt();
    const out = new Uint8Array(64);
    out.set(r, 0);
    out.set(s, 32);
    return out;
}

async function importVerifyKey(spki, alg) {
    if (alg === -7) {
        return {
            key: await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']),
            params: { name: 'ECDSA', hash: 'SHA-256' },
            raw: true,
        };
    }
    if (alg === -257) {
        return {
            key: await crypto.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']),
            params: { name: 'RSASSA-PKCS1-v1_5' },
            raw: false,
        };
    }
    if (alg === -8) {
        return {
            key: await crypto.subtle.importKey('spki', spki, { name: 'Ed25519' }, false, ['verify']),
            params: { name: 'Ed25519' },
            raw: false,
        };
    }
    throw new Error(`unsupported credential algorithm ${alg}`);
}

export function parseClientData(clientDataJSON) {
    const text = new TextDecoder().decode(clientDataJSON);
    const data = JSON.parse(text);
    if (!data || typeof data !== 'object') throw new Error('clientDataJSON is not an object');
    return data;
}

export async function checkClientData(clientDataJSON, purpose, type = 'webauthn.get') {
    const data = parseClientData(clientDataJSON);
    if (data.type !== type) {
        throw new Error(`assertion clientData.type is ${JSON.stringify(data.type)}, expected ${type}`);
    }
    const expected = bytesToB64Url(await purposeChallenge(purpose));
    if (data.challenge !== expected) {
        throw new Error('assertion challenge does not match the action it was requested for');
    }
    return data;
}

export async function verifyAssertionSignature({
    publicKeySpki, alg, authenticatorData, clientDataJSON, signature,
}) {
    const spki = publicKeySpki instanceof Uint8Array ? publicKeySpki : b64ToBytes(publicKeySpki);
    const ad = authenticatorData instanceof Uint8Array ? authenticatorData : b64ToBytes(authenticatorData);
    const cd = clientDataJSON instanceof Uint8Array ? clientDataJSON : b64ToBytes(clientDataJSON);
    let sig = signature instanceof Uint8Array ? signature : b64ToBytes(signature);
    const { key, params, raw } = await importVerifyKey(spki, Number(alg));
    if (raw) sig = derToRawEcdsa(sig);
    const cdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', cd));
    const signed = new Uint8Array(ad.length + cdHash.length);
    signed.set(ad, 0);
    signed.set(cdHash, ad.length);
    return crypto.subtle.verify(params, key, sig, signed);
}

export function authenticatorFlags(authenticatorData) {
    const bytes = authenticatorData instanceof Uint8Array
        ? authenticatorData
        : new Uint8Array(authenticatorData || []);
    if (bytes.length < 33) return { userPresent: false, userVerified: false, known: false };
    const f = bytes[32];
    return { userPresent: (f & 0x01) !== 0, userVerified: (f & 0x04) !== 0, known: true };
}

export const __testing = { derToRawEcdsa };
