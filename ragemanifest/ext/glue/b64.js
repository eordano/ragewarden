export function bytesToB64(bytes) {
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let s = '';
    for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
    return btoa(s);
}

export function b64ToBytes(b64) {
    const s = atob(String(b64).replace(/-/g, '+').replace(/_/g, '/'));
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
}

export function bytesToB64Url(bytes) {
    return bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function bytesToHex(bytes) {
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let hex = '';
    for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, '0');
    return hex;
}

export function hexFromB64(b64) {
    return bytesToHex(b64ToBytes(b64));
}

export function hexToBytes(hex) {
    const s = String(hex || '');
    const out = new Uint8Array(Math.floor(s.length / 2));
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
    return out;
}

export function b64FromHex(hex) {
    return bytesToB64(hexToBytes(hex));
}

export async function sha256Hex(input) {
    const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
    return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}
