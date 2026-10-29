import test from 'node:test';
import assert from 'node:assert/strict';
import {
    b64FromHex, b64ToBytes, bytesToB64, bytesToB64Url, bytesToHex, hexFromB64, hexToBytes, sha256Hex,
} from '../../ext/glue/b64.js';

test('base64, base64url and hex round-trip', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255, 62, 63]);
    assert.deepEqual(b64ToBytes(bytesToB64(bytes)), bytes);
    assert.deepEqual(b64ToBytes(bytesToB64Url(bytes)), bytes);
    assert.ok(!/[+/=]/.test(bytesToB64Url(bytes)));
    assert.equal(b64FromHex(hexFromB64(bytesToB64(bytes))), bytesToB64(bytes));
});

test('hex round-trips and sha256Hex hashes strings and bytes alike', async () => {
    const bytes = new Uint8Array([0, 15, 16, 255]);
    assert.equal(bytesToHex(bytes), '000f10ff');
    assert.deepEqual(hexToBytes('000f10ff'), bytes);
    const abc = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
    assert.equal(await sha256Hex('abc'), abc);
    assert.equal(await sha256Hex(new TextEncoder().encode('abc')), abc);
});
