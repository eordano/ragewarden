import { test } from 'node:test';
import assert from 'node:assert/strict';
import { kdfFromSession, loadKdfPin, pinKey, saveKdfPinFromSession } from '../../ext/glue/kdf-pin.js';

function area() {
    const data = {};
    return {
        data,
        get: (keys, cb) => cb(Object.fromEntries(keys.filter(k => k in data).map(k => [k, data[k]]))),
        set: (items, cb) => { Object.assign(data, items); cb(); },
    };
}

test('a pin is kept per server origin and lower-cased email', async () => {
    const a = area();
    await saveKdfPinFromSession('https://vault.example.test/', 'Me@Example.test',
        { kdf_type: 0, kdf_iterations: 600000 }, a);
    assert.deepEqual(await loadKdfPin('https://vault.example.test', 'me@example.test', a), { kdf: 0, iterations: 600000 });
    assert.equal(await loadKdfPin('https://other.example.test', 'me@example.test', a), null);
    assert.equal(pinKey('https://vault.example.test/x', ' ME@x '), 'https://vault.example.test|me@x');
});

test('Argon2id sessions pin memory and parallelism in core\'s camelCase shape', () => {
    assert.deepEqual(kdfFromSession(JSON.stringify({ kdf_type: 1, kdf_iterations: 3, kdf_memory_mib: 64, kdf_parallelism: 4 })),
        { kdf: 1, iterations: 3, memoryMib: 64, parallelism: 4 });
    assert.equal(kdfFromSession({}), null);
});

test('a later login replaces the pin (an upgrade raises it)', async () => {
    const a = area();
    await saveKdfPinFromSession('https://v.test', 'a@b', { kdf_type: 0, kdf_iterations: 5000 }, a);
    await saveKdfPinFromSession('https://v.test', 'a@b', { kdf_type: 0, kdf_iterations: 600000 }, a);
    assert.equal((await loadKdfPin('https://v.test', 'a@b', a)).iterations, 600000);
});
