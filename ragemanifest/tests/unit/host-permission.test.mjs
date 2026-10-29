import { test } from 'node:test';
import assert from 'node:assert/strict';
import { missingServerOrigin, requestServerPermission } from '../../ext/glue/host-permission.js';

function fakePermissions(granted = new Set(), answer = true) {
    const asked = [];
    return {
        asked,
        request: async ({ origins }) => { asked.push(...origins); if (answer) origins.forEach(o => granted.add(o)); return answer; },
        contains: async ({ origins }) => origins.every(o => granted.has(o)),
    };
}

test('sign-in asks for the server origin only', async () => {
    const api = fakePermissions();
    assert.equal(await requestServerPermission('https://vault.example.test/some/path', api), true);
    assert.deepEqual(api.asked, ['https://vault.example.test/*']);
});

test('a refused prompt stops sign-in with a reason naming the origin', async () => {
    const api = fakePermissions(new Set(), false);
    await assert.rejects(requestServerPermission('http://127.0.0.1:8222', api), /permission to reach http:\/\/127\.0\.0\.1:8222/);
});

test('an unparseable server URL is refused before any prompt', async () => {
    const api = fakePermissions();
    await assert.rejects(requestServerPermission('not a url', api), /not a server URL/);
    assert.deepEqual(api.asked, []);
});

test('a stored session whose server was never granted is reported, a granted one is not', async () => {
    const session = JSON.stringify({ api_url: 'https://vault.example.test/api', identity_url: 'https://vault.example.test/identity' });
    assert.equal(await missingServerOrigin(session, fakePermissions()), 'https://vault.example.test');
    assert.equal(await missingServerOrigin(session, fakePermissions(new Set(['https://vault.example.test/*']))), null);
    assert.equal(await missingServerOrigin(null, fakePermissions()), null);
});
