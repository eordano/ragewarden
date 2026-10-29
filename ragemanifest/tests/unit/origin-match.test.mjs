import test from 'node:test';
import assert from 'node:assert/strict';
import { ciphersForOrigin, siteMatchesOrigin } from '../../ext/glue/origin-match.js';

test('exact host and subdomains of the stored host match', () => {
    assert.equal(siteMatchesOrigin('example.com', 'https://example.com'), true);
    assert.equal(siteMatchesOrigin('example.com', 'https://a.example.com'), true);
    assert.equal(siteMatchesOrigin('https://login.example.com/path', 'https://login.example.com'), true);
});

test('lookalikes and shared suffixes never match', () => {
    assert.equal(siteMatchesOrigin('example.com', 'https://evil-example.com'), false);
    assert.equal(siteMatchesOrigin('example.com', 'https://example.com.evil.net'), false);
    assert.equal(siteMatchesOrigin('co.uk', 'https://x.co.uk'), false);
    assert.equal(siteMatchesOrigin('github.io', 'https://someone.github.io'), false);
    assert.equal(siteMatchesOrigin('a.example.com', 'https://example.com'), false);
});

test('an https site is not filled into plain http', () => {
    assert.equal(siteMatchesOrigin('https://example.com', 'http://example.com'), false);
    assert.equal(siteMatchesOrigin('example.com', 'http://example.com'), false);
    assert.equal(siteMatchesOrigin('http://intranet.lan', 'http://intranet.lan'), true);
    assert.equal(siteMatchesOrigin('localhost:8080', 'http://localhost:8080'), true);
});

test('ciphersForOrigin skips internal, undecryptable and non-login items', () => {
    const ciphers = [
        { id: '1', kind: 'login', name: 'a', site: 'example.com', rage: true, decryptable: true },
        { id: '2', kind: 'login', name: 'b', site: 'example.com', rage: true, decryptable: false },
        { id: '3', kind: 'note', name: 'c', site: 'example.com' },
        { id: '4', kind: 'login', name: '__ragewarden_history_v1__', site: 'example.com' },
        { id: '5', kind: 'login', name: 'e', site: 'other.com' },
    ];
    assert.deepEqual(ciphersForOrigin(ciphers, 'https://www.example.com').map(c => c.id), ['1']);
});
