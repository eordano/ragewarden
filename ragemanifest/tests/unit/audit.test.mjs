import test from 'node:test';
import assert from 'node:assert/strict';
import { installFakeChrome } from './fake-chrome.mjs';

installFakeChrome();
const audit = await import('../../ext/glue/audit.js');

test('concurrent records are serialised, none is lost', async () => {
    await Promise.all(Array.from({ length: 20 }, (_, i) =>
        audit.record({ kind: audit.KINDS.Reveal, target: `item-${i}` })));
    const all = await audit.tail();
    assert.equal(all.length, 20);
    assert.equal(new Set(all.map(e => e.target)).size, 20);
});

test('entries carry the outcome, not the intent', async () => {
    await audit.record({
        kind: audit.KINDS.Copy, target: 'x', result: audit.RESULTS.declined, code: 'tap_declined',
    });
    await audit.record({ kind: audit.KINDS.Recover, target: 'y', backends: ['webauthn-prf'] });
    const [recovered, declined] = await audit.tail(2);
    assert.equal(declined.result, 'declined');
    assert.equal(declined.code, 'tap_declined');
    assert.equal(recovered.kind, 'Recover');
    assert.deepEqual(recovered.backends, ['webauthn-prf']);
    assert.equal(typeof audit.clear, 'undefined');
});

test('the browser logs in core\'s shared audit vocabulary and reads old names back under it', async () => {
    const { readFileSync } = await import('node:fs');
    const vocab = JSON.parse(readFileSync(new URL('../../../core/tests/vectors/audit_vocabulary_v1.json', import.meta.url), 'utf8'));
    for (const kind of Object.values(audit.KINDS)) assert.ok(vocab.kinds.includes(kind), `${kind} is core vocabulary`);
    assert.deepEqual({ ...audit.LEGACY_NAMES }, vocab.legacy_names);
    assert.deepEqual(Object.values(audit.RESULTS).sort(), [...vocab.results].sort());
});
