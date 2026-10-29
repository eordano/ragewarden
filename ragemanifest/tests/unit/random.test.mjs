import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pickDistinct, uniformIndex } from '../../ext/popup/random.js';

test('uniformIndex is unbiased over a range that does not divide 2^32', () => {
    const m = 24;
    const counts = new Array(m).fill(0);
    const draws = 120_000;
    for (let i = 0; i < draws; i++) counts[uniformIndex(m)]++;
    const expected = draws / m;
    for (const c of counts) assert.ok(Math.abs(c - expected) < expected * 0.08, `bucket ${c} vs ${expected}`);
});

test('uniformIndex rejects the values past the last whole multiple', () => {
    const seq = [0xffffffff, 7];
    const rng = { getRandomValues(buf) { buf[0] = seq.shift(); return buf; } };
    assert.equal(uniformIndex(24, rng), 7);
    assert.equal(seq.length, 0);
});

test('pickDistinct returns k distinct ascending indices', () => {
    for (let i = 0; i < 200; i++) {
        const out = pickDistinct(24, 3);
        assert.equal(out.length, 3);
        assert.equal(new Set(out).size, 3);
        assert.deepEqual([...out].sort((a, b) => a - b), out);
        assert.ok(out.every(x => x >= 0 && x < 24));
    }
});

test('no CSPRNG means no words picked, not Math.random', () => {
    assert.throws(() => pickDistinct(24, 3, {}), /getRandomValues is unavailable/);
});
