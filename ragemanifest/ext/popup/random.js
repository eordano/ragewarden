/**
 * Uniform integer in [0, m) from a CSPRNG, by rejection sampling: the values
 * past the last whole multiple of m are redrawn instead of folded back with a
 * modulo, which would favour the low indices.
 */
export function uniformIndex(m, rng = globalThis.crypto) {
    if (!rng || typeof rng.getRandomValues !== 'function') {
        throw new Error('crypto.getRandomValues is unavailable; refusing to pick words without it');
    }
    if (!Number.isInteger(m) || m <= 0 || m > 0x100000000) throw new RangeError(`bad range ${m}`);
    const limit = Math.floor(0x100000000 / m) * m;
    const buf = new Uint32Array(1);
    for (;;) {
        rng.getRandomValues(buf);
        if (buf[0] < limit) return buf[0] % m;
    }
}

/** k distinct indices from [0, n), ascending. */
export function pickDistinct(n, k, rng = globalThis.crypto) {
    const pool = Array.from({ length: n }, (_, i) => i);
    const out = [];
    while (out.length < k && pool.length > 0) {
        out.push(pool.splice(uniformIndex(pool.length, rng), 1)[0]);
    }
    return out.sort((a, b) => a - b);
}
