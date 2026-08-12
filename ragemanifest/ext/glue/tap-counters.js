export function bumpCounter(name) {
    const target = (typeof globalThis !== 'undefined') ? globalThis : (typeof self !== 'undefined' ? self : window);
    const slot = target.__ragewardenTapCounters;
    if (slot && typeof slot === 'object') {
        slot[name] = (slot[name] || 0) + 1;
    }
}

export function readCounters() {
    const target = (typeof globalThis !== 'undefined') ? globalThis : (typeof self !== 'undefined' ? self : window);
    const slot = target.__ragewardenTapCounters;
    return slot ? { ...slot } : null;
}

export function resetCounters() {
    const target = (typeof globalThis !== 'undefined') ? globalThis : (typeof self !== 'undefined' ? self : window);
    if (target.__ragewardenTapCounters) {
        for (const k of Object.keys(target.__ragewardenTapCounters)) {
            target.__ragewardenTapCounters[k] = 0;
        }
    }
}

export function enableCounters() {
    const target = (typeof globalThis !== 'undefined') ? globalThis : (typeof self !== 'undefined' ? self : window);
    if (!target.__ragewardenTapCounters) {
        target.__ragewardenTapCounters = {
            prf_eval: 0, presence_tap: 0, js_decrypt: 0, wasm_decrypt: 0,
        };
    }
}
