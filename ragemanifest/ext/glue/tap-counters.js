export function bumpCounter(name) {
    const target = (typeof globalThis !== 'undefined') ? globalThis : (typeof self !== 'undefined' ? self : window);
    const slot = target.__ragewardenTapCounters;
    if (slot && typeof slot === 'object') {
        slot[name] = (slot[name] || 0) + 1;
    }
}
