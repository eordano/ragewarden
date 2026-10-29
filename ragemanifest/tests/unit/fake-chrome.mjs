export function makeArea(name, listeners) {
    const data = new Map();
    const fire = (changes) => { for (const l of listeners) l(changes, name); };
    return {
        data,
        get(keys, cb) {
            const out = {};
            for (const k of [].concat(keys)) if (data.has(k)) out[k] = structuredClone(data.get(k));
            queueMicrotask(() => cb(out));
        },
        set(items, cb) {
            const changes = {};
            for (const [k, v] of Object.entries(items)) {
                changes[k] = { oldValue: data.get(k), newValue: structuredClone(v) };
                data.set(k, structuredClone(v));
            }
            queueMicrotask(() => { fire(changes); cb && cb(); });
        },
        remove(keys, cb) {
            const changes = {};
            for (const k of [].concat(keys)) {
                if (data.has(k)) changes[k] = { oldValue: data.get(k) };
                data.delete(k);
            }
            queueMicrotask(() => { if (Object.keys(changes).length) fire(changes); cb && cb(); });
        },
    };
}

export function installFakeChrome() {
    const listeners = [];
    const chrome = {
        runtime: {
            id: 'test-extension-id',
            lastError: null,
            getURL: (p) => `chrome-extension://test-extension-id/${p}`,
            onMessage: { addListener() {} },
            onInstalled: { addListener() {} },
            onStartup: { addListener() {} },
            sendMessage() {},
        },
        storage: {
            onChanged: { addListener: (l) => listeners.push(l) },
        },
    };
    chrome.storage.local = makeArea('local', listeners);
    chrome.storage.session = makeArea('session', listeners);
    globalThis.chrome = chrome;
    globalThis.self = globalThis;
    return chrome;
}
