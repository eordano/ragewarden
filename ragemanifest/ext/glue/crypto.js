let wasmModule = null;
let wasmInitPromise = null;

export async function init() {
    if (wasmModule) return wasmModule;
    if (wasmInitPromise) return wasmInitPromise;

    wasmInitPromise = (async () => {
        const url = new URL('../wasm/ragemanifest.js', import.meta.url);
        const mod = await import(url.href);
        if (typeof mod.default === 'function') {
            await mod.default();
        }
        wasmModule = mod;
        return mod;
    })();

    return wasmInitPromise;
}

export async function encrypt(plaintext, recipientPubkey) {
    const mod = await init();
    const ptBytes = typeof plaintext === 'string'
        ? new TextEncoder().encode(plaintext)
        : plaintext;
    return mod.wasm_encrypt(ptBytes, recipientPubkey);
}

export async function moduleTag() {
    const mod = await init();
    return mod.wasm_module_tag();
}

export function isReady() {
    return wasmModule !== null;
}
