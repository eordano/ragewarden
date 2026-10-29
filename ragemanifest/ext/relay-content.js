/*
 * Runs only on https://ragewarden.decent.foundation/prf (the passkey relay).
 * It carries the worker's request into the page and the page's answer back:
 * the nonce in the URL fragment names the request, and the worker accepts an
 * answer only from the tab it opened, for that nonce, before its deadline.
 */
(() => {
    const api = (typeof browser !== 'undefined' && browser.runtime) ? browser : chrome;
    const REQUEST = 'ragewarden-prf-request';
    const RESULT = 'ragewarden-prf-result';
    let current = '';

    async function hello() {
        const nonce = location.hash.replace(/^#/, '');
        current = nonce;
        let resp;
        try {
            resp = await api.runtime.sendMessage({ kind: 'relay.hello', nonce });
        } catch {
            return;
        }
        if (resp && resp.ok && resp.request && nonce === current) {
            window.postMessage({ type: REQUEST, ...resp.request }, location.origin);
        }
    }

    window.addEventListener('message', (ev) => {
        if (ev.source !== window || ev.origin !== location.origin) return;
        const m = ev.data;
        if (!m || m.type !== RESULT || !current || m.nonce !== current) return;
        const { type: _t, nonce, ...result } = m;
        current = '';
        api.runtime.sendMessage({ kind: 'relay.result', nonce, result }).catch(() => {});
    });
    window.addEventListener('hashchange', hello);
    hello();
})();
