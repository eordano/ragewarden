/*
 * The Ragewarden passkey relay. Passkeys made for ragewarden.decent.foundation
 * (RageDroid's, or one synced to a password manager) can only be asked from a
 * page on that origin, so the extension opens this one. Its content script
 * posts the request into this window; the assertion and the PRF output go back
 * the same way. Nothing leaves the browser: no request is made by this script.
 */
(() => {
    'use strict';
    const RP_ID = 'ragewarden.decent.foundation';
    const REQUEST = 'ragewarden-prf-request';
    const RESULT = 'ragewarden-prf-result';
    const ask = document.getElementById('ask');
    const go = document.getElementById('go');
    const status = document.getElementById('status');
    let request = null;

    const b64ToBytes = (s) => {
        const t = String(s).replace(/-/g, '+').replace(/_/g, '/');
        const bin = atob(t + '='.repeat((4 - (t.length % 4)) % 4));
        return Uint8Array.from(bin, c => c.charCodeAt(0));
    };
    const bytesToB64 = (buf) => {
        const bytes = new Uint8Array(buf);
        let s = '';
        for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
        return btoa(s);
    };
    const bytesToB64Url = (buf) => bytesToB64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    function valid(m) {
        return m && typeof m.nonce === 'string' && m.nonce.length >= 16
            && typeof m.challenge === 'string' && m.rpId === RP_ID
            && Array.isArray(m.credentials) && m.credentials.length > 0
            && m.credentials.every(c => c && typeof c.id === 'string' && typeof c.salt === 'string');
    }

    function reply(body) {
        window.postMessage({ type: RESULT, nonce: request ? request.nonce : '', ...body }, location.origin);
    }

    window.addEventListener('message', (ev) => {
        if (ev.source !== window || ev.origin !== location.origin) return;
        const m = ev.data;
        if (!m || m.type !== REQUEST) return;
        if (!valid(m)) {
            status.textContent = 'The request from the extension was malformed; nothing was asked.';
            return;
        }
        request = m;
        const what = [m.action, m.destination].filter(Boolean).join(' → ');
        ask.textContent = what
            ? `Ragewarden asks your passkey to ${what}.`
            : 'Ragewarden asks your passkey for this browser.';
        status.textContent = '';
        go.disabled = false;
        go.focus();
    });

    go.addEventListener('click', async () => {
        if (!request) return;
        go.disabled = true;
        status.textContent = 'Waiting for your passkey...';
        const evalByCredential = {};
        for (const c of request.credentials) evalByCredential[c.id] = { first: b64ToBytes(c.salt) };
        try {
            const a = await navigator.credentials.get({
                publicKey: {
                    rpId: RP_ID,
                    challenge: b64ToBytes(request.challenge),
                    allowCredentials: request.credentials.map(c => ({ type: 'public-key', id: b64ToBytes(c.id) })),
                    userVerification: 'required',
                    timeout: 120000,
                    extensions: { prf: { evalByCredential } },
                },
            });
            const prf = a && a.getClientExtensionResults().prf;
            const first = prf && prf.results && prf.results.first;
            if (!first) throw new Error('this passkey returned no PRF output');
            reply({
                credentialId: bytesToB64Url(a.rawId),
                prfFirst: bytesToB64(first),
                authenticatorData: bytesToB64(a.response.authenticatorData),
                clientDataJSON: bytesToB64(a.response.clientDataJSON),
                signature: bytesToB64(a.response.signature),
            });
            request = null;
            status.textContent = 'Done. The extension closes this tab.';
        } catch (err) {
            const message = `${(err && err.name) || 'Error'}: ${(err && err.message) || err}`;
            reply({ error: message });
            request = null;
            status.textContent = `The passkey did not answer (${message}). Start again from the extension.`;
        }
    });
})();
