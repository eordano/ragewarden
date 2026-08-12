const STYLE = `
<style id="ragewarden-onboarding-style">
  .ragewarden-onb-root {
    position: fixed; inset: 0; z-index: 10000;
    background: rgba(20, 20, 20, 0.94);
    color: #faf6ee;
    font-family: ui-serif, "New York", Georgia, serif;
    display: flex; align-items: center; justify-content: center;
    padding: 32px;
  }
  .ragewarden-onb-card {
    width: min(420px, 100%);
    background: #1d1d1d;
    border: 1px solid #2c2c2c;
    border-radius: 14px;
    padding: 28px 24px 22px;
    box-shadow: 0 24px 60px rgba(0,0,0,0.45);
  }
  .ragewarden-onb-card h1 {
    font-size: 22px; margin: 0 0 6px; font-weight: 700;
  }
  .ragewarden-onb-card .ragewarden-onb-sub {
    font-size: 13px; opacity: 0.72; margin-bottom: 18px;
    font-family: ui-sans-serif, system-ui, sans-serif;
  }
  .ragewarden-onb-field {
    display: block; margin-bottom: 12px;
    font-family: ui-sans-serif, system-ui, sans-serif;
  }
  .ragewarden-onb-field span {
    display: block; font-size: 11px; letter-spacing: 0.06em;
    text-transform: uppercase; opacity: 0.6; margin-bottom: 4px;
  }
  .ragewarden-onb-field input {
    width: 100%; box-sizing: border-box;
    background: #121212; color: #faf6ee;
    border: 1px solid #2c2c2c; border-radius: 8px;
    padding: 10px 12px; font-size: 14px;
    font-family: ui-monospace, "SF Mono", Menlo, monospace;
  }
  .ragewarden-onb-field input:focus {
    outline: none; border-color: #6a8fff;
  }
  .ragewarden-onb-row {
    display: flex; gap: 10px; margin-top: 14px;
  }
  .ragewarden-onb-btn {
    flex: 1; padding: 10px 14px; border-radius: 8px;
    border: 1px solid #2c2c2c; cursor: pointer;
    font-family: ui-sans-serif, system-ui, sans-serif;
    font-size: 13px; font-weight: 600;
  }
  .ragewarden-onb-primary {
    background: #faf6ee; color: #121212; border-color: #faf6ee;
  }
  .ragewarden-onb-primary[disabled] {
    opacity: 0.55; cursor: progress;
  }
  .ragewarden-onb-secondary {
    background: transparent; color: #faf6ee;
  }
  .ragewarden-onb-toggle {
    margin-top: 12px; text-align: center; font-size: 12px; opacity: 0.7;
    font-family: ui-sans-serif, system-ui, sans-serif;
  }
  .ragewarden-onb-toggle a {
    color: #faf6ee; cursor: pointer; text-decoration: underline;
  }
  .ragewarden-onb-error {
    margin-top: 10px; padding: 8px 10px;
    background: #4a1d1d; border: 1px solid #7a2c2c; border-radius: 6px;
    font-size: 12px; font-family: ui-monospace, monospace;
    word-break: break-word;
  }
</style>
`;

function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
        if (k === 'class') node.className = v;
        else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
        else if (k === 'value') node.value = v;
        else node.setAttribute(k, v);
    }
    for (const c of children) {
        if (c == null) continue;
        node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return node;
}

export function showProtectionWizard(args) {
    const { passkeyEnroll, savePasskeyRecipient } = args;
    const rpId = args.defaultRpId || (typeof location !== 'undefined' ? location.hostname : 'ragewarden');
    const label = args.defaultLabel || 'Primary passkey';

    return new Promise((resolve) => {
        if (!document.getElementById('ragewarden-onboarding-style')) {
            const styleHolder = el('div');
            styleHolder.innerHTML = STYLE;
            document.head.appendChild(styleHolder.firstElementChild);
        }

        const root = el('div', { class: 'ragewarden-onb-root' });
        const card = el('div', { class: 'ragewarden-onb-card' });
        const title = el('h1', {}, ['Set up Ragewarden protection']);
        const sub = el('div', { class: 'ragewarden-onb-sub' }, [
            'Enrol a passkey so each individual credential reveal requires a hardware tap. ',
            'Your browser will save the passkey wherever it normally does -- Touch ID, Windows Hello, a security key, or your phone.',
        ]);
        // No cryptography paragraph here. This card is shown to someone who has
        // not yet decided to trust the product, and "WebAuthn-PRF derivation
        // wraps each cipher's file key" asks them to evaluate a claim they have
        // no way to check. The sentence above already says the thing they can
        // act on: each reveal costs a tap, and the passkey lives where their
        // browser keeps passkeys.
        const errorBox = el('div', { class: 'ragewarden-onb-error' });
        errorBox.style.display = 'none';

        const enrollBtn = el('button', { class: 'ragewarden-onb-btn ragewarden-onb-primary' }, ['Create passkey']);
        const skipBtn = el('button', { class: 'ragewarden-onb-btn ragewarden-onb-secondary' }, ['Skip for now']);

        function showError(msg) { errorBox.textContent = msg; errorBox.style.display = 'block'; }
        function cleanup() { if (root.parentNode) root.parentNode.removeChild(root); }

        skipBtn.addEventListener('click', () => { cleanup(); resolve({ enrolled: false }); });
        enrollBtn.addEventListener('click', async () => {
            errorBox.style.display = 'none';
            enrollBtn.disabled = true;
            skipBtn.disabled = true;
            try {
                const recipient = await passkeyEnroll({ rpId, label });
                await savePasskeyRecipient(recipient);
                cleanup();
                resolve({ enrolled: true, recipient });
            } catch (err) {
                showError((err && err.message) || String(err));
                enrollBtn.disabled = false;
                skipBtn.disabled = false;
            }
        });

        card.appendChild(title);
        card.appendChild(sub);
        card.appendChild(errorBox);
        card.appendChild(el('div', { class: 'ragewarden-onb-row' }, [enrollBtn, skipBtn]));
        root.appendChild(card);
        document.body.appendChild(root);
    });
}

export function showOnboarding({ wasmLogin, wasmRegister, defaultServerUrl = 'https://vault.bitwarden.com' }) {
    return new Promise((resolve, reject) => {
        if (!document.getElementById('ragewarden-onboarding-style')) {
            const styleHolder = el('div');
            styleHolder.innerHTML = STYLE;
            document.head.appendChild(styleHolder.firstElementChild);
        }

        let mode = 'login';
        const root = el('div', { class: 'ragewarden-onb-root' });
        const card = el('div', { class: 'ragewarden-onb-card' });

        const title = el('h1', {}, ['Sign in to Bitwarden']);
        const sub = el('div', { class: 'ragewarden-onb-sub' }, [
            'Ragewarden talks to a real Bitwarden or Vaultwarden server. Your master password signs you in; revealing any individual password takes a separate hardware tap.',
        ]);

        const serverInput = el('input', {
            type: 'url', value: defaultServerUrl, placeholder: 'https://vault.example.com',
        });
        const emailInput = el('input', { type: 'email', placeholder: 'you@example.com' });
        const passwordInput = el('input', { type: 'password', placeholder: 'Master password' });
        const nameInput = el('input', { type: 'text', placeholder: 'Display name' });
        const nameField = el('label', { class: 'ragewarden-onb-field' }, [
            el('span', {}, ['Name']),
            nameInput,
        ]);
        nameField.style.display = 'none';

        const errorBox = el('div', { class: 'ragewarden-onb-error' });
        errorBox.style.display = 'none';

        const submitBtn = el('button', { class: 'ragewarden-onb-btn ragewarden-onb-primary' });
        const cancelBtn = el('button', { class: 'ragewarden-onb-btn ragewarden-onb-secondary' }, ['Cancel']);

        // Enter in any field submits, so the master password field does not need
        // the mouse to reach the button.
        for (const inp of [serverInput, emailInput, passwordInput, nameInput]) {
            inp.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !submitBtn.disabled) {
                    e.preventDefault();
                    submitBtn.click();
                }
            });
        }
        const toggleLink = el('a', {});
        const toggleRow = el('div', { class: 'ragewarden-onb-toggle' }, [
            el('span', {}, ['']),
            toggleLink,
        ]);

        function applyMode() {
            if (mode === 'login') {
                title.textContent = 'Sign in to Bitwarden';
                submitBtn.textContent = 'Sign in';
                nameField.style.display = 'none';
                toggleRow.firstChild.textContent = 'No account yet? ';
                toggleLink.textContent = 'Create one';
            } else {
                title.textContent = 'Create a Bitwarden account';
                submitBtn.textContent = 'Create account';
                nameField.style.display = 'block';
                toggleRow.firstChild.textContent = 'Already registered? ';
                toggleLink.textContent = 'Sign in';
            }
        }
        toggleLink.addEventListener('click', () => {
            mode = (mode === 'login') ? 'register' : 'login';
            errorBox.style.display = 'none';
            applyMode();
        });

        cancelBtn.addEventListener('click', () => {
            cleanup();
            reject(new Error('cancelled'));
        });

        submitBtn.addEventListener('click', async () => {
            const serverUrl = serverInput.value.trim();
            const email = emailInput.value.trim();
            const password = passwordInput.value;
            const name = nameInput.value.trim();
            if (!serverUrl || !email || !password) {
                showError('All fields are required.');
                return;
            }
            errorBox.style.display = 'none';
            submitBtn.disabled = true;
            try {
                if (mode === 'register') {
                    await wasmRegister(serverUrl, email, name || email, password, 600000);
                }
                const session = await wasmLogin(
                    serverUrl, email, password,
                    'ragemanifest@' + (navigator.userAgent.split(' ')[0] || 'browser'),
                );
                cleanup();
                resolve(session);
            } catch (err) {
                showError((err && err.message) || String(err));
                submitBtn.disabled = false;
            }
        });

        function showError(msg) {
            errorBox.textContent = msg;
            errorBox.style.display = 'block';
        }

        card.appendChild(title);
        card.appendChild(sub);
        card.appendChild(el('label', { class: 'ragewarden-onb-field' }, [
            el('span', {}, ['Server URL']),
            serverInput,
        ]));
        card.appendChild(el('label', { class: 'ragewarden-onb-field' }, [
            el('span', {}, ['Email']),
            emailInput,
        ]));
        card.appendChild(el('label', { class: 'ragewarden-onb-field' }, [
            el('span', {}, ['Master password']),
            passwordInput,
        ]));
        card.appendChild(nameField);
        card.appendChild(errorBox);
        card.appendChild(el('div', { class: 'ragewarden-onb-row' }, [submitBtn, cancelBtn]));
        card.appendChild(toggleRow);

        root.appendChild(card);
        document.body.appendChild(root);
        applyMode();

        function cleanup() {
            if (root.parentNode) root.parentNode.removeChild(root);
        }
    });
}
