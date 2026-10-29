import { defaultRpId } from './passkey.js';
import { requestServerPermission } from './host-permission.js';
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
  .ragewarden-onb-link {
    color: #faf6ee; cursor: pointer; text-decoration: underline;
    background: none; border: 0; padding: 0; font: inherit;
  }
  .ragewarden-onb-step {
    font-size: 11px; letter-spacing: 0.06em; text-transform: uppercase; opacity: 0.6;
    margin-bottom: 4px; font-family: ui-sans-serif, system-ui, sans-serif;
  }
  .ragewarden-onb-phrase {
    columns: 3; margin: 0 0 14px; padding-left: 22px;
    font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12px;
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

const PICK_WORDS = 3;

function pickWordIndices(n, k) {
    const pool = Array.from({ length: n }, (_, i) => i);
    const out = [];
    const buf = new Uint32Array(1);
    while (out.length < k && pool.length > 0) {
        const m = pool.length;
        const limit = Math.floor(0x100000000 / m) * m;
        do { globalThis.crypto.getRandomValues(buf); } while (buf[0] >= limit);
        out.push(pool.splice(buf[0] % m, 1)[0]);
    }
    return out.sort((a, b) => a - b);
}

function ensureStyle() {
    if (!document.getElementById('ragewarden-onboarding-style')) {
        const styleHolder = el('div');
        styleHolder.innerHTML = STYLE;
        document.head.appendChild(styleHolder.firstElementChild);
    }
}

/**
 * First-run protection, in three steps: a passkey, a backup passkey, and a
 * paper recovery phrase. The phrase step cannot be skipped once the backup was
 * skipped, so a profile that finishes with a passkey always has a second way in.
 * Skipping the first passkey ends on an explicit "not protected yet" card.
 *
 * Resolves { enrolled, backup, recovery, protected }.
 */
export function showProtectionWizard(args) {
    const { passkeyEnroll, savePasskeyRecipient, enrollBackupPasskey,
        generateRecovery, publishRecovery } = args;
    const rpId = args.defaultRpId || defaultRpId();
    const label = args.defaultLabel || 'Primary passkey';
    const result = { enrolled: false, backup: false, recovery: false, protected: false };

    return new Promise((resolve) => {
        ensureStyle();
        const root = el('div', { class: 'ragewarden-onb-root' });
        const card = el('div', { class: 'ragewarden-onb-card', role: 'dialog', 'aria-modal': 'true',
            'aria-labelledby': 'ragewarden-onb-title' });
        root.appendChild(card);
        document.body.appendChild(root);

        const finish = () => {
            if (root.parentNode) root.parentNode.removeChild(root);
            result.protected = result.enrolled || result.recovery;
            resolve(result);
        };

        function screen(titleText, subText, ...rest) {
            while (card.firstChild) card.removeChild(card.firstChild);
            card.appendChild(el('div', { class: 'ragewarden-onb-step' }, [stepLabel()]));
            card.appendChild(el('h1', { id: 'ragewarden-onb-title' }, [titleText]));
            card.appendChild(el('div', { class: 'ragewarden-onb-sub' }, [subText]));
            const errorBox = el('div', { class: 'ragewarden-onb-error' });
            errorBox.style.display = 'none';
            card.appendChild(errorBox);
            for (const r of rest) if (r) card.appendChild(r);
            const first = card.querySelector('.ragewarden-onb-primary') || card.querySelector('button');
            if (first) first.focus();
            return (msg) => { errorBox.textContent = msg; errorBox.style.display = 'block'; };
        }

        let step = 1;
        const stepLabel = () => `Step ${step} of 3`;

        function busy(buttons, on) { for (const b of buttons) b.disabled = on; }

        function passkeyStep() {
            step = 1;
            const create = el('button', { class: 'ragewarden-onb-btn ragewarden-onb-primary' }, ['Create passkey']);
            const skip = el('button', { class: 'ragewarden-onb-btn ragewarden-onb-secondary' }, ['Skip for now']);
            const showError = screen('Set up Ragewarden protection',
                'Enrol a passkey so each individual credential reveal requires a hardware tap. '
                + 'Your browser will save the passkey wherever it normally does -- Touch ID, '
                + 'Windows Hello, a security key, or your phone.',
                el('div', { class: 'ragewarden-onb-row' }, [create, skip]));
            skip.addEventListener('click', unprotectedStep);
            create.addEventListener('click', async () => {
                busy([create, skip], true);
                try {
                    const recipient = await passkeyEnroll({ rpId, label });
                    await savePasskeyRecipient(recipient);
                    result.enrolled = true;
                    result.recipient = recipient;
                    backupStep();
                } catch (err) {
                    showError((err && err.message) || String(err));
                    busy([create, skip], false);
                }
            });
        }

        function unprotectedStep() {
            const back = el('button', { class: 'ragewarden-onb-btn ragewarden-onb-primary' }, ['Create a passkey']);
            const go = el('button', { class: 'ragewarden-onb-btn ragewarden-onb-secondary' }, ['Continue unprotected']);
            screen('Not protected yet',
                'Without a passkey or a recovery phrase, items you save are protected only by your '
                + 'master password. You can set protection up later in Settings -> Recipients.',
                el('div', { class: 'ragewarden-onb-row' }, [back, go]));
            back.addEventListener('click', passkeyStep);
            go.addEventListener('click', finish);
        }

        function backupStep() {
            step = 2;
            const add = el('button', { class: 'ragewarden-onb-btn ragewarden-onb-primary' }, ['Add a backup passkey']);
            const skip = el('button', { class: 'ragewarden-onb-btn ragewarden-onb-secondary' }, ['Skip']);
            const showError = screen('Add a backup passkey',
                'Use a second authenticator -- another security key or your phone. If you skip this, '
                + 'you will write down a recovery phrase instead, so losing one device never locks you out.',
                el('div', { class: 'ragewarden-onb-row' }, [add, skip]));
            skip.addEventListener('click', () => recoveryStep(true));
            add.addEventListener('click', async () => {
                busy([add, skip], true);
                try {
                    await enrollBackupPasskey({ rpId, label: 'Backup passkey' });
                    result.backup = true;
                    recoveryStep(false);
                } catch (err) {
                    showError((err && err.message) || String(err));
                    busy([add, skip], false);
                }
            });
        }

        async function recoveryStep(mandatory) {
            step = 3;
            if (!mandatory) {
                const write = el('button', { class: 'ragewarden-onb-btn ragewarden-onb-primary' }, ['Write down a phrase']);
                const done = el('button', { class: 'ragewarden-onb-btn ragewarden-onb-secondary' }, ['Finish']);
                screen('Paper recovery (optional)',
                    'Two passkeys are enrolled. A recovery phrase on paper also opens your items '
                    + 'if both devices are lost.',
                    el('div', { class: 'ragewarden-onb-row' }, [write, done]));
                write.addEventListener('click', () => phraseStep(false));
                done.addEventListener('click', finish);
                return;
            }
            phraseStep(true);
        }

        async function phraseStep(mandatory) {
            let gen;
            try {
                gen = await generateRecovery();
            } catch (err) {
                const retry = el('button', { class: 'ragewarden-onb-btn ragewarden-onb-primary' }, ['Try again']);
                const showError = screen('Paper recovery', 'The recovery phrase could not be generated.',
                    el('div', { class: 'ragewarden-onb-row' }, [retry]));
                showError((err && err.message) || String(err));
                retry.addEventListener('click', () => phraseStep(mandatory));
                return;
            }
            const words = gen.phrase.trim().split(/\s+/);
            const grid = el('ol', { class: 'ragewarden-onb-phrase' },
                words.map(w => el('li', {}, [el('span', { class: 'ragewarden-onb-word' }, [w])])));
            const idx = pickWordIndices(words.length, Math.min(PICK_WORDS, words.length));
            const inputs = idx.map(() => el('input', { type: 'text', autocomplete: 'off', spellcheck: 'false' }));
            const fields = idx.map((i, n) => el('label', { class: 'ragewarden-onb-field' }, [
                el('span', {}, [`Word ${i + 1}`]), inputs[n]]));
            const confirm = el('button', { class: 'ragewarden-onb-btn ragewarden-onb-primary' }, ['I have written it down']);
            const back = mandatory
                ? el('button', { class: 'ragewarden-onb-btn ragewarden-onb-secondary' }, ['Back'])
                : el('button', { class: 'ragewarden-onb-btn ragewarden-onb-secondary' }, ['Skip']);
            const showError = screen(mandatory ? 'Write down your recovery phrase' : 'Paper recovery',
                'Write these words on paper. Do not copy, photograph or type them anywhere else. '
                + 'They are published only after you confirm three of them.',
                grid, ...fields, el('div', { class: 'ragewarden-onb-row' }, [confirm, back]));
            back.addEventListener('click', mandatory ? backupStep : finish);
            confirm.addEventListener('click', async () => {
                const wrong = idx.filter((i, n) => inputs[n].value.trim().toLowerCase() !== words[i].toLowerCase());
                if (wrong.length > 0) {
                    showError(`Word ${wrong.map(i => i + 1).join(', ')} does not match.`);
                    return;
                }
                busy([confirm, back], true);
                try {
                    await publishRecovery(gen.armoredPubkey, 'Paper recovery');
                    result.recovery = true;
                    finish();
                } catch (err) {
                    showError((err && err.message) || String(err));
                    busy([confirm, back], false);
                }
            });
        }

        passkeyStep();
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
        const toggleLink = el('button', { type: 'button', class: 'ragewarden-onb-link' });
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
            const permission = requestServerPermission(serverUrl);
            errorBox.style.display = 'none';
            submitBtn.disabled = true;
            try {
                await permission;
                if (mode === 'register') {
                    await wasmRegister(serverUrl, email, name || email, password, 600000);
                }
                const device = 'ragemanifest@' + (navigator.userAgent.split(' ')[0] || 'browser');
                let session;
                try {
                    session = await wasmLogin(serverUrl, email, password, device);
                } catch (err) {
                    if (!err || err.code !== 'legacy_kdf_needs_consent') throw err;
                    if (!await confirmLegacyKdf(err.got, err.min)) {
                        throw new Error('sign-in cancelled: the account still uses its old key derivation');
                    }
                    session = await wasmLogin(serverUrl, email, password, device, { allowLegacyKdf: true });
                }
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

        /*
         * An account created with an old PBKDF2 count. Consent signs in once with
         * it and immediately re-derives the master key at today's count on the
         * server; other Bitwarden clients of the account then sign in again.
         */
        function confirmLegacyKdf(got, min) {
            return new Promise((done) => {
                const box = el('div', { class: 'ragewarden-onb-consent', role: 'alertdialog',
                    'aria-labelledby': 'ragewarden-kdf-title' }, [
                    el('h2', { id: 'ragewarden-kdf-title' }, ['Upgrade this account\'s key derivation?']),
                    el('div', { class: 'ragewarden-onb-sub' }, [
                        `This account derives its key with ${Number(got).toLocaleString('en')} PBKDF2 `
                        + `iterations; Ragewarden needs at least ${Number(min).toLocaleString('en')}. `
                        + 'Signing in now upgrades it on the server. Your other Bitwarden apps will ask '
                        + 'you to sign in again.',
                    ]),
                ]);
                const yes = el('button', { class: 'ragewarden-onb-btn ragewarden-onb-primary' }, ['Upgrade and sign in']);
                const no = el('button', { class: 'ragewarden-onb-btn ragewarden-onb-secondary' }, ['Cancel']);
                box.appendChild(el('div', { class: 'ragewarden-onb-row' }, [yes, no]));
                card.appendChild(box);
                yes.focus();
                const finish = (v) => { box.remove(); done(v); };
                yes.addEventListener('click', () => finish(true));
                no.addEventListener('click', () => finish(false));
            });
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
