import { test, expect, fillOnboarding, waitForBootstrap, randomSuffix } from './fixtures';
import { createServer, type Server } from 'node:http';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AddressInfo } from 'node:net';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_HTML = readFileSync(join(__dirname, 'fixtures', 'login-form.html'));

const FIXTURE_USERNAME = 'octocat@github.local';
const FIXTURE_PASSWORD = 'tier2-fill-correct-horse-battery';

interface FixtureServer { server: Server; host: string; port: number; url: string; close: () => Promise<void>; }

async function startFixtureServer(): Promise<FixtureServer> {
  const server = createServer((req, res) => {
    if (req.url === '/' || req.url?.startsWith('/login')) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(FIXTURE_HTML);
      return;
    }
    res.writeHead(404);
    res.end('not found');
  });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()));
  const addr = server.address() as AddressInfo;
  const port = addr.port;
  const host = `127.0.0.1:${port}`;
  return {
    server,
    host,
    port,
    url: `http://${host}/login`,
    close: () => new Promise<void>(r => server.close(() => r())),
  };
}

/*
 * SKIPPED -- structurally, not flakily. Read this before re-enabling.
 *
 * The skip carried no reason, which reads as "known flaky". It is not: the test
 * cannot observe what it asserts on, for two independent reasons.
 *
 *  1. It drives the content script through `window.__ragewardenContent`
 *     (12 call sites below). A content script runs in an ISOLATED WORLD, so
 *     that property lands on the isolated world's `window`, not the page's.
 *     Playwright's page.evaluate/waitForFunction run in the MAIN world, so the
 *     hook is invisible there and line 92 times out -- which is exactly what
 *     happens if you delete the `.skip`.
 *  2. Falling back to inspecting the rendered chip does not work either:
 *     content.js attaches its UI with `attachShadow({ mode: 'closed' })`
 *     (content.js:119), deliberately, so the page cannot introspect it. A
 *     closed root is not reachable from page.evaluate at all.
 *
 * So this whole surface -- focus a field, chip appears, prompt names the
 * destination, tap brokered through the background worker, fill dispatched as
 * real InputEvents -- is currently UNTESTED, and the skip is the only thing
 * saying so.
 *
 * A working replacement has to drive it the way a user does: real trusted input
 * (page.mouse/page.keyboard at coordinates) rather than internal hooks, since
 * trusted events reach a closed shadow root even though scripts cannot. That is
 * a rewrite of the whole file, not a flag change, and it has not been done.
 */
test.skip('autofill content script -- chip appears, prompt names destination, fill via InputEvents', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(180_000);

  const fixture = await startFixtureServer();
  const popupPage = await context.newPage();

  await popupPage.goto(popupUrl);

  const cdp = await context.newCDPSession(popupPage);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      hasPrf: true,
      automaticPresenceSimulation: true,
      isUserVerified: true,
    },
  });

  const suffix = randomSuffix();
  const email = `e2e-fill-${suffix}@ragewarden.test`;
  const password = 'e2e-fill-correct-horse-battery';

  await fillOnboarding(popupPage, { server: vaultwardenUrl, email, password, mode: 'register' });
  await waitForBootstrap(popupPage);

  await popupPage.evaluate(HARNESS_HELPERS);

  const enrolledPubkeyB64 = await popupPage.evaluate(async () => {
    const w = window as unknown as RagewardenWindow;
    return w.__ragewardenFillHarness.enrollPasskeyAndKeygen();
  });
  expect(typeof enrolledPubkeyB64).toBe('string');

  const cipherSite = `https://${fixture.host}`;
  await popupPage.evaluate(async ([site, user, pass, pubkey]) => {
    const w = window as unknown as RagewardenWindow;
    return w.__ragewardenFillHarness.createLoginCipher(
      site as string, user as string, pass as string, pubkey as string,
    );
  }, [cipherSite, FIXTURE_USERNAME, FIXTURE_PASSWORD, enrolledPubkeyB64]);

  await popupPage.evaluate(() => new Promise<void>((resolve) => {
    const c = (window as unknown as { chrome: { runtime: { sendMessage(msg: unknown, cb: () => void): void } } }).chrome;
    c.runtime.sendMessage({ kind: 'vault.invalidate' }, () => resolve());
  }));

  const fixturePage = await context.newPage();
  await fixturePage.goto(fixture.url, { waitUntil: 'domcontentloaded' });

  await fixturePage.waitForFunction(() => Boolean((window as unknown as { __ragewardenContent?: unknown }).__ragewardenContent), { timeout: 10_000 });

  const matchesBeforeFocus = await fixturePage.evaluate(async () => {
    const w = window as unknown as ContentScriptWindow;
    return w.__ragewardenContent.forceLookup();
  });
  expect(Array.isArray(matchesBeforeFocus)).toBe(true);
  expect(matchesBeforeFocus.length).toBeGreaterThan(0);

  await fixturePage.evaluate(async () => {
    const w = window as unknown as ContentScriptWindow;
    const pwd = document.getElementById('login-password') as HTMLInputElement;
    return w.__ragewardenContent.showChipFor(pwd);
  });

  const chipState = await fixturePage.evaluate(() => {
    const w = window as unknown as ContentScriptWindow;
    return w.__ragewardenContent.getState();
  });
  expect(chipState.chipPresent).toBe(true);
  expect(chipState.matches.length).toBeGreaterThan(0);
  expect(chipState.domain).toBe(fixture.host.split(':')[0]);

  await fixturePage.evaluate(() => {
    const w = window as unknown as ContentScriptWindow;
    w.__ragewardenContent.clickChip();
  });
  const promptText = await fixturePage.evaluate(() => {
    const w = window as unknown as ContentScriptWindow;
    return w.__ragewardenContent.readPromptText();
  });
  expect(promptText).not.toBeNull();
  expect(promptText!).toContain('Autofill into');
  expect(promptText!).toContain(fixture.host.split(':')[0]);

  await fixturePage.evaluate(async () => {
    const w = window as unknown as ContentScriptWindow;
    w.__ragewardenContent.confirmPrompt();
    await w.__ragewardenContent.waitForPromptClosed();
  });

  await fixturePage.waitForFunction(
    (expected) => {
      const el = document.getElementById('login-password') as HTMLInputElement | null;
      return Boolean(el && el.value === expected);
    },
    FIXTURE_PASSWORD,
    { timeout: 10_000 },
  );

  const filled = await fixturePage.evaluate(() => {
    const w = window as unknown as ContentScriptWindow & { __ragewardenFixtureForm: { readUsername(): string; readPassword(): string; counters: Record<string, number>; recorded: Array<{ name: string; target: string; value: string }> } };
    return {
      username: w.__ragewardenFixtureForm.readUsername(),
      password: w.__ragewardenFixtureForm.readPassword(),
      counters: w.__ragewardenFixtureForm.counters,
      events: w.__ragewardenFixtureForm.recorded.length,
    };
  });
  expect(filled.username).toBe(FIXTURE_USERNAME);
  expect(filled.password).toBe(FIXTURE_PASSWORD);
  expect(filled.counters.input).toBeGreaterThanOrEqual(FIXTURE_PASSWORD.length);
  expect(filled.counters.beforeinput).toBeGreaterThanOrEqual(FIXTURE_PASSWORD.length);
  expect(filled.events).toBeGreaterThan(0);

  const internal = await fixturePage.evaluate(() => {
    const w = window as unknown as ContentScriptWindowExtended;
    return w.__ragewardenContent.snapshotInternalState();
  });
  expect(internal.promptPresent).toBe(false);
  expect(internal.shadowTextSample.includes(FIXTURE_PASSWORD)).toBe(false);

  const leakSearch = await fixturePage.evaluate((needle) => {
    const w = window as unknown as ContentScriptWindowExtended;
    const blob = JSON.stringify(w.__ragewardenContent.snapshotInternalState());
    return blob.includes(needle);
  }, FIXTURE_PASSWORD);
  expect(leakSearch).toBe(false);

  const session = await popupPage.evaluate(async () => {
    const w = window as unknown as RagewardenWindow & {
      __ragewardenFillHarness: { getSession(): Promise<{ access_token: string }> };
    };
    return w.__ragewardenFillHarness.getSession();
  });
  await assertServerStoredEncryptedBlob(vaultwardenUrl, (session as { access_token: string }).access_token, FIXTURE_PASSWORD);

  await fixturePage.close();
  await popupPage.close();
  await fixture.close();
});

async function assertServerStoredEncryptedBlob(server: string, token: string, plaintext: string): Promise<void> {
  const res = await fetch(`${server}/api/sync`, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Bitwarden-Client-Name': 'web',
      'Bitwarden-Client-Version': '2024.10.0',
    },
  });
  if (!res.ok) throw new Error(`/api/sync failed: ${res.status}`);
  const body = await res.json();
  const haystack = JSON.stringify(body);
  if (haystack.includes(plaintext)) {
    throw new Error('plaintext leaked into Vaultwarden /api/sync response (§0d violation)');
  }
  if (!haystack.includes('2.')) {
    throw new Error('expected Type-2 EncString markers in /api/sync response');
  }
}

const HARNESS_HELPERS = String.raw`
(() => {
  if (window.__ragewardenFillHarness) return;
  const RP_ID = location.hostname;
  // Must decode to exactly 32 bytes (Recipient::PasskeyPrf requirement).
  // Old placeholder was 47 bytes -- replaced with a 32-byte ASCII tag.
  const SALT_B64 = 'cmFnZXdhcmRlbi10aWVyMi1maWxsLXNhbHQtLS0tLS0=';

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function bytesToB64(bytes) {
    let s = '';
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
    return btoa(s);
  }

  async function getSession() {
    return new Promise((resolve, reject) => {
      try {
        chrome.storage.local.get(['ragewarden:sessionEnvelope'], async (envItems) => {
          const env = envItems['ragewarden:sessionEnvelope'];
          chrome.storage.session.get(['ragewarden:envelopeKey'], async (skItems) => {
            const rawKeyB64 = skItems['ragewarden:envelopeKey'];
            if (!env || !rawKeyB64) return reject(new Error('no session'));
            try {
              const keyBytes = b64ToBytes(rawKeyB64);
              const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
              const pt = new Uint8Array(await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: b64ToBytes(env.iv) }, key, b64ToBytes(env.ct),
              ));
              resolve(JSON.parse(new TextDecoder().decode(pt)));
            } catch (e) { reject(e); }
          });
        });
      } catch (e) { reject(e); }
    });
  }

  async function enrollPasskeyAndKeygen() {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = crypto.getRandomValues(new Uint8Array(16));
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { id: RP_ID, name: 'Ragewarden test' },
        user: { id: userId, name: 'fill@ragewarden.test', displayName: 'fill' },
        challenge,
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'none',
        extensions: { prf: { eval: { first: b64ToBytes(SALT_B64) } } },
      },
    });
    if (!cred) throw new Error('passkey create failed');

    const wasm = await window.RagewardenVault.crypto.init();
    const kg = wasm.wasm_software_keygen();
    const publicKey = new Uint8Array(kg.public_key);
    return bytesToB64(publicKey);
  }

  async function createLoginCipher(site, username, password, pubkeyB64) {
    const session = await getSession();
    const wasm = await window.RagewardenVault.crypto.init();
    const url = new URL(site);
    const fields = {
      name: url.hostname,
      username,
      rage: password,
      site,
    };
    const recipients = [{ kind: 'x25519', public_key_b64: pubkeyB64 }];
    const saved = await wasm.wasm_create_cipher(session, fields, recipients);
    return saved.id;
  }

  window.__ragewardenFillHarness = { enrollPasskeyAndKeygen, createLoginCipher, getSession };
})();
`;

interface RagewardenWindow {
  RagewardenVault: {
    bootstrapResult: { email: string; ciphers: number };
    crypto: { init(): Promise<unknown> };
  };
  __ragewardenFillHarness: {
    enrollPasskeyAndKeygen(): Promise<string>;
    createLoginCipher(site: string, username: string, password: string, pubkeyB64: string): Promise<string>;
    getSession(): Promise<unknown>;
  };
}

interface ContentScriptWindow {
  __ragewardenContent: {
    forceLookup(): Promise<Array<{ id: string; name: string }>>;
    showChipFor(field: HTMLElement): Promise<void>;
    getState(): { origin: string; domain: string; chipPresent: boolean; promptPresent: boolean; matches: Array<{ id: string; name: string }> };
    clickChip(): void;
    readPromptText(): string | null;
    confirmPrompt(): void;
    waitForPromptClosed(): Promise<void>;
    snapshotInternalState(): { hasMatches: boolean; chipPresent: boolean; promptPresent: boolean };
  };
}

interface ContentScriptWindowExtended {
  __ragewardenContent: Omit<ContentScriptWindow['__ragewardenContent'], 'snapshotInternalState'> & {
    snapshotInternalState(): {
      hasMatches: boolean;
      chipPresent: boolean;
      promptPresent: boolean;
      matchesJson: string;
      shadowTextLength: number;
      shadowTextSample: string;
    };
  };
}
