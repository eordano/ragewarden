import { test, expect, fillOnboarding, waitForBootstrap, randomSuffix } from './fixtures';
import type { CDPSession, Page } from '@playwright/test';

const FIXTURE_PLAINTEXT = 'roundtrip-secret-correct-horse-battery';
const FIXTURE_NAME = 'github.com';
const ACTION_LABEL = `Reveal ${FIXTURE_NAME} password?`;

async function attachVirtualAuthenticator(page: Page): Promise<{ cdp: CDPSession; authenticatorId: string }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const result = await cdp.send('WebAuthn.addVirtualAuthenticator', {
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
  return { cdp, authenticatorId: result.authenticatorId };
}

async function exportCredentials(cdp: CDPSession, authenticatorId: string): Promise<unknown[]> {
  const res = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  return res.credentials.map(c => ({ ...c }));
}

test('passkey-PRF roundtrip (AES-GCM-wrapped age secret) -- principles 0a/0b/0c/0d', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(180_000);

  const page = await context.newPage();
  const auth1 = await attachVirtualAuthenticator(page);
  await page.goto(popupUrl);

  const suffix = randomSuffix();
  const email = `e2e-prf-${suffix}@ragewarden.test`;
  const password = 'e2e-prf-correct-horse-battery';

  await fillOnboarding(page, { server: vaultwardenUrl, email, password, mode: 'register' });
  await waitForBootstrap(page);

  await page.evaluate(HARNESS_HELPERS);

  const enrolledPubkeyB64 = await page.evaluate(async () => {
    const w = window as unknown as RagewardenWindow;
    return w.__ragewardenHarness.enrollPasskeyAndKeygen();
  });
  expect(typeof enrolledPubkeyB64).toBe('string');
  expect(enrolledPubkeyB64.length).toBeGreaterThan(0);

  const cipherId = await page.evaluate(async ([name, plaintext, pubkey]) => {
    const w = window as unknown as RagewardenWindow;
    return w.__ragewardenHarness.createRageCipher(name as string, plaintext as string, pubkey as string);
  }, [FIXTURE_NAME, FIXTURE_PLAINTEXT, enrolledPubkeyB64]);
  expect(cipherId).toMatch(/[0-9a-f-]{36}/);

  const session = await page.evaluate(async () => {
    const w = window as unknown as RagewardenWindow;
    return w.__ragewardenHarness.getSession();
  });

  await assertServerStoredEncryptedBlob(vaultwardenUrl, session.access_token, cipherId);

  const credsBefore = await exportCredentials(auth1.cdp, auth1.authenticatorId);
  expect(credsBefore.length).toBeGreaterThan(0);

  await page.goto('about:blank');
  await page.goto(popupUrl);
  const page2 = page;
  await waitForBootstrap(page2);
  await page2.evaluate(HARNESS_HELPERS);

  const credsAfter = await exportCredentials(auth1.cdp, auth1.authenticatorId);
  expect(credsAfter.length).toBe(credsBefore.length);

  const reveal1 = await page2.evaluate(async ([cid, label]) => {
    const w = window as unknown as RagewardenWindow;
    return w.__ragewardenHarness.revealOnce(cid as string, label as string);
  }, [cipherId, ACTION_LABEL]);

  expect(reveal1.plaintext).toBe(FIXTURE_PLAINTEXT);
  expect(reveal1.promptVisibleAtTap).toBe(true);
  expect(reveal1.promptText).toContain(FIXTURE_NAME);
  expect(reveal1.decryptCounter).toBe(1);
  expect(reveal1.prfCounter).toBe(1);
  expect(reveal1.wasmDecryptCalls).toBe(1);

  const reachableAfter = await page2.evaluate((needle) => {
    const w = window as unknown as RagewardenWindow & {
      RagewardenVault: Record<string, unknown>;
    };
    if ('__plaintextCache' in w.RagewardenVault) return 'cache field present';
    if ('lastPlaintext' in w.RagewardenVault) return 'lastPlaintext present';
    for (const k of Object.keys(w.RagewardenVault)) {
      const v = (w.RagewardenVault as Record<string, unknown>)[k];
      if (typeof v === 'string' && v === needle) {
        return `plaintext leaked under key ${k}`;
      }
    }
    return null;
  }, FIXTURE_PLAINTEXT);
  expect(reachableAfter).toBeNull();

  const reveal2 = await page2.evaluate(async ([cid, label]) => {
    const w = window as unknown as RagewardenWindow;
    return w.__ragewardenHarness.revealOnce(cid as string, label as string);
  }, [cipherId, ACTION_LABEL]);

  expect(reveal2.plaintext).toBe(FIXTURE_PLAINTEXT);
  expect(reveal2.decryptCounter).toBe(2);
  expect(reveal2.prfCounter).toBe(2);
  expect(reveal2.wasmDecryptCalls).toBe(2);

  await page2.close();
});

test('Recipient::PasskeyPrf via wasm_decrypt_with_passkey -- full §0a/§0b/§0c/§0d', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(180_000);

  const page = await context.newPage();
  const auth = await attachVirtualAuthenticator(page);
  await page.goto(popupUrl);

  const suffix = randomSuffix();
  const email = `e2e-passkey2-${suffix}@ragewarden.test`;
  const password = 'e2e-passkey2-correct-horse-battery';

  await fillOnboarding(page, { server: vaultwardenUrl, email, password, mode: 'register' });
  await waitForBootstrap(page);
  await page.evaluate(HARNESS_HELPERS);

  const credentialIdB64 = await page.evaluate(async () => {
    const w = window as unknown as RagewardenWindowExtended;
    const id = await w.__ragewardenHarness.enrollPasskeyOnly();
    let s = ''; for (let i = 0; i < id.length; i++) s += String.fromCharCode(id[i]);
    return btoa(s);
  });

  const PASSKEY_PLAINTEXT = 'passkey-prf-secret-correct-horse-battery';
  const PASSKEY_NAME = 'login.passkey-prf-test';
  const ACTION_LABEL_2 = `Reveal ${PASSKEY_NAME} password?`;

  const cipherId = await page.evaluate(async ([credB64, name, plaintext]) => {
    const w = window as unknown as RagewardenWindowExtended;
    function b64ToBytes(b64: string): Uint8Array {
      const bin = atob(b64);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    const cred = b64ToBytes(credB64 as string);
    return w.__ragewardenHarness.createPasskeyPrfCipher(name as string, plaintext as string, cred);
  }, [credentialIdB64, PASSKEY_NAME, PASSKEY_PLAINTEXT]);
  expect(cipherId).toMatch(/[0-9a-f-]{36}/);

  const session = await page.evaluate(async () => {
    const w = window as unknown as RagewardenWindowExtended;
    return w.__ragewardenHarness.getSession();
  });
  await assertCipherCarriesEncryptedRageBlob(vaultwardenUrl, session.access_token, cipherId, PASSKEY_PLAINTEXT);

  const baseline = await page.evaluate(() => {
    const w = window as unknown as RagewardenWindowExtended;
    return { ...w.__ragewardenHarness.counters };
  });

  const reveal1 = await page.evaluate(async ([cid, label, credB64]) => {
    const w = window as unknown as RagewardenWindowExtended;
    function b64ToBytes(b64: string): Uint8Array {
      const bin = atob(b64);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    return w.__ragewardenHarness.revealViaWasmDecryptWithPasskey(
      cid as string, label as string, b64ToBytes(credB64 as string),
    );
  }, [cipherId, ACTION_LABEL_2, credentialIdB64]);

  expect(reveal1.plaintext).toBe(PASSKEY_PLAINTEXT);
  expect(reveal1.promptVisibleAtTap).toBe(true);
  expect(reveal1.promptText).toContain(PASSKEY_NAME);
  expect(reveal1.prfCounter - baseline.prf).toBe(1);
  expect(reveal1.decryptCounter - baseline.decrypt).toBe(1);
  expect(reveal1.wasmDecryptCalls - baseline.wasmDecryptCalls).toBe(1);

  const leak = await page.evaluate((needle) => {
    const w = window as unknown as { RagewardenVault: Record<string, unknown> };
    for (const k of Object.keys(w.RagewardenVault)) {
      const v = w.RagewardenVault[k];
      if (typeof v === 'string' && v === needle) return `leaked under key ${k}`;
    }
    return null;
  }, PASSKEY_PLAINTEXT);
  expect(leak).toBeNull();

  const reveal2 = await page.evaluate(async ([cid, label, credB64]) => {
    const w = window as unknown as RagewardenWindowExtended;
    function b64ToBytes(b64: string): Uint8Array {
      const bin = atob(b64);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    return w.__ragewardenHarness.revealViaWasmDecryptWithPasskey(
      cid as string, label as string, b64ToBytes(credB64 as string),
    );
  }, [cipherId, ACTION_LABEL_2, credentialIdB64]);
  expect(reveal2.plaintext).toBe(PASSKEY_PLAINTEXT);
  expect(reveal2.prfCounter - baseline.prf).toBe(2);
  expect(reveal2.decryptCounter - baseline.decrypt).toBe(2);
  expect(reveal2.wasmDecryptCalls - baseline.wasmDecryptCalls).toBe(2);

  await page.close();
  void auth;
});

/**
 * The SHIPPED write/read path, end to end, through the CDP virtual
 * authenticator: `RagewardenVault.setCipher` -> popup reboot ->
 * `RagewardenVault.revealPassword`.
 *
 * Both tests above drive `window.__ragewardenHarness`, which builds its own
 * passkey record and calls wasm directly. They prove the crypto. They do not
 * prove that the extension's own glue -- `enrollPasskey`'s registry entry,
 * `selectEncryptRecipients`, `unlockOnce`'s tap ceremony -- is wired to it, and
 * they count taps only inside the harness they installed themselves.
 *
 * So this asserts two things that must both hold, and neither alone is worth
 * anything:
 *
 *   - the plaintext comes back, and
 *   - a WebAuthn assertion was actually requested to get it.
 *
 * Then the same reveal is run with `navigator.credentials.get` refused, and it
 * must fail. Without that control, "the plaintext came back" is satisfied by a
 * cached copy, a plaintext write, or a software secret sitting unsealed on
 * disk -- the reveal succeeding tells you nothing about where the key came from.
 *
 * The refusal is a throwing wrapper installed via `addInitScript`, NOT
 * `WebAuthn.removeVirtualAuthenticator`: with the authenticator removed
 * `credentials.get` never settles and the test burns its whole timeout instead
 * of failing.
 */
test('the browser opens what it writes, and only by asking the authenticator', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(180_000);

  const page = await context.newPage();
  await attachVirtualAuthenticator(page);

  // Installed before any page script, so nothing can capture the original
  // `credentials.get` first and route around the counter.
  await page.addInitScript(() => {
    const w = window as unknown as { __prfCalls: number; __prfBreak: boolean };
    w.__prfCalls = 0;
    w.__prfBreak = false;
    const orig = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = async (o?: CredentialRequestOptions) => {
      w.__prfCalls++;
      if (w.__prfBreak) throw new Error('simulated: no authenticator present');
      return orig(o);
    };
  });

  const suffix = randomSuffix();
  const email = `e2e-shipped-${suffix}@ragewarden.test`;
  const password = `e2e-shipped-pw-${suffix}`;

  await page.goto(popupUrl);
  // dismissProtectionWizard:false + click the PRIMARY button: this test needs
  // the real `enrollPasskey`, not the skip path the other two take.
  await fillOnboarding(page, {
    server: vaultwardenUrl, email, password, mode: 'register',
    dismissProtectionWizard: false,
  });
  await page.waitForSelector('.ragewarden-onb-card h1', { state: 'visible' });
  await expect(page.locator('.ragewarden-onb-card h1')).toHaveText('Set up Ragewarden protection');
  await page.click('.ragewarden-onb-primary');
  await waitForBootstrap(page);

  const registry = await page.evaluate(async () => {
    const w = window as unknown as {
      RagewardenVault: { listRecipients: () => Promise<{ id: string; kind: string }[]> };
    };
    return w.RagewardenVault.listRecipients();
  });
  expect(
    registry.filter(e => e.kind === 'PasskeyPrf' && e.id.startsWith('passkey-')).length,
    'the enrolment under test published a PasskeyPrf entry',
  ).toBe(1);

  const SHIPPED_PLAINTEXT = `shipped-path-secret-${suffix}`;
  const SHIPPED_NAME = `shipped-item-${suffix}`;
  await page.evaluate(async ([n, pt]) => {
    const w = window as unknown as {
      RagewardenVault: { setCipher: (n: string, pt: string, o?: unknown) => Promise<unknown> };
    };
    await w.RagewardenVault.setCipher(n as string, pt as string, {});
  }, [SHIPPED_NAME, SHIPPED_PLAINTEXT]);

  const listItem = async () => page.evaluate((n) => {
    type C = { name: string; id: string; rage?: boolean }[];
    const w = window as unknown as { ITEMS_BY_KIND?: C; VAULT?: C };
    const all = [...(w.VAULT ?? []), ...(w.ITEMS_BY_KIND ?? [])];
    const hit = all.find(c => c.name === n && !!c.rage);
    return hit ? hit.id : null;
  }, SHIPPED_NAME);

  const reboot = async () => {
    await page.goto('about:blank');
    await page.goto(popupUrl);
    await waitForBootstrap(page);
  };

  // Reboot first: an in-memory secret from the write would make the reveal
  // below prove nothing about what reached the server.
  await reboot();
  const cipherId = await listItem();
  expect(cipherId, 'the popup lists the item it just wrote').toBeTruthy();

  const prfCalls = async () =>
    page.evaluate(() => (window as unknown as { __prfCalls: number }).__prfCalls);

  const before = await prfCalls();
  const revealed = await page.evaluate(async (id) => {
    const w = window as unknown as {
      RagewardenVault: { revealPassword: (id: string) => Promise<string> };
    };
    return w.RagewardenVault.revealPassword(id as string);
  }, cipherId!);
  const after = await prfCalls();

  expect(revealed, 'POSITIVE -- the browser opens what it wrote').toBe(SHIPPED_PLAINTEXT);
  expect(
    after - before,
    'the reveal really went through the virtual authenticator; a plaintext returned with '
    + 'zero assertions means the secret came from somewhere it should not exist',
  ).toBeGreaterThanOrEqual(1);

  await reboot();
  await page.evaluate(() => {
    (window as unknown as { __prfBreak: boolean }).__prfBreak = true;
  });
  const cipherId2 = await listItem();
  expect(cipherId2, 'the item survives a second reboot').toBeTruthy();

  let threw = '';
  try {
    await page.evaluate(async (id) => {
      const w = window as unknown as {
        RagewardenVault: { revealPassword: (id: string) => Promise<string> };
      };
      return w.RagewardenVault.revealPassword(id as string);
    }, cipherId2!);
  } catch (e) {
    threw = (e as Error).message;
  }
  expect(
    threw,
    'CONTROL -- refuse the assertion and the identical reveal must fail. If this reveal '
    + 'succeeds, the positive one above was not being paid for by the authenticator.',
  ).not.toBe('');
  expect(
    threw.includes(SHIPPED_PLAINTEXT),
    'the failure path must not carry the plaintext in its message',
  ).toBe(false);

  await page.close();
});

async function assertCipherCarriesEncryptedRageBlob(server: string, token: string, cipherId: string, plaintext: string): Promise<void> {
  const res = await fetch(`${server}/api/sync`, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Bitwarden-Client-Name': 'web',
      'Bitwarden-Client-Version': '2024.10.0',
    },
  });
  if (!res.ok) throw new Error(`/api/sync failed: ${res.status}`);
  const body = await res.json();
  const ciphers: Array<Record<string, unknown>> = body?.Ciphers ?? body?.ciphers ?? [];
  const ours = ciphers.find(c => (c.Id ?? c.id) === cipherId);
  if (!ours) throw new Error(`cipher ${cipherId} not found in /api/sync response`);
  const haystack = JSON.stringify(ours);
  if (haystack.includes(plaintext)) {
    throw new Error('plaintext leaked into Vaultwarden cipher payload (§0d violation)');
  }
  if (!haystack.includes('2.')) {
    throw new Error('expected Type-2 EncString markers in cipher payload');
  }
}

async function assertServerStoredEncryptedBlob(server: string, token: string, cipherId: string): Promise<void> {
  const res = await fetch(`${server}/api/sync`, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Bitwarden-Client-Name': 'web',
      'Bitwarden-Client-Version': '2024.10.0',
    },
  });
  if (!res.ok) throw new Error(`/api/sync failed: ${res.status}`);
  const body = await res.json();
  const ciphers: Array<Record<string, unknown>> = body?.Ciphers ?? body?.ciphers ?? [];
  const ours = ciphers.find(c => (c.Id ?? c.id) === cipherId);
  if (!ours) throw new Error(`cipher ${cipherId} not found in /api/sync response`);

  const haystack = JSON.stringify(ours);
  if (haystack.includes(FIXTURE_PLAINTEXT)) {
    throw new Error('plaintext leaked into Vaultwarden cipher payload (§0d violation)');
  }
  if (!haystack.includes('2.')) {
    throw new Error('expected Type-2 EncString markers in cipher payload');
  }
  if (!haystack.includes('age-encryption.org') && !haystack.toLowerCase().includes('begin age')) {
  }
}

const HARNESS_HELPERS = String.raw`
(() => {
  if (window.__ragewardenHarness) return;
  const RP_ID = location.hostname;
  // Must decode to exactly 32 bytes (Recipient::PasskeyPrf requirement).
  // Old placeholder was 49 bytes -- replaced with a 32-byte ASCII tag.
  const SALT_B64 = 'cmFnZXdhcmRlbi10ZXN0LXNhbHQtMS0tLS0tLi4uLi4=';
  const STORAGE_KEY = 'ragewarden:test:passkey';

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

  function setLocal(key, value) {
    return new Promise((resolve, reject) => {
      try {
        chrome.storage.local.set({ [key]: value }, () => {
          if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
          else resolve();
        });
      } catch (e) { reject(e); }
    });
  }
  function getLocal(key) {
    return new Promise((resolve, reject) => {
      try {
        chrome.storage.local.get([key], items => {
          if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
          else resolve(items[key] ?? null);
        });
      } catch (e) { reject(e); }
    });
  }
  function getSessionLocal(key) {
    return new Promise((resolve, reject) => {
      try {
        chrome.storage.session.get([key], items => {
          if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
          else resolve(items[key] ?? null);
        });
      } catch (e) { reject(e); }
    });
  }

  const counters = { prf: 0, decrypt: 0, wasmDecryptCalls: 0 };

  async function instrumentedDecryptWithSoftware(wasm, blobBytes, secretArmored) {
    counters.wasmDecryptCalls += 1;
    return wasm.wasm_decrypt_with_software(blobBytes, secretArmored);
  }

  async function prfEval(credentialId, saltBytes) {
    // Single source of truth for the §0b PRF counter -- every passkey
    // ceremony goes through this helper (revealOnce calls it directly;
    // revealViaWasmDecryptWithPasskey wraps it in a prfCallback). The
    // wrapper must NOT bump again, or §0b's lockstep assertion
    // double-counts.
    counters.prf += 1;
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId: RP_ID,
        allowCredentials: [{ id: credentialId, type: 'public-key' }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: saltBytes } } },
      },
    });
    const ext = assertion.getClientExtensionResults();
    const prf = ext && ext.prf && ext.prf.results && ext.prf.results.first;
    if (!prf) throw new Error('prf extension produced no result; authenticator missing PRF capability');
    return new Uint8Array(prf);
  }

  async function importAesGcmKey(rawBytes) {
    return crypto.subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  async function enrollPasskeyAndKeygen() {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = crypto.getRandomValues(new Uint8Array(16));
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { id: RP_ID, name: 'Ragewarden test' },
        user: { id: userId, name: 'e2e@ragewarden.test', displayName: 'e2e' },
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
    const credentialId = new Uint8Array(cred.rawId);

    const prfBytes = await prfEval(credentialId, b64ToBytes(SALT_B64));
    const wrapKey = await importAesGcmKey(prfBytes);

    const wasm = await window.RagewardenVault.crypto.init();
    const kg = wasm.wasm_software_keygen();
    const secretArmored = new TextDecoder().decode(kg.secret);
    const publicKey = new Uint8Array(kg.public_key);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, new TextEncoder().encode(secretArmored)),
    );

    await setLocal(STORAGE_KEY, {
      credentialIdB64: bytesToB64(credentialId),
      saltB64: SALT_B64,
      ivB64: bytesToB64(iv),
      wrappedB64: bytesToB64(wrapped),
      publicKeyB64: bytesToB64(publicKey),
    });

    return bytesToB64(publicKey);
  }

  async function createRageCipher(name, plaintext, pubkeyB64) {
    const session = await getSession();
    const wasm = await window.RagewardenVault.crypto.init();
    const fields = { name, rage: plaintext, site: 'https://' + name };
    const recipients = [{ kind: 'x25519', public_key_b64: pubkeyB64 }];
    const saved = await wasm.wasm_create_cipher(session, fields, recipients);
    return saved.id;
  }

  async function getSession() {
    const env = await getLocal('ragewarden:sessionEnvelope');
    const rawKeyB64 = await getSessionLocal('ragewarden:envelopeKey');
    if (!env || !rawKeyB64) throw new Error('no persisted session envelope');
    const keyBytes = b64ToBytes(rawKeyB64);
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    const pt = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBytes(env.iv) }, key, b64ToBytes(env.ct),
    ));
    return JSON.parse(new TextDecoder().decode(pt));
  }

  async function decryptType2Bytes(encStr, encKey, macKey) {
    if (!encStr || !encStr.startsWith('2.')) throw new Error('not a Type-2 EncString');
    const body = encStr.slice(2);
    const parts = body.split('|');
    if (parts.length !== 3) throw new Error('Type-2 has wrong shape');
    const iv = b64ToBytes(parts[0]);
    const ct = b64ToBytes(parts[1]);
    const macProvided = b64ToBytes(parts[2]);

    const macKeyImported = await crypto.subtle.importKey(
      'raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    );
    const ivCt = new Uint8Array(iv.length + ct.length);
    ivCt.set(iv, 0); ivCt.set(ct, iv.length);
    const macComputed = new Uint8Array(await crypto.subtle.sign('HMAC', macKeyImported, ivCt));
    if (macComputed.length !== macProvided.length) throw new Error('mac length mismatch');
    let diff = 0;
    for (let i = 0; i < macComputed.length; i++) diff |= macComputed[i] ^ macProvided[i];
    if (diff !== 0) throw new Error('mac mismatch');

    const aesKey = await crypto.subtle.importKey('raw', encKey, { name: 'AES-CBC' }, false, ['decrypt']);
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, ct));
    return pt;
  }

  async function decryptType2Utf8(encStr, encKey, macKey) {
    const bytes = await decryptType2Bytes(encStr, encKey, macKey);
    return new TextDecoder().decode(bytes);
  }

  function renderActionPrompt(label) {
    const existing = document.getElementById('ragewarden-test-action-prompt');
    if (existing) existing.remove();
    const div = document.createElement('div');
    div.id = 'ragewarden-test-action-prompt';
    div.setAttribute('data-ragewarden-action', label);
    div.style.cssText = 'position:fixed;top:8px;right:8px;background:#222;color:#faf6ee;padding:8px 12px;border-radius:6px;z-index:99999;';
    div.textContent = label;
    document.body.appendChild(div);
  }

  async function revealOnce(cipherId, actionLabel) {
    counters.decrypt += 1;
    const stored = await getLocal(STORAGE_KEY);
    if (!stored) throw new Error('no enrolled passkey state');

    renderActionPrompt(actionLabel);
    const promptEl = document.getElementById('ragewarden-test-action-prompt');
    const promptVisibleAtTap = !!promptEl;
    const promptText = promptEl ? promptEl.textContent : '';

    const credentialId = b64ToBytes(stored.credentialIdB64);
    const saltBytes = b64ToBytes(stored.saltB64);
    const prfBytes = await prfEval(credentialId, saltBytes);
    const wrapKey = await importAesGcmKey(prfBytes);
    const secretBytes = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64ToBytes(stored.ivB64) },
        wrapKey,
        b64ToBytes(stored.wrappedB64),
      ),
    );
    const secretArmored = new TextDecoder().decode(secretBytes);

    const session = await getSession();
    const wasm = await window.RagewardenVault.crypto.init();
    const snapshot = await wasm.wasm_fetch_vault(session);
    const cipher = snapshot.ciphers.find(c => c.id === cipherId);
    if (!cipher) throw new Error('cipher not found in fetched vault');

    const encKey = b64ToBytes(session.user_enc_key_b64);
    const macKey = b64ToBytes(session.user_mac_key_b64);

    const fields = (cipher.raw && (cipher.raw.fields || cipher.raw.Fields)) || [];
    let rageBlobArmored = null;
    for (const f of fields) {
      const fieldNameEnc = f.name || f.Name;
      const fieldName = await decryptType2Utf8(fieldNameEnc, encKey, macKey);
      if (fieldName === 'rage:v1') {
        const fieldValueEnc = f.value || f.Value;
        rageBlobArmored = await decryptType2Utf8(fieldValueEnc, encKey, macKey);
        break;
      }
    }
    if (!rageBlobArmored) throw new Error('rage:v1 field absent on cipher');

    const blobBytes = new TextEncoder().encode(rageBlobArmored);
    const plaintextBytes = await instrumentedDecryptWithSoftware(wasm, blobBytes, secretArmored);
    const plaintext = new TextDecoder().decode(new Uint8Array(plaintextBytes));

    return {
      plaintext,
      promptVisibleAtTap,
      promptText,
      prfCounter: counters.prf,
      decryptCounter: counters.decrypt,
      wasmDecryptCalls: counters.wasmDecryptCalls,
    };
  }

  // ── Real Recipient::PasskeyPrf flow ─────────────────────────────────────────────
  //
  // This exercises the wasm_decrypt_with_passkey + Recipient::PasskeyPrf path. The
  // age stanza format is webauthn-prf-v1; HKDF info string is "webauthn-prf-v1"
  // (forever-stable contract -- see core/src/stanza_format.rs and DESIGN.md §3a).

  async function enrollPasskeyOnly() {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = crypto.getRandomValues(new Uint8Array(16));
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { id: RP_ID, name: 'Ragewarden test' },
        user: { id: userId, name: 'e2e@ragewarden.test', displayName: 'e2e' },
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
    return new Uint8Array(cred.rawId);
  }

  async function createPasskeyPrfCipher(name, plaintext, credentialId) {
    const session = await getSession();
    const wasm = await window.RagewardenVault.crypto.init();
    const saltBytes = b64ToBytes(SALT_B64);
    // PRF eval at encrypt time so WASM can wrap the file key under the recipient's
    // PRF derivation. Using the same authenticator + salt produces the same bytes,
    // so the unlock path can re-derive without further coordination.
    const prfBytes = await prfEval(credentialId, saltBytes);

    const fields = { name, rage: plaintext, site: 'https://' + name };
    const recipients = [{
      kind: 'passkey_prf',
      credential_id_b64: bytesToB64(credentialId),
      salt_b64: SALT_B64,
      rp_id: RP_ID,
      label: 'Test passkey',
    }];
    const prfTable = [{
      rp_id: RP_ID,
      salt_b64: SALT_B64,
      prf_output_b64: bytesToB64(prfBytes),
    }];
    const saved = await wasm.wasm_create_cipher_with_prf(session, fields, recipients, prfTable);
    return saved.id;
  }

  async function revealViaWasmDecryptWithPasskey(cipherId, actionLabel, credentialId) {
    counters.decrypt += 1;
    renderActionPrompt(actionLabel);
    const promptEl = document.getElementById('ragewarden-test-action-prompt');
    const promptVisibleAtTap = !!promptEl;
    const promptText = promptEl ? promptEl.textContent : '';

    const session = await getSession();
    const wasm = await window.RagewardenVault.crypto.init();
    const snapshot = await wasm.wasm_fetch_vault(session);
    const cipher = snapshot.ciphers.find(c => c.id === cipherId);
    if (!cipher) throw new Error('cipher not found in fetched vault');

    const encKey = b64ToBytes(session.user_enc_key_b64);
    const macKey = b64ToBytes(session.user_mac_key_b64);
    const fields = (cipher.raw && (cipher.raw.fields || cipher.raw.Fields)) || [];
    let rageBlobArmored = null;
    for (const f of fields) {
      const fieldNameEnc = f.name || f.Name;
      const fieldName = await decryptType2Utf8(fieldNameEnc, encKey, macKey);
      if (fieldName === 'rage:v1') {
        const fieldValueEnc = f.value || f.Value;
        rageBlobArmored = await decryptType2Utf8(fieldValueEnc, encKey, macKey);
        break;
      }
    }
    if (!rageBlobArmored) throw new Error('rage:v1 field absent on cipher');
    const blobBytes = new TextEncoder().encode(rageBlobArmored);

    const saltBytes = b64ToBytes(SALT_B64);
    // The PRF callback runs inside WASM, on the same tick. Counters bump on entry --
    // §0b's "lockstep" assertion relies on this counting once per call.
    const prfCallback = async (saltFromWasm) => {
      // prfEval bumps counters.prf -- don't bump again here.
      const prfBytes = await prfEval(credentialId, new Uint8Array(saltFromWasm));
      return prfBytes;
    };

    counters.wasmDecryptCalls += 1;
    const plaintextBytes = await wasm.wasm_decrypt_with_passkey(
      blobBytes, credentialId, saltBytes, prfCallback,
    );
    const plaintext = new TextDecoder().decode(new Uint8Array(plaintextBytes));
    return {
      plaintext,
      promptVisibleAtTap,
      promptText,
      prfCounter: counters.prf,
      decryptCounter: counters.decrypt,
      wasmDecryptCalls: counters.wasmDecryptCalls,
    };
  }

  window.__ragewardenHarness = {
    enrollPasskeyAndKeygen,
    enrollPasskeyOnly,
    createRageCipher,
    createPasskeyPrfCipher,
    revealOnce,
    revealViaWasmDecryptWithPasskey,
    getSession,
    counters,
  };
})();
`;

interface RagewardenWindow {
  RagewardenVault: {
    bootstrapResult: { email: string; ciphers: number };
    crypto: { init(): Promise<unknown> };
  };
  __ragewardenHarness: {
    enrollPasskeyAndKeygen(): Promise<string>;
    createRageCipher(name: string, plaintext: string, pubkeyB64: string): Promise<string>;
    revealOnce(cipherId: string, actionLabel: string): Promise<{
      plaintext: string;
      promptVisibleAtTap: boolean;
      promptText: string;
      prfCounter: number;
      decryptCounter: number;
      wasmDecryptCalls: number;
    }>;
    getSession(): Promise<{ access_token: string; user_enc_key_b64: string; user_mac_key_b64: string }>;
    counters: { prf: number; decrypt: number; wasmDecryptCalls: number };
  };
}

interface RagewardenWindowExtended extends RagewardenWindow {
  __ragewardenHarness: RagewardenWindow['__ragewardenHarness'] & {
    enrollPasskeyOnly(): Promise<Uint8Array>;
    createPasskeyPrfCipher(name: string, plaintext: string, credentialId: Uint8Array): Promise<string>;
    revealViaWasmDecryptWithPasskey(cipherId: string, actionLabel: string, credentialId: Uint8Array): Promise<{
      plaintext: string;
      promptVisibleAtTap: boolean;
      promptText: string;
      prfCounter: number;
      decryptCounter: number;
      wasmDecryptCalls: number;
    }>;
  };
}
