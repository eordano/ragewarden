import { test, expect, dropRecoveryRecipients, fillOnboarding, finishWizardWithPaper, waitForBootstrap, randomSuffix } from './fixtures';
import { RagetermDriver } from './rageterm-driver';
import type { Page } from '@playwright/test';

const FUZZ_ROUNDS = Number(process.env.RAGEWARDEN_FUZZ_ROUNDS ?? 6);

interface ServerCipher {
  Id?: string;
  Type?: number;
  Name?: { EncryptedString?: string } | string;
  Notes?: { EncryptedString?: string } | string | null;
  Fields?: Array<{
    Name?: { EncryptedString?: string } | string;
    Value?: { EncryptedString?: string } | string | null;
  }> | null;
}

interface SyncResponse { Ciphers?: ServerCipher[] }

/**
 * Read a key that the server may spell in either case.
 *
 * Bitwarden's own API returns PascalCase; Vaultwarden returns camelCase, and
 * the harness runs Vaultwarden 1.37.0. core/src/sync.rs:900 already knows this
 * -- every field there is `#[serde(rename = "Ciphers", alias = "ciphers")]` --
 * but the interfaces above were written PascalCase-only and, because the block
 * that reads them was dead code until now, nothing ever caught it. Reading
 * `sync.Ciphers` off a camelCase body yields undefined, so the two count
 * assertions below saw an empty vault and failed on a server that was in fact
 * holding exactly the ciphertext they meant to inspect.
 *
 * Accept both rather than pinning to Vaultwarden's spelling: this suite is the
 * one that claims cross-client compatibility, so it should not start failing
 * against a real Bitwarden server.
 */
function pick<T>(obj: unknown, ...names: string[]): T | undefined {
  if (!obj || typeof obj !== 'object') return undefined;
  for (const n of names) {
    const v = (obj as Record<string, unknown>)[n];
    if (v !== undefined && v !== null) return v as T;
  }
  return undefined;
}

function syncCiphers(sync: SyncResponse): ServerCipher[] {
  return pick<ServerCipher[]>(sync, 'Ciphers', 'ciphers') ?? [];
}

function cipherFields(c: ServerCipher): Array<Record<string, unknown>> {
  return pick<Array<Record<string, unknown>>>(c, 'Fields', 'fields') ?? [];
}

function fieldString(v: unknown): string {
  if (v == null) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'object' && v !== null) {
    const s = pick<string>(v, 'EncryptedString', 'encryptedString');
    if (typeof s === 'string') return s;
  }
  return '';
}

async function fetchSync(server: string, accessToken: string): Promise<SyncResponse> {
  const res = await fetch(`${server}/api/sync`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Bitwarden-Client-Name': 'web',
      'Bitwarden-Client-Version': '2024.10.0',
    },
  });
  if (!res.ok) throw new Error(`/api/sync ${res.status}`);
  return res.json();
}

async function popupResync(page: Page): Promise<{ ciphers: { id: string; name: string; rage: boolean }[] }> {
  return page.evaluate(async () => {
    const w = window as unknown as {
      RagewardenVault: {
        crypto: { init: () => Promise<{
          wasm_fetch_vault: (s: unknown) => Promise<{ ciphers: { id: string; name: string; rage: boolean }[] }>;
        }> };
      };
    };
    const wasm = await w.RagewardenVault.crypto.init();
    type WindowCiphers = { name: string; id: string; rage?: boolean }[];
    const cached = (window as unknown as { ITEMS_BY_KIND?: WindowCiphers; VAULT?: WindowCiphers }).VAULT ?? [];
    const more = (window as unknown as { ITEMS_BY_KIND?: WindowCiphers }).ITEMS_BY_KIND ?? [];
    const all = [...cached, ...more].map(c => ({ id: c.id, name: c.name, rage: !!c.rage }));
    void wasm;
    return { ciphers: all };
  });
}

async function popupReboot(page: Page, popupUrl: string): Promise<void> {
  await page.goto('about:blank');
  await page.goto(popupUrl);
  await waitForBootstrap(page);
}

/**
 * The popup's Bitwarden access token, read the way the extension itself reads
 * it: the envelope in `chrome.storage.local`, decrypted with the AES-GCM key
 * that lives in `chrome.storage.session` (see `ext/glue/storage.js`).
 *
 * This used to be an inline block that resolved to `''` on every path -- it
 * called `chrome.storage.local.get` and then threw the result away -- so the
 * `if (accessToken)` guard downstream was always false and the "server stays
 * opaque" assertions never ran once. Hence: no fallback to `''`. If the token
 * cannot be read the caller gets an exception and the test fails, because a
 * fuzz run that never checks the server is not a fuzz run worth being green.
 */
async function readAccessToken(page: Page): Promise<string> {
  const got = await page.evaluate(async () => {
    // No `: Uint8Array` return annotation -- that widens to
    // `Uint8Array<ArrayBufferLike>`, which SubtleCrypto's BufferSource will not
    // accept. Let it infer `Uint8Array<ArrayBuffer>`.
    function b64ToBytes(b64: string) {
      const bin = atob(b64);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    type Area = { get: (k: string[], cb: (i: Record<string, unknown>) => void) => void };
    const c = (globalThis as unknown as {
      chrome?: { storage?: { local?: Area; session?: Area } };
    }).chrome;

    const read = (area: Area, key: string) =>
      new Promise<unknown>(res => area.get([key], items => res(items[key] ?? null)));

    let why = 'chrome.storage unavailable in this context';
    if (c?.storage?.local && c.storage.session) {
      try {
        const env = await read(c.storage.local, 'ragewarden:sessionEnvelope') as
          { v?: number; iv?: string; ct?: string } | null;
        const stored = await read(c.storage.session, 'ragewarden:envelopeKey') as string | { k?: string } | null;
        const rawKeyB64 = typeof stored === 'string' ? stored : (stored?.k ?? null);
        if (!env?.iv || !env.ct) why = 'no session envelope in chrome.storage.local';
        else if (!rawKeyB64) why = 'no envelope key in chrome.storage.session';
        else {
          const key = await crypto.subtle.importKey(
            'raw', b64ToBytes(rawKeyB64), { name: 'AES-GCM' }, false, ['decrypt'],
          );
          const pt = new Uint8Array(await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: b64ToBytes(env.iv) }, key, b64ToBytes(env.ct),
          ));
          const blob = JSON.parse(new TextDecoder().decode(pt)) as { access_token?: string };
          if (blob.access_token) return { token: blob.access_token, why: '' };
          why = 'decrypted envelope carries no access_token';
        }
      } catch (e) {
        why = `envelope decrypt failed: ${(e as Error).message}`;
      }
    }
    // Test-hook mirror of the same blob, published by vault.js when the build
    // has testHooks on. Covers the window between login and the first flush of
    // the envelope to storage.
    const mirror = (window as unknown as { __ragewardenSession?: { access_token?: string } })
      .__ragewardenSession;
    if (mirror?.access_token) return { token: mirror.access_token, why: '' };
    return { token: '', why };
  });
  if (!got.token) {
    throw new Error(
      `could not read the popup's access token (${got.why}); the server-opacity `
      + 'assertions cannot run, so this is a failure, not a skip',
    );
  }
  return got.token;
}

async function popupReveal(page: Page, cipherId: string): Promise<string> {
  return page.evaluate(async (id) => {
    const w = window as unknown as { RagewardenVault: { revealPassword: (id: string) => Promise<string> } };
    return w.RagewardenVault.revealPassword(id);
  }, cipherId);
}

/** A cross-device registry entry as `core/src/registry.rs::WireEntry` puts it on the wire. */
interface RegistryEntry {
  id: string;
  kind: string;
  displayName?: string;
  deviceLabel?: string;
  createdAt?: number;
  defaultEncrypt?: boolean;
  fido2CredentialId?: string;
  fido2RpId?: string;
  fido2Salt?: string;
  recoveryArmoredPubkey?: string;
}

async function readRegistry(page: Page): Promise<RegistryEntry[]> {
  return page.evaluate(async () => {
    const w = window as unknown as {
      RagewardenVault: { listRecipients: () => Promise<RegistryEntry[]> };
    };
    return w.RagewardenVault.listRecipients();
  });
}

/**
 * Publish an entry the way another client would: straight through
 * `wasm_publish_recipient_to_registry`, bypassing `vault.js`'s own builders.
 * That is the only way to put a `Fido2` entry in the registry now that the
 * browser never writes one, and it is also how a legacy (mistagged) entry is
 * reproduced without checking out an older build.
 */
async function publishRegistryEntry(page: Page, entry: RegistryEntry): Promise<void> {
  await page.evaluate(async (e) => {
    const w = window as unknown as {
      RagewardenVault: { crypto: { init: () => Promise<{
        wasm_publish_recipient_to_registry: (s: unknown, e: unknown) => Promise<unknown>;
      }> } };
      __ragewardenSession?: unknown;
    };
    const wasm = await w.RagewardenVault.crypto.init();
    await wasm.wasm_publish_recipient_to_registry(w.__ragewardenSession, e);
  }, entry);
}

/** The inverse of `publishRegistryEntry`, same route: straight through wasm. */
async function unpublishRegistryEntry(page: Page, id: string): Promise<void> {
  await page.evaluate(async (i) => {
    const w = window as unknown as {
      RagewardenVault: { crypto: { init: () => Promise<{
        wasm_unpublish_from_registry: (s: unknown, id: string) => Promise<unknown>;
      }> } };
      __ragewardenSession?: unknown;
    };
    const wasm = await w.RagewardenVault.crypto.init();
    await wasm.wasm_unpublish_from_registry(w.__ragewardenSession, i);
  }, id);
}

function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1103515245 + 12345) >>> 0;
    return s / 0x1_0000_0000;
  };
}

function randomPlaintext(rand: () => number, round: number): string {
  const len = 8 + Math.floor(rand() * 32);
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789-_';
  let s = `pt${round}-`;
  for (let i = 0; i < len; i++) s += alphabet[Math.floor(rand() * alphabet.length)];
  return s;
}

test.describe('cross-client fuzz', () => {
  test('rageterm writes round-trip into the popup, registry and server stay opaque', async ({
    context, popupUrl, vaultwardenUrl,
  }) => {
    test.setTimeout(180_000 + 15_000 * FUZZ_ROUNDS);

    const seed = Number(process.env.RAGEWARDEN_FUZZ_SEED ?? Date.now() & 0xffff);
    const rand = rng(seed);
    console.log(`[fuzz] seed=${seed} rounds=${FUZZ_ROUNDS}`);

    const suffix = randomSuffix();
    const email = `fuzz-${suffix}@ragewarden.test`;
    const password = `fuzz-pw-${suffix}-correct-horse-battery`;

    const popup = await context.newPage();
    const cdp = await context.newCDPSession(popup);
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
    await popup.goto(popupUrl);
    await fillOnboarding(popup, {
      server: vaultwardenUrl, email, password, mode: 'register',
      dismissProtectionWizard: false,
    });
    await popup.waitForSelector('.ragewarden-onb-card h1', { state: 'visible' });
    await expect(popup.locator('.ragewarden-onb-card h1')).toHaveText('Set up Ragewarden protection');
    await popup.click('.ragewarden-onb-primary');
    await finishWizardWithPaper(popup);
    await waitForBootstrap(popup);

    const rage = new RagetermDriver({ server: vaultwardenUrl });
    const login = await rage.login(email, password);
    expect(login.code, login.stderr).toBe(0);

    const enroll = await rage.enrollSoftwareIdentity();
    expect(enroll.code, enroll.stderr).toBe(0);
    const sync = await rage.sync();
    expect(sync.code, `warmup sync: ${sync.stderr}`).toBe(0);

    const written = new Map<string, string>();

    for (let round = 0; round < FUZZ_ROUNDS; round++) {
      const roll = rand();
      let action: 'rageterm-write' | 'popup-write' | 'rotate';
      if (roll < 0.4 || written.size === 0) action = 'rageterm-write';
      else if (roll < 0.75) action = 'popup-write';
      else action = 'rotate';

      if (action === 'rotate') {
        const names = [...written.keys()];
        const target = names[Math.floor(rand() * names.length)];
        const r = await rage.rotate(target);
        expect(r.code, `[round ${round}] rageterm rotate ${target}: ${r.stderr}`).toBe(0);

        const expected = written.get(target)!;
        const echo = await rage.get(target);
        expect(echo.code, `[round ${round}] rageterm get post-rotate: ${echo.stderr}`).toBe(0);
        expect(echo.stdout.replace(/\n$/, '')).toBe(expected);

        await popupReboot(popup, popupUrl);
        const view = await popupResync(popup);
        const c = view.ciphers.find(x => x.name === target && x.rage);
        expect(c, `[round ${round}] popup missing rotated cipher`).toBeTruthy();
        const got = await popupReveal(popup, c!.id);
        expect(got, `[round ${round}] popup decrypt rotated`).toBe(expected);
        continue;
      }

      const writer: 'rageterm' | 'popup' = action === 'rageterm-write' ? 'rageterm' : 'popup';
      const name = `fuzz-${round}-${writer}-${Math.floor(rand() * 1e6).toString(16)}`;
      const plaintext = randomPlaintext(rand, round);

      if (writer === 'rageterm') {
        const useLogin = rand() < 0.5;
        const r = useLogin
          ? await rage.setLogin(name, plaintext)
          : await rage.setSecureNote(name, plaintext);
        expect(r.code, `[round ${round}] rageterm set (type=${useLogin ? 'login' : 'note'}): ${r.stderr}`).toBe(0);
      } else {
        const ok = await popup.evaluate(async ([n, pt]) => {
          const w = window as unknown as {
            RagewardenVault: {
              crypto: { init: () => Promise<{
                wasm_select_encrypt_recipients: (s: unknown, ids: unknown) => Promise<unknown>;
                wasm_create_cipher: (s: unknown, fields: unknown, recipients: unknown) => Promise<unknown>;
              }> };
            };
          };
          const wasm = await w.RagewardenVault.crypto.init();
          const sessionBlob = (window as unknown as { __ragewardenSession?: unknown }).__ragewardenSession;
          if (!sessionBlob) return { failed: 'no session on window (build without testHooks?)' };
          // Must go through the canonical policy, exactly as the extension
          // does. This block used to keep only Software/Recovery entries -- the
          // same filter the production code had -- so the cross-client fuzz
          // test agreed with the bug instead of catching it.
          const selection = await wasm.wasm_select_encrypt_recipients(sessionBlob, null) as
            { recipients?: unknown[]; skipped?: unknown[] } | null;
          const recipients = selection?.recipients ?? [];
          if (recipients.length === 0) {
            return {
              failed: 'policy selected no recipients; skipped='
                + JSON.stringify(selection?.skipped ?? []),
            };
          }
          await wasm.wasm_create_cipher(
            sessionBlob,
            { name: n, rage: pt },
            recipients,
          );
          return { ok: true };
        }, [name, plaintext]);
        // An empty selection is precisely the DEFECT-A regression this suite
        // exists to catch: the popup would write a cipher that nobody -- not
        // even the popup itself -- can ever open. This used to `test.skip`,
        // which turned "the regression fired" into a green run and threw away
        // every assertion the earlier rounds had already made. Fail instead.
        expect(
          (ok as { failed?: string }).failed,
          `[round ${round}] popup write`,
        ).toBeUndefined();
      }
      written.set(name, plaintext);

      if (writer === 'popup') {
        await rage.sync();
      }

      const echo = await rage.get(name);
      expect(echo.code, `[round ${round}] rageterm get (writer=${writer}): ${echo.stderr}`).toBe(0);
      expect(echo.stdout.replace(/\n$/, '')).toBe(plaintext);

      await popupReboot(popup, popupUrl);
      const view = await popupResync(popup);

      const popupNames = new Set(view.ciphers.filter(c => c.rage).map(c => c.name));
      for (const [n] of written) {
        expect(popupNames, `[round ${round}] popup missing ${n}`).toContain(n);
      }

      for (const [n, expected] of written) {
        const c = view.ciphers.find(x => x.name === n && x.rage);
        if (!c) continue;

        await popup.evaluate(() => {
          const w = window as unknown as { __ragewardenTapCounters?: Record<string, number> };
          w.__ragewardenTapCounters = { prf_eval: 0, js_decrypt: 0, wasm_decrypt: 0 };
        });

        const got = await popupReveal(popup, c.id);
        expect(got, `[round ${round}] popup decrypt ${n}`).toBe(expected);

        const counters = await popup.evaluate(() => {
          const w = window as unknown as { __ragewardenTapCounters?: Record<string, number> };
          return w.__ragewardenTapCounters ?? {};
        });
        expect(counters.js_decrypt ?? 0,
          `[round ${round}] §0b: js_decrypt didn't bump`).toBeGreaterThanOrEqual(1);
        expect(counters.wasm_decrypt ?? 0,
          `[round ${round}] §0b: wasm_decrypt didn't bump`).toBeGreaterThanOrEqual(1);
        expect(counters.prf_eval ?? 0,
          `[round ${round}] §0b: prf_eval didn't bump`).toBeGreaterThanOrEqual(1);

        const leaked = await popup.evaluate((needle) => {
          const w = window as unknown as { RagewardenVault: Record<string, unknown> };
          for (const k of Object.keys(w.RagewardenVault)) {
            const v = w.RagewardenVault[k];
            if (typeof v === 'string' && v === needle) return `RagewardenVault.${k}`;
          }
          return null;
        }, expected);
        expect(leaked, `[round ${round}] §0c: plaintext leaked into ${leaked}`).toBeNull();
      }

      // §0d -- the server holds ciphertext and nothing else. This runs
      // unconditionally: `readAccessToken` throws rather than handing back a
      // falsy token, so there is no path where the block below is skipped.
      const accessToken = await readAccessToken(popup);
      const sync = await fetchSync(vaultwardenUrl, accessToken);
      const serverCiphers = syncCiphers(sync);
      expect(
        serverCiphers.length,
        `[round ${round}] /api/sync returned no ciphers, so the opacity checks would inspect nothing`,
      ).toBeGreaterThan(0);

      // Whole-response scan first. The per-field walk below only sees the
      // custom-field Values we model; a plaintext that escaped into Name,
      // Notes, or a field shape this test does not know about would sail past
      // it. Serialising the entire body catches all of them.
      const body = JSON.stringify(sync);
      for (const [n, plaintext] of written) {
        expect(
          body.includes(plaintext),
          `[round ${round}] plaintext for ${n} reached the server in the clear`,
        ).toBe(false);
      }

      let inspectedFields = 0;
      for (const c of serverCiphers) {
        for (const f of cipherFields(c)) {
          const v = fieldString(pick(f, 'Value', 'value'));
          if (!v) continue;
          inspectedFields++;
          expect(
            v.startsWith('2.'),
            `[round ${round}] field Value not Type-2 wrapped: ${v.slice(0, 16)}...`,
          ).toBe(true);
        }
      }
      // Every rage cipher carries the age blob in a custom field named
      // `rage:v1` (core/src/sync.rs), so zero inspected fields means the shape
      // changed under us and the Type-2 assertion above became a no-op.
      expect(
        inspectedFields,
        `[round ${round}] no custom field Values on the server -- expected at least the rage:v1 payload`,
      ).toBeGreaterThan(0);
    }

    console.log(`[fuzz] seed=${seed} ✓ ${written.size} ciphers round-tripped rageterm -> popup`);
  });

  test('design surface -- window.FOLDERS reflects folder CRUD; enrollPasskey publishes PasskeyPrf+Software; setCipher type=login produces cipher_type=1', async ({
    context, popupUrl, vaultwardenUrl,
  }) => {
    const suffix = randomSuffix();
    const email = `surface-${suffix}@ragewarden.test`;
    const password = `surface-pw-${suffix}`;

    const popup = await context.newPage();
    const cdp = await context.newCDPSession(popup);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
        hasUserVerification: true, hasPrf: true,
        automaticPresenceSimulation: true, isUserVerified: true,
      },
    });
    await popup.goto(popupUrl);
    await fillOnboarding(popup, {
      server: vaultwardenUrl, email, password, mode: 'register',
      dismissProtectionWizard: false,
    });
    await popup.waitForSelector('.ragewarden-onb-card h1', { state: 'visible', timeout: 30_000 });
    await expect(popup.locator('.ragewarden-onb-card h1'))
      .toHaveText('Set up Ragewarden protection', { timeout: 15_000 });
    await popup.click('.ragewarden-onb-primary');
    await finishWizardWithPaper(popup);
    await waitForBootstrap(popup);

    expect(await popup.evaluate(() => {
      const f = (window as unknown as { FOLDERS?: unknown[] }).FOLDERS;
      return Array.isArray(f) ? f.length : -1;
    }), 'window.FOLDERS exposed as empty array on bootstrap').toBe(0);

    const folderName = `surface-folder-${suffix}`;
    const createdFolderId = await popup.evaluate(async (n) => {
      const w = window as unknown as { RagewardenVault: { createFolder: (n: string) => Promise<{ Id?: string; id?: string }> } };
      const r = await w.RagewardenVault.createFolder(n);
      return r.Id ?? r.id ?? null;
    }, folderName);
    expect(createdFolderId, 'createFolder returned id').toBeTruthy();
    {
      const folders = await popup.evaluate(() => {
        const f = (window as unknown as { FOLDERS?: { id: string; name: string; count: number }[] }).FOLDERS;
        return f ?? [];
      });
      expect(folders.length, 'window.FOLDERS grew after createFolder').toBe(1);
      expect(folders[0].name).toBe(folderName);
      expect(folders[0].count).toBe(0);
    }

    const renamedName = `${folderName}-renamed`;
    await popup.evaluate(async ([id, n]) => {
      const w = window as unknown as { RagewardenVault: { renameFolder: (id: string, n: string) => Promise<unknown> } };
      await w.RagewardenVault.renameFolder(id as string, n as string);
    }, [createdFolderId!, renamedName]);
    expect(await popup.evaluate(() => {
      const f = (window as unknown as { FOLDERS?: { name: string }[] }).FOLDERS;
      return f && f[0] ? f[0].name : null;
    }), 'rename reflected in window.FOLDERS').toBe(renamedName);

    await popup.evaluate(async (id) => {
      const w = window as unknown as { RagewardenVault: { deleteFolder: (id: string) => Promise<unknown> } };
      await w.RagewardenVault.deleteFolder(id as string);
    }, createdFolderId!);
    expect(await popup.evaluate(() => {
      const f = (window as unknown as { FOLDERS?: unknown[] }).FOLDERS;
      return Array.isArray(f) ? f.length : -1;
    }), 'window.FOLDERS shrank after deleteFolder').toBe(0);

    const beforeRegistry = await popup.evaluate(async () => {
      const w = window as unknown as { RagewardenVault: { listRecipients: () => Promise<{ id: string; kind: string }[]> } };
      return w.RagewardenVault.listRecipients();
    });
    // `PasskeyPrf`, not `Fido2`. This assertion used to read `=== 'Fido2'` and
    // so pinned the defect: the browser holds a WebAuthn-PRF passkey, which
    // wraps into the `webauthn-prf-v1` stanza, and `Fido2` decodes to
    // `Recipient::Fido2HmacSecret` -- a stanza this extension has no code to
    // open (`src/wasm/sync.rs` filters to `TAG_WEBAUTHN_PRF_V1`). Every item
    // wrapped to that entry was unopenable in the browser that enrolled it.
    const beforePasskey = beforeRegistry.filter(e => e.kind === 'PasskeyPrf').length;
    const beforeSoftware = beforeRegistry.filter(e => e.kind === 'Software').length;
    const beforeFido2 = beforeRegistry.filter(e => e.kind === 'Fido2').length;

    const enrolled = await popup.evaluate(async (label) => {
      const w = window as unknown as { RagewardenVault: {
        enrollPasskey: (opts: { label: string }) => Promise<{ registryEntryIds: { passkey: string; software: string } }>;
      } };
      return w.RagewardenVault.enrollPasskey({ label });
    }, 'second-passkey');
    expect(enrolled.registryEntryIds.passkey, 'passkey entry id returned').toBeTruthy();
    expect(enrolled.registryEntryIds.software, 'software entry id returned').toBeTruthy();

    const afterRegistry = await popup.evaluate(async () => {
      const w = window as unknown as { RagewardenVault: { listRecipients: () => Promise<{ id: string; kind: string }[]> } };
      return w.RagewardenVault.listRecipients();
    });
    expect(
      afterRegistry.filter(e => e.kind === 'PasskeyPrf').length,
      'enrollPasskey published a PasskeyPrf entry',
    ).toBe(beforePasskey + 1);
    expect(
      afterRegistry.filter(e => e.kind === 'Software').length,
      'enrollPasskey published a Software entry',
    ).toBe(beforeSoftware + 1);
    expect(
      afterRegistry.filter(e => e.kind === 'Fido2').length,
      'the browser must publish no Fido2 entry at all; Fido2 is ragedroid\'s kind',
    ).toBe(beforeFido2);

    const rage = new RagetermDriver({ server: vaultwardenUrl });
    expect((await rage.login(email, password)).code).toBe(0);
    expect((await rage.enrollSoftwareIdentity()).code).toBe(0);
    expect((await rage.sync()).code).toBe(0);

    const loginName = `surface-login-${suffix}`;
    const noteName = `surface-note-${suffix}`;
    const loginPlaintext = `login-plaintext-${suffix}`;
    const notePlaintext = `note-plaintext-${suffix}`;

    await popup.evaluate(async ([n, pt]) => {
      const w = window as unknown as { RagewardenVault: {
        setCipher: (n: string, p: string, opts?: { type: string }) => Promise<unknown>;
      } };
      await w.RagewardenVault.setCipher(n as string, pt as string, { type: 'login' });
    }, [loginName, loginPlaintext]);
    await popup.evaluate(async ([n, pt]) => {
      const w = window as unknown as { RagewardenVault: {
        setCipher: (n: string, p: string) => Promise<unknown>;
      } };
      await w.RagewardenVault.setCipher(n as string, pt as string);
    }, [noteName, notePlaintext]);

    const kinds = await popup.evaluate(async ([login, note]) => {
      const w = window as unknown as {
        RagewardenVault: { crypto: { init: () => Promise<{
          wasm_fetch_vault: (s: unknown) => Promise<{ ciphers: { name: string; kind: string; rage: boolean; raw?: { Type?: number } }[] }>;
        }> } };
        __ragewardenSession?: unknown;
      };
      const wasm = await w.RagewardenVault.crypto.init();
      const v = await wasm.wasm_fetch_vault(w.__ragewardenSession);
      const l = v.ciphers.find(c => c.name === login);
      const n = v.ciphers.find(c => c.name === note);
      return {
        login: { kind: l?.kind, cipher_type: l?.raw?.Type, rage: !!l?.rage },
        note: { kind: n?.kind, cipher_type: n?.raw?.Type, rage: !!n?.rage },
      };
    }, [loginName, noteName]);
    expect(kinds.login.kind, 'snapshot kind=login for type=login').toBe('login');
    expect(kinds.login.cipher_type, 'Bitwarden cipher_type=1 for type=login').toBe(1);
    expect(kinds.login.rage, 'login cipher carries rage:v1').toBe(true);
    expect(kinds.note.kind, 'snapshot kind=note for default').toBe('note');
    expect(kinds.note.cipher_type, 'Bitwarden cipher_type=2 default').toBe(2);
    expect(kinds.note.rage, 'note cipher carries rage:v1').toBe(true);

    expect((await rage.sync()).code).toBe(0);
    {
      const echoLogin = await rage.get(loginName);
      expect(echoLogin.code, `rageterm get login: ${echoLogin.stderr}`).toBe(0);
      expect(echoLogin.stdout.replace(/\n$/, '')).toBe(loginPlaintext);
      const echoNote = await rage.get(noteName);
      expect(echoNote.code, `rageterm get note: ${echoNote.stderr}`).toBe(0);
      expect(echoNote.stdout.replace(/\n$/, '')).toBe(notePlaintext);
    }
  });

  /**
   * Publishing the right kind from now on repairs nobody: `enrollPasskey` runs
   * once, at first sign-in, and the wrong kind is durable server-side state. So
   * this drives the migration against the state a real already-enrolled account
   * is in, and against the entry the migration must NOT touch.
   *
   * The two registries cannot be told apart by id scheme alone across clients --
   * rageterm derives `rageterm-fido2-<sha256(domain||rp||cred)>` for the same
   * credential this browser calls `passkey-<sha256(cred)>` -- so ownership is
   * proved from the local passkey store, and anything unprovable is left as it
   * is. All three cases are exercised here.
   */
  test('the browser repairs its own mistagged Fido2 passkey entry and leaves other Fido2 entries alone', async ({
    context, popupUrl, vaultwardenUrl,
  }) => {
    const suffix = randomSuffix();
    const email = `prfkind-${suffix}@ragewarden.test`;
    const password = `prfkind-pw-${suffix}`;

    const popup = await context.newPage();
    const cdp = await context.newCDPSession(popup);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
        hasUserVerification: true, hasPrf: true,
        automaticPresenceSimulation: true, isUserVerified: true,
      },
    });
    await popup.goto(popupUrl);
    await fillOnboarding(popup, {
      server: vaultwardenUrl, email, password, mode: 'register',
      dismissProtectionWizard: false,
    });
    await popup.waitForSelector('.ragewarden-onb-card h1', { state: 'visible' });
    await expect(popup.locator('.ragewarden-onb-card h1')).toHaveText('Set up Ragewarden protection');
    await popup.click('.ragewarden-onb-primary');
    await finishWizardWithPaper(popup);
    await waitForBootstrap(popup);

    const enrolled = await readRegistry(popup);
    const ownPasskey = enrolled.find(e => e.kind === 'PasskeyPrf' && e.id.startsWith('passkey-'));
    expect(ownPasskey, 'bootstrap published this browser\'s passkey as PasskeyPrf').toBeTruthy();

    // ragedroid's entry. `Fido2` is CORRECT here -- Android passkeys really are
    // wrapped as fido2-hmac (RecipientPolicy.kt) -- so retagging it would orphan
    // every item the phone has already written.
    const androidEntry: RegistryEntry = {
      id: `android-passkey-${suffix}`,
      kind: 'Fido2',
      displayName: 'Pixel passkey',
      deviceLabel: 'Pixel 8',
      createdAt: 1_700_000_000_000,
      defaultEncrypt: true,
      fido2CredentialId: 'aabbccddeeff00112233445566778899',
      fido2RpId: 'ragewarden',
      fido2Salt: '22'.repeat(32),
    };
    await publishRegistryEntry(popup, androidEntry);

    // Rewind this browser's own entry into the state every account enrolled by
    // an older build is permanently in.
    await publishRegistryEntry(popup, { ...ownPasskey!, kind: 'Fido2' });
    expect(
      (await readRegistry(popup)).find(e => e.id === ownPasskey!.id)!.kind,
      'legacy mistagged state reproduced',
    ).toBe('Fido2');

    await popupReboot(popup, popupUrl);
    const repaired = await readRegistry(popup);

    const own = repaired.find(e => e.id === ownPasskey!.id)!;
    expect(own.kind, 'bootstrap migrated this browser\'s own entry to PasskeyPrf').toBe('PasskeyPrf');
    expect(
      { ...own, kind: '' },
      'the migration is a rename in place: id, credential, salt and createdAt all hold still',
    ).toEqual({ ...ownPasskey!, kind: '' });

    const android = repaired.find(e => e.id === androidEntry.id);
    expect(android, 'the Android entry is still in the registry').toBeTruthy();
    expect(
      android,
      'an Android Fido2 entry is correct as published and must survive untouched',
    ).toEqual(androidEntry);

    expect(
      repaired.length,
      'a rename in place must not leave a second copy behind',
    ).toBe(enrolled.length + 1);

    // Fail closed. The id carries only the first 32 hex chars of the digest and
    // a registry is editable by anyone holding the account, so "the id looks
    // like one of mine" is not proof. Same id, different credential id: the
    // browser cannot show the entry is its own, so it does not touch it.
    await publishRegistryEntry(popup, {
      ...ownPasskey!, kind: 'Fido2', fido2CredentialId: '00'.repeat(16),
    });
    await popupReboot(popup, popupUrl);
    expect(
      (await readRegistry(popup)).find(e => e.id === ownPasskey!.id)!.kind,
      'an entry whose credential id does not match a locally held passkey stays as it is',
    ).toBe('Fido2');
  });

  /**
   * The kind made load-bearing -- the one thing the migration test above cannot
   * show.
   *
   * Every other assertion about `kind` in this suite compares a string in the
   * registry to a string in the test. Collapse `Recipient::PasskeyPrf` and
   * `Recipient::Fido2HmacSecret` onto the same stanza tag in core, or teach
   * `registry.rs` to decode the two kinds identically, and all of them stay
   * green while the hazard `rageterm/src/recipients.rs` names comes straight
   * back. This test is the one that goes red for that, because it never reads
   * the kind: it wraps a real secret twice and asks the browser to open both.
   *
   *   kind PasskeyPrf -> Recipient::PasskeyPrf      -> webauthn-prf-v1 stanza
   *   kind Fido2      -> Recipient::Fido2HmacSecret -> fido2-hmac stanza
   *
   * and `src/wasm/sync.rs` unwraps only `TAG_WEBAUTHN_PRF_V1`. Same credential,
   * same salt, same PRF output, same authenticator, same wasm: the ONLY
   * difference between the two writes is the string in the registry.
   *
   * SCOPE, stated plainly so the comment does not overclaim the way the commit
   * message did: no shipped browser path wraps to a PRF recipient today.
   * `vault.js`'s `setCipher` passes `null` for `local_prf_entry_ids`, so
   * passkey entries come back `skipped: no_local_authenticator` and the write
   * lands on the paired `Software` twin. The wrong kind is therefore LATENT for
   * wrapping and ACTIVE as published cross-client metadata. This test reaches
   * past the glue -- `wasm_select_encrypt_recipients(session, [ownEntryId])` --
   * to make the latent half bite, which is what a regression guard on core's
   * decode has to do.
   */
  test('the published kind is load-bearing: the same passkey wrapped as Fido2 is unopenable in the browser that owns it', async ({
    context, popupUrl, vaultwardenUrl,
  }) => {
    test.setTimeout(180_000);
    const suffix = randomSuffix();
    const email = `kindwrap-${suffix}@ragewarden.test`;
    const password = `kindwrap-pw-${suffix}`;

    const popup = await context.newPage();
    const cdp = await context.newCDPSession(popup);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
        hasUserVerification: true, hasPrf: true,
        automaticPresenceSimulation: true, isUserVerified: true,
      },
    });
    await popup.goto(popupUrl);
    await fillOnboarding(popup, {
      server: vaultwardenUrl, email, password, mode: 'register',
      dismissProtectionWizard: false,
    });
    await popup.waitForSelector('.ragewarden-onb-card h1', { state: 'visible' });
    await expect(popup.locator('.ragewarden-onb-card h1')).toHaveText('Set up Ragewarden protection');
    await popup.click('.ragewarden-onb-primary');
    await finishWizardWithPaper(popup);
    await waitForBootstrap(popup);
    await dropRecoveryRecipients(popup);

    const enrolled = await readRegistry(popup);
    const own = enrolled.find(e => e.kind === 'PasskeyPrf' && e.id.startsWith('passkey-'));
    expect(own, 'bootstrap published this browser\'s passkey as PasskeyPrf').toBeTruthy();
    const twin = enrolled.find(e => e.kind === 'Software' && e.id.startsWith('browser-sw-'));
    expect(twin, 'bootstrap published the paired Software twin').toBeTruthy();

    /*
     * DO NOT DELETE THE NEXT LINE. `enrollPasskey` publishes a Software entry
     * whose age secret is sealed under this same passkey's PRF, and policy
     * wraps to every entry it can reach. Leave it published and BOTH writes
     * below open -- through the twin's age stanza, not the passkey's -- the
     * selections come back ['passkey_prf','software_passphrase'] and
     * ['fido2_hmac_secret','software_passphrase'], and the negative half of
     * this test passes for entirely the wrong reason. That is exactly how it
     * behaved on the first run of this reproduction.
     */
    await unpublishRegistryEntry(popup, twin!.id);
    expect(
      (await readRegistry(popup)).some(e => e.id === twin!.id),
      'the Software twin is gone, so the passkey entry is the only wrap target left',
    ).toBe(false);

    // ONE real assertion on the virtual authenticator, reused for both writes,
    // so the authenticator cannot be what differs between them.
    const prfTable = await popup.evaluate(async () => {
      const stored: { credential_id_b64: string; salt_b64: string; rp_id: string } =
        await new Promise(res => {
          const chrome = (globalThis as unknown as { chrome: { storage: { local: {
            get: (k: string[], cb: (i: Record<string, unknown>) => void) => void } } } }).chrome;
          chrome.storage.local.get(['ragewarden:passkey-recipient'], items => {
            const v = items['ragewarden:passkey-recipient'];
            res((Array.isArray(v) ? v[0] : v) as never);
          });
        });
      function b64ToBytes(b64: string) {
        const bin = atob(b64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
      }
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rpId: stored.rp_id,
          allowCredentials: [{ id: b64ToBytes(stored.credential_id_b64), type: 'public-key' }],
          userVerification: 'required',
          extensions: { prf: { eval: { first: b64ToBytes(stored.salt_b64) } } },
        },
      });
      const buf = (assertion as PublicKeyCredential).getClientExtensionResults().prf?.results?.first;
      if (!buf) throw new Error('the virtual authenticator returned no PRF output');
      const bytes = new Uint8Array(buf as ArrayBuffer);
      let s = ''; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return [{ rp_id: stored.rp_id, salt_b64: stored.salt_b64, prf_output_b64: btoa(s) }];
    });
    expect(prfTable.length, 'one PRF output captured from the authenticator').toBe(1);

    const writeWithPrf = async (name: string, pt: string): Promise<string[]> =>
      popup.evaluate(async ([n, p, ownId, table]) => {
        const w = window as unknown as {
          RagewardenVault: { crypto: { init: () => Promise<{
            wasm_select_encrypt_recipients: (s: unknown, ids: unknown) => Promise<{
              recipients: { type: string }[]; skipped: unknown[];
            }>;
            wasm_create_cipher_with_prf: (
              s: unknown, f: unknown, r: unknown, t: unknown,
            ) => Promise<unknown>;
          }> } };
          __ragewardenSession?: unknown;
        };
        const wasm = await w.RagewardenVault.crypto.init();
        const sel = await wasm.wasm_select_encrypt_recipients(w.__ragewardenSession, [ownId]);
        await wasm.wasm_create_cipher_with_prf(
          w.__ragewardenSession, { name: n as string, rage: p as string }, sel.recipients, table,
        );
        return sel.recipients.map(r => r.type).sort();
      }, [name, pt, own!.id, prfTable] as const);

    const GOOD = `kindwrap-prf-secret-${suffix}`;
    const goodTypes = await writeWithPrf('kindwrap-good', GOOD);
    // toEqual, not toContain. toContain is what let the Software twin hide in
    // the set and made the negative half meaningless.
    expect(
      goodTypes,
      'kind=PasskeyPrf decodes this credential to a passkey_prf wrap target, and nothing else',
    ).toEqual(['passkey_prf']);

    // Rewind ONLY the kind. No reboot: a reboot runs the migration, which would
    // repair the entry before the write below lands.
    await publishRegistryEntry(popup, { ...own!, kind: 'Fido2' });

    const BAD = `kindwrap-hmac-secret-${suffix}`;
    const badTypes = await writeWithPrf('kindwrap-bad', BAD);
    expect(
      badTypes,
      'kind=Fido2 decodes the very same credential to a fido2_hmac_secret wrap target',
    ).toEqual(['fido2_hmac_secret']);

    await popupReboot(popup, popupUrl);
    expect(
      (await readRegistry(popup)).find(e => e.id === own!.id)!.kind,
      'the migration repaired the registry on this boot',
    ).toBe('PasskeyPrf');

    const items = (await popupResync(popup)).ciphers;
    const good = items.find(c => c.name === 'kindwrap-good' && c.rage);
    const bad = items.find(c => c.name === 'kindwrap-bad' && c.rage);
    expect(good, 'the popup lists the item wrapped under kind=PasskeyPrf').toBeTruthy();
    expect(bad, 'the popup lists the item wrapped under kind=Fido2').toBeTruthy();

    // Both on the SAME boot. The positive is what rules out "the authenticator
    // broke" as the explanation for the negative.
    expect(
      await popupReveal(popup, good!.id),
      'POSITIVE -- an item wrapped under kind=PasskeyPrf reopens in the browser that owns the key',
    ).toBe(GOOD);

    let threw = '';
    try {
      await popupReveal(popup, bad!.id);
    } catch (e) {
      threw = (e as Error).message;
    }
    expect(
      threw,
      'NEGATIVE -- the same credential wrapped under kind=Fido2 is a fido2-hmac stanza this '
      + 'browser has no code to open. Repairing the registry does NOT repair an item already '
      + 'written; if this ever passes, the two kinds have been collapsed in core.',
    ).toMatch(/no supplied identity matched any stanza|no identity available|none on this device/);

    await popup.close();
  });

  test('I7 -- re-publishing the same registry entry is idempotent', async ({
    context, popupUrl, vaultwardenUrl,
  }) => {

    const suffix = randomSuffix();
    const email = `idemp-${suffix}@ragewarden.test`;
    const password = `idemp-pw-${suffix}`;

    const popup = await context.newPage();
    const cdp = await context.newCDPSession(popup);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
        hasUserVerification: true, hasPrf: true,
        automaticPresenceSimulation: true, isUserVerified: true,
      },
    });
    await popup.goto(popupUrl);
    await fillOnboarding(popup, {
      server: vaultwardenUrl, email, password, mode: 'register',
      dismissProtectionWizard: false,
    });
    await popup.waitForSelector('.ragewarden-onb-card h1', { state: 'visible' });
    await expect(popup.locator('.ragewarden-onb-card h1')).toHaveText('Set up Ragewarden protection');
    await popup.click('.ragewarden-onb-primary');
    await finishWizardWithPaper(popup);
    await waitForBootstrap(popup);

    const before = await popup.evaluate(async () => {
      const w = window as unknown as {
        RagewardenVault: { crypto: { init: () => Promise<{
          wasm_fetch_registry: (s: unknown) => Promise<{ entries?: unknown[] } | null>;
        }> } };
        __ragewardenSession?: unknown;
      };
      const wasm = await w.RagewardenVault.crypto.init();
      const reg = await wasm.wasm_fetch_registry(w.__ragewardenSession);
      return reg?.entries?.length ?? 0;
    });
    expect(before, 'popup published PasskeyPrf + Software entries on bootstrap').toBeGreaterThanOrEqual(2);

    const after = await popup.evaluate(async () => {
      const w = window as unknown as {
        RagewardenVault: { crypto: { init: () => Promise<{
          wasm_fetch_registry: (s: unknown) => Promise<{ entries?: unknown[] } | null>;
          wasm_publish_recipient_to_registry: (s: unknown, e: unknown) => Promise<unknown>;
        }> } };
        __ragewardenSession?: unknown;
      };
      const wasm = await w.RagewardenVault.crypto.init();
      const reg = await wasm.wasm_fetch_registry(w.__ragewardenSession);
      const entries = reg?.entries ?? [];
      for (const e of entries) {
        await wasm.wasm_publish_recipient_to_registry(w.__ragewardenSession, e);
      }
      const reg2 = await wasm.wasm_fetch_registry(w.__ragewardenSession);
      return reg2?.entries?.length ?? 0;
    });
    expect(after, 'I7 -- re-publish of same entries must not duplicate').toBe(before);
  });

  test('I8 -- popup unpublishes its Software entry; rageterm stops encrypting to it', async ({
    context, popupUrl, vaultwardenUrl,
  }) => {

    const suffix = randomSuffix();
    const email = `i8-${suffix}@ragewarden.test`;
    const password = `i8-pw-${suffix}`;

    const popup = await context.newPage();
    const cdp = await context.newCDPSession(popup);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
        hasUserVerification: true, hasPrf: true,
        automaticPresenceSimulation: true, isUserVerified: true,
      },
    });
    await popup.goto(popupUrl);
    await fillOnboarding(popup, {
      server: vaultwardenUrl, email, password, mode: 'register',
      dismissProtectionWizard: false,
    });
    await popup.waitForSelector('.ragewarden-onb-card h1', { state: 'visible' });
    await expect(popup.locator('.ragewarden-onb-card h1')).toHaveText('Set up Ragewarden protection');
    await popup.click('.ragewarden-onb-primary');
    await finishWizardWithPaper(popup);
    await waitForBootstrap(popup);

    const rage = new RagetermDriver({ server: vaultwardenUrl });
    expect((await rage.login(email, password)).code).toBe(0);
    expect((await rage.enrollSoftwareIdentity()).code).toBe(0);
    expect((await rage.sync()).code).toBe(0);

    const baseName = 'i8-baseline';
    const basePt = 'baseline-decryptable-on-both';
    expect((await rage.setSecureNote(baseName, basePt)).code).toBe(0);
    await popupReboot(popup, popupUrl);
    {
      const view = await popupResync(popup);
      const c = view.ciphers.find(x => x.name === baseName && x.rage)!;
      expect(c, 'baseline visible to popup').toBeTruthy();
      expect(await popupReveal(popup, c.id)).toBe(basePt);
    }

    const removed = await popup.evaluate(async () => {
      const w = window as unknown as {
        RagewardenVault: { crypto: { init: () => Promise<{
          wasm_fetch_registry: (s: unknown) => Promise<{ entries?: { id: string; kind: string }[] } | null>;
          wasm_unpublish_from_registry: (s: unknown, id: string) => Promise<unknown>;
        }> } };
        __ragewardenSession?: unknown;
      };
      const wasm = await w.RagewardenVault.crypto.init();
      const reg = await wasm.wasm_fetch_registry(w.__ragewardenSession);
      const sw = (reg?.entries ?? []).find(e => e.kind === 'Software' && e.id.startsWith('browser-sw-'));
      if (!sw) return null;
      await wasm.wasm_unpublish_from_registry(w.__ragewardenSession, sw.id);
      return sw.id;
    });
    expect(removed, 'popup Software entry was published in setup').toBeTruthy();

    expect((await rage.sync()).code).toBe(0);
    const postName = 'i8-post-removal';
    const postPt = 'rageterm-only-decryptable';
    expect((await rage.setSecureNote(postName, postPt)).code).toBe(0);

    {
      const echo = await rage.get(postName);
      expect(echo.code).toBe(0);
      expect(echo.stdout.replace(/\n$/, '')).toBe(postPt);
    }

    await popupReboot(popup, popupUrl);
    {
      const view = await popupResync(popup);
      const c = view.ciphers.find(x => x.name === postName && x.rage);
      expect(c, 'popup sees the cipher metadata').toBeTruthy();
      let threw = false;
      try {
        await popupReveal(popup, c!.id);
      } catch (err) {
        threw = true;
        expect((err as Error).message, 'popup decrypt should fail with no-identity').toMatch(/no supplied identity|none on this device/);
      }
      expect(threw, 'I8 -- popup must NOT decrypt after unpublishing its Software entry').toBe(true);
    }
  });

  test('I13 -- recovery: BIP39 phrase typed on the popup decrypts a rageterm-written cipher', async ({
    context, popupUrl, vaultwardenUrl,
  }) => {

    const suffix = randomSuffix();
    const email = `i13-${suffix}@ragewarden.test`;
    const password = `i13-pw-${suffix}`;

    const rage = new RagetermDriver({ server: vaultwardenUrl });
    const reg = await rage.register(email, password);
    expect(reg.code, `register: ${reg.stderr || reg.stdout}`).toBe(0);
    const lg = await rage.login(email, password);
    expect(lg.code, `login: ${lg.stderr || lg.stdout}`).toBe(0);
    const enr = await rage.enrollSoftwareIdentity();
    expect(enr.code, `enroll: ${enr.stderr || enr.stdout}`).toBe(0);

    const enroll = await rage.enrollRecovery();
    expect(enroll.code, `enroll-recovery: ${enroll.stderr}`).toBe(0);
    const wordPairs: { idx: number; word: string }[] = [];
    for (const m of enroll.stderr.matchAll(/(\d+)\.\s+([a-z]+)/g)) {
      wordPairs.push({ idx: Number(m[1]), word: m[2] });
    }
    const phraseByIdx = new Map<number, string>();
    for (const p of wordPairs) phraseByIdx.set(p.idx, p.word);
    expect(phraseByIdx.size, 'expected 24-word mnemonic').toBe(24);
    const phrase = Array.from({ length: 24 }, (_, i) => phraseByIdx.get(i + 1)).join(' ');

    expect((await rage.sync()).code).toBe(0);
    const NAME = 'i13-cipher';
    const PT = 'recovery-paper-decryptable-after-everything-else-lost';
    expect((await rage.setSecureNote(NAME, PT)).code).toBe(0);

    const popup = await context.newPage();
    await popup.goto(popupUrl);
    await fillOnboarding(popup, {
      server: vaultwardenUrl, email, password, mode: 'login',
      dismissProtectionWizard: true,
    });
    await waitForBootstrap(popup);

    const decrypted = await popup.evaluate(async ([n, ph]) => {
      const w = window as unknown as {
        VAULT?: { id: string; name: string; rage?: boolean }[];
        ITEMS_BY_KIND?: { id: string; name: string; rage?: boolean }[];
        RagewardenVault: { crypto: { init: () => Promise<{
          wasm_recovery_identity_from_phrase: (phrase: string) => { armored_secret: string };
          wasm_decrypt_cipher_field_with_secrets: (
            session: unknown, cipher: unknown, fieldName: string,
            prfCallback: null, secrets: string[],
          ) => Promise<Uint8Array>;
        }> } };
        __ragewardenSession?: unknown;
      };
      const wasm = await w.RagewardenVault.crypto.init();

      const all = [...(w.VAULT ?? []), ...(w.ITEMS_BY_KIND ?? [])];
      const c = all.find(x => x.name === n && x.rage);
      if (!c) throw new Error(`no cipher named ${n}`);

      const wasmAny = wasm as unknown as { wasm_fetch_vault: (s: unknown) => Promise<{ ciphers: { id: string; raw?: unknown }[] }> };
      const snap = await wasmAny.wasm_fetch_vault(w.__ragewardenSession);
      const ci = snap.ciphers.find((x) => x.id === c.id)!;

      const recovery = wasm.wasm_recovery_identity_from_phrase(ph as string);
      const bytes = await wasm.wasm_decrypt_cipher_field_with_secrets(
        w.__ragewardenSession,
        ci,
        'password',
        null,
        [recovery.armored_secret],
      );
      return new TextDecoder().decode(bytes);
    }, [NAME, phrase]);
    expect(decrypted, 'I13 -- phrase-derived identity decrypts recovery-stanza cipher').toBe(PT);
  });

  test('lifecycle -- edit / delete / folders all sync to server and round-trip on rageterm', async ({
    context, popupUrl, vaultwardenUrl,
  }) => {

    const suffix = randomSuffix();
    const email = `lc-${suffix}@ragewarden.test`;
    const password = `lc-pw-${suffix}`;

    const popup = await context.newPage();
    const cdp = await context.newCDPSession(popup);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
        hasUserVerification: true, hasPrf: true,
        automaticPresenceSimulation: true, isUserVerified: true,
      },
    });
    await popup.goto(popupUrl);
    await fillOnboarding(popup, {
      server: vaultwardenUrl, email, password, mode: 'register',
      dismissProtectionWizard: false,
    });
    await popup.waitForSelector('.ragewarden-onb-card h1', { state: 'visible' });
    await expect(popup.locator('.ragewarden-onb-card h1')).toHaveText('Set up Ragewarden protection');
    await popup.click('.ragewarden-onb-primary');
    await finishWizardWithPaper(popup);
    await waitForBootstrap(popup);

    const rage = new RagetermDriver({ server: vaultwardenUrl });
    expect((await rage.login(email, password)).code).toBe(0);
    expect((await rage.enrollSoftwareIdentity()).code).toBe(0);
    expect((await rage.sync()).code).toBe(0);

    const folder = await popup.evaluate(async (n) => {
      const w = window as unknown as { RagewardenVault: { createFolder: (n: string) => Promise<{ Id?: string; id?: string; Name?: { EncryptedString: string }; name?: { EncryptedString: string } }> } };
      return w.RagewardenVault.createFolder(n);
    }, 'lifecycle-folder');
    const folderId = (folder as { Id?: string; id?: string }).Id ?? (folder as { id?: string }).id;
    expect(folderId, 'createFolder returns id').toBeTruthy();

    const written = await popup.evaluate(async ([n, p]) => {
      const w = window as unknown as { RagewardenVault: { setCipher: (n: string, p: string) => Promise<{ Id?: string; id?: string }> } };
      return w.RagewardenVault.setCipher(n as string, p as string);
    }, ['lc-cipher', 'original-plaintext']);
    const cipherId = (written as { Id?: string; id?: string }).Id ?? (written as { id?: string }).id;
    expect(cipherId, 'setCipher returns id').toBeTruthy();

    expect((await rage.sync()).code).toBe(0);
    {
      const echo = await rage.get('lc-cipher');
      expect(echo.code, `rageterm get after setCipher: ${echo.stderr}`).toBe(0);
      expect(echo.stdout.replace(/\n$/, '')).toBe('original-plaintext');
    }

    await popup.evaluate(async ([id, n, p]) => {
      const w = window as unknown as { RagewardenVault: { editCipher: (id: string, n: string, p: string) => Promise<unknown> } };
      await w.RagewardenVault.editCipher(id as string, n as string, p as string);
    }, [cipherId, 'lc-cipher', 'edited-plaintext']);

    expect((await rage.sync()).code).toBe(0);
    {
      const echo = await rage.get('lc-cipher');
      expect(echo.code, `rageterm get after editCipher: ${echo.stderr}`).toBe(0);
      expect(echo.stdout.replace(/\n$/, '')).toBe('edited-plaintext');
    }

    await popup.evaluate(async (id) => {
      const w = window as unknown as { RagewardenVault: { rotateCipher: (id: string) => Promise<unknown> } };
      await w.RagewardenVault.rotateCipher(id as string);
    }, cipherId);
    expect((await rage.sync()).code).toBe(0);
    {
      const echo = await rage.get('lc-cipher');
      expect(echo.code).toBe(0);
      expect(echo.stdout.replace(/\n$/, '')).toBe('edited-plaintext');
    }

    await popup.evaluate(async ([id, n]) => {
      const w = window as unknown as { RagewardenVault: { renameFolder: (id: string, n: string) => Promise<unknown> } };
      await w.RagewardenVault.renameFolder(id as string, n as string);
    }, [folderId, 'lifecycle-folder-renamed']);

    await popup.evaluate(async (id) => {
      const w = window as unknown as { RagewardenVault: { deleteCipher: (id: string) => Promise<unknown> } };
      await w.RagewardenVault.deleteCipher(id as string);
    }, cipherId);

    expect((await rage.sync()).code).toBe(0);
    {
      const list = await rage.listJson();
      const found = list.find(i => i.name === 'lc-cipher');
      expect(found, 'cipher should be gone after deleteCipher').toBeUndefined();
    }

    await popup.evaluate(async (id) => {
      const w = window as unknown as { RagewardenVault: { deleteFolder: (id: string) => Promise<unknown> } };
      await w.RagewardenVault.deleteFolder(id as string);
    }, folderId);

    const recoveryRes = await popup.evaluate(async () => {
      const w = window as unknown as { RagewardenVault: {
        enrollRecovery: () => Promise<{ phrase: string; registryEntryId: string }>;
        listRecipients: () => Promise<{ id: string; kind: string }[]>;
      } };
      const enrolled = await w.RagewardenVault.enrollRecovery();
      const list = await w.RagewardenVault.listRecipients();
      const found = list.find(e => e.id === enrolled.registryEntryId);
      return { phraseLen: enrolled.phrase.split(' ').length, foundKind: found?.kind, id: enrolled.registryEntryId };
    });
    expect(recoveryRes.phraseLen, 'BIP39 phrase has 24 words').toBe(24);
    expect(recoveryRes.foundKind, 'Recovery entry published').toBe('Recovery');

    const after = await popup.evaluate(async (id) => {
      const w = window as unknown as { RagewardenVault: {
        removeRecipient: (id: string) => Promise<unknown>;
        listRecipients: () => Promise<{ id: string }[]>;
      } };
      await w.RagewardenVault.removeRecipient(id as string);
      return (await w.RagewardenVault.listRecipients()).map(e => e.id);
    }, recoveryRes.id);
    expect(after.includes(recoveryRes.id), 'recovery entry removed').toBe(false);

    expect((await rage.sync()).code).toBe(0);
    expect((await rage.run(['folders', 'create', 'rage-folder'])).code).toBe(0);
    expect((await rage.run(['folders', 'list'])).code).toBe(0);
    expect((await rage.setSecureNote('rage-doomed', 'temporary'))).toBeTruthy();

    // `delete` is irreversible -- no trash, no soft delete, no history revision --
    // so its confirmation is typed at the terminal and `--yes`, which exists for
    // the read gate on a software-only vault, does not answer it
    // (rageterm/src/commands.rs::cmd_delete). Three legs, in the order a gate
    // has to be proved: refused without a terminal, refused when the answer is
    // no, honoured when the answer is yes. The first two must also leave the
    // cipher on the server.
    {
      const refused = await rage.run(['delete', 'rage-doomed', '--yes']);
      expect(refused.code, 'delete with no controlling terminal must refuse').not.toBe(0);
      expect(refused.stderr, 'refusal names the missing terminal').toContain('no terminal to type it on');
      const list = await rage.listJson();
      expect(list.find(i => i.name === 'rage-doomed'), 'refused delete left the cipher alone').toBeTruthy();
    }
    {
      const declined = await rage.runOnTty(['delete', 'rage-doomed'], 'n');
      expect(declined.code, `answering no must not delete: ${declined.output}`).not.toBe(0);
      const list = await rage.listJson();
      expect(list.find(i => i.name === 'rage-doomed'), 'declined delete left the cipher alone').toBeTruthy();
    }
    const del = await rage.runOnTty(['delete', 'rage-doomed'], 'y');
    expect(del.code, `rageterm delete on a tty: ${del.output}`).toBe(0);
    {
      const list = await rage.listJson();
      expect(list.find(i => i.name === 'rage-doomed'), 'cipher gone after rage delete').toBeUndefined();
    }
  });

  test('I5 -- popup decrypts via PRF after its software identity is wiped', async ({
    context, popupUrl, vaultwardenUrl,
  }) => {

    const suffix = randomSuffix();
    const email = `i5-${suffix}@ragewarden.test`;
    const password = `i5-pw-${suffix}`;

    const popup = await context.newPage();
    const cdp = await context.newCDPSession(popup);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
        hasUserVerification: true, hasPrf: true,
        automaticPresenceSimulation: true, isUserVerified: true,
      },
    });
    await popup.goto(popupUrl);
    await fillOnboarding(popup, {
      server: vaultwardenUrl, email, password, mode: 'register',
      dismissProtectionWizard: false,
    });
    await popup.waitForSelector('.ragewarden-onb-card h1', { state: 'visible' });
    await expect(popup.locator('.ragewarden-onb-card h1')).toHaveText('Set up Ragewarden protection');
    await popup.click('.ragewarden-onb-primary');
    await finishWizardWithPaper(popup);
    await waitForBootstrap(popup);

    const PT = 'i5-multi-recipient-redundancy-secret';
    const NAME = 'i5-multi';
    const wrote = await popup.evaluate(async ([n, pt]) => {
      const w = window as unknown as {
        RagewardenVault: { crypto: { init: () => Promise<{
          wasm_create_cipher_with_prf: (s: unknown, fields: unknown, recipients: unknown, prfTable: unknown) => Promise<unknown>;
        }> } };
        __ragewardenSession?: unknown;
      };
      const wasm = await w.RagewardenVault.crypto.init();
      const session = w.__ragewardenSession;

      const stored: { passkey?: unknown; software?: unknown } = await new Promise(res => {
        const chrome = (globalThis as unknown as { chrome?: {
          storage?: { local?: { get: (k: string[], cb: (i: Record<string, unknown>) => void) => void } };
        } }).chrome!;
        chrome.storage!.local!.get(
          ['ragewarden:passkey-recipient', 'ragewarden:software-identity'],
          items => res({
            passkey: Array.isArray(items['ragewarden:passkey-recipient'])
              ? items['ragewarden:passkey-recipient'][0]
              : items['ragewarden:passkey-recipient'],
            software: items['ragewarden:software-identity'],
          }),
        );
      });
      const pk = stored.passkey as {
        credential_id_b64: string; salt_b64: string; rp_id: string; label: string;
      };
      const sw = stored.software as { armored_pubkey: string };

      function b64ToBytes(b64: string) {
        const bin = atob(b64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
      }
      function bytesToB64(b: Uint8Array) {
        let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
        return btoa(s);
      }
      const credentialId = b64ToBytes(pk.credential_id_b64);
      const salt = b64ToBytes(pk.salt_b64);
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge,
          rpId: pk.rp_id,
          allowCredentials: [{ id: credentialId, type: 'public-key' }],
          userVerification: 'required',
          extensions: { prf: { eval: { first: salt } } },
        },
      });
      const prfBuf = (assertion as PublicKeyCredential)
        .getClientExtensionResults().prf?.results?.first;
      if (!prfBuf) throw new Error('no PRF in assertion');
      const prfOutput = new Uint8Array(prfBuf as ArrayBuffer);

      const recipients = [
        { kind: 'software', armored_pubkey: sw.armored_pubkey },
        {
          kind: 'passkey_prf',
          credential_id_b64: pk.credential_id_b64,
          salt_b64: pk.salt_b64,
          rp_id: pk.rp_id,
          label: pk.label,
        },
      ];
      const prfTable = [
        { rp_id: pk.rp_id, salt_b64: pk.salt_b64, prf_output_b64: bytesToB64(prfOutput) },
      ];
      const saved = await wasm.wasm_create_cipher_with_prf(
        session, { name: n, rage: pt }, recipients, prfTable,
      );
      return saved as { id?: string; Id?: string };
    }, [NAME, PT]);
    expect(wrote, 'popup wrote multi-stanza cipher').toBeTruthy();

    await popupReboot(popup, popupUrl);
    {
      const view = await popupResync(popup);
      const c = view.ciphers.find(x => x.name === NAME && x.rage)!;
      expect(c).toBeTruthy();
      expect(await popupReveal(popup, c.id)).toBe(PT);
    }

    await popup.evaluate(() => new Promise<void>(res => {
      const chrome = (globalThis as unknown as { chrome?: {
        storage?: { local?: { remove: (k: string[], cb: () => void) => void } };
      } }).chrome!;
      chrome.storage!.local!.remove(['ragewarden:software-identity'], () => res());
    }));

    await popupReboot(popup, popupUrl);
    {
      const view = await popupResync(popup);
      const c = view.ciphers.find(x => x.name === NAME && x.rage)!;
      expect(c).toBeTruthy();
      expect(
        await popupReveal(popup, c.id),
        'I5 -- multi-recipient cipher must still decrypt via PRF after Software identity wiped',
      ).toBe(PT);
    }
  });

});
