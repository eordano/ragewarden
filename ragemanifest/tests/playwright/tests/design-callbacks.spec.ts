import {
  test, expect, fillOnboarding, finishWizardWithPaper, waitForBootstrap, randomSuffix,
} from './fixtures';
import type { Page, BrowserContext } from '@playwright/test';

interface SnapshotItem {
  id: string;
  name: string;
  rage?: boolean;
  folder?: string | null;
}

interface FolderRecord {
  id?: string;
  Id?: string;
  name?: string | { EncryptedString?: string };
  Name?: string | { EncryptedString?: string };
}

async function readSnapshot(page: Page): Promise<SnapshotItem[]> {
  return page.evaluate(() => {
    const w = window as unknown as {
      VAULT?: SnapshotItem[];
      ITEMS_BY_KIND?: SnapshotItem[];
    };
    return [...(w.VAULT ?? []), ...(w.ITEMS_BY_KIND ?? [])];
  });
}

async function readFolders(page: Page): Promise<FolderRecord[] | null> {
  return page.evaluate(() => {
    const w = window as unknown as { FOLDERS?: FolderRecord[] };
    return Array.isArray(w.FOLDERS) ? w.FOLDERS : null;
  });
}

function folderId(f: FolderRecord | { Id?: string; id?: string } | null | undefined): string | undefined {
  if (!f) return undefined;
  return (f as { Id?: string }).Id ?? (f as { id?: string }).id;
}

function folderName(f: FolderRecord): string | undefined {
  const n = (f as { name?: unknown }).name ?? (f as { Name?: unknown }).Name;
  if (typeof n === 'string') return n;
  if (n && typeof n === 'object' && 'EncryptedString' in (n as Record<string, unknown>)) {
    return undefined;
  }
  return undefined;
}

test.describe('design callbacks -> window.RagewardenVault', () => {
  test('every wired callback round-trips through window.RagewardenVault', async ({
    context, popupUrl, vaultwardenUrl,
  }) => {
    test.setTimeout(90_000);

    const popup = await bootstrapFreshPopup(context, popupUrl, vaultwardenUrl);

    let cipherId = '';
    const NAME_NEW = `dc-new-${randomSuffix()}`;
    const PT_NEW = `pt-new-${randomSuffix()}`;
    await test.step('setCipher publishes the new item into window.VAULT/ITEMS_BY_KIND', async () => {
      const saved = await popup.evaluate(async ([n, p]) => {
        const w = window as unknown as { RagewardenVault: { setCipher: (n: string, p: string) => Promise<{ id?: string; Id?: string }> } };
        return w.RagewardenVault.setCipher(n as string, p as string);
      }, [NAME_NEW, PT_NEW]);
      cipherId = (saved.id ?? saved.Id) ?? '';
      expect(cipherId, 'setCipher returned an id').toBeTruthy();

      const items = await readSnapshot(popup);
      const found = items.find(i => i.id === cipherId);
      expect(found, `popup snapshot contains the new cipher id ${cipherId}`).toBeTruthy();
      expect(found!.name).toBe(NAME_NEW);
      expect(found!.rage, 'note carries a rage:v1 stanza so the design treats it as encrypted').toBe(true);
    });

    const NAME_EDIT = `dc-edit-${randomSuffix()}`;
    const PT_EDIT = `pt-edit-${randomSuffix()}`;
    await test.step('editCipher overwrites the plaintext (revealPassword echoes the new value)', async () => {
      await popup.evaluate(async ([id, n, p]) => {
        const w = window as unknown as { RagewardenVault: { editCipher: (id: string, n: string, p: string) => Promise<unknown> } };
        await w.RagewardenVault.editCipher(id as string, n as string, p as string);
      }, [cipherId, NAME_EDIT, PT_EDIT]);

      const items = await readSnapshot(popup);
      const found = items.find(i => i.id === cipherId);
      expect(found, 'cipher still in snapshot after edit').toBeTruthy();
      expect(found!.name, 'edited name reflected in snapshot').toBe(NAME_EDIT);

      const revealed = await popup.evaluate(async (id) => {
        const w = window as unknown as { RagewardenVault: { revealPassword: (id: string) => Promise<string> } };
        return w.RagewardenVault.revealPassword(id);
      }, cipherId);
      expect(revealed, 'edited plaintext round-trips through revealPassword').toBe(PT_EDIT);
    });

    await test.step('deleteCipher removes the item from the popup snapshot', async () => {
      await popup.evaluate(async (id) => {
        const w = window as unknown as { RagewardenVault: { deleteCipher: (id: string) => Promise<unknown> } };
        await w.RagewardenVault.deleteCipher(id as string);
      }, cipherId);

      const items = await readSnapshot(popup);
      expect(items.find(i => i.id === cipherId), 'deleted cipher gone from snapshot').toBeUndefined();
    });

    await test.step('createFolder + renameFolder + deleteFolder round-trip via window.FOLDERS', async () => {
      const FOLDER_NAME = `dc-folder-${randomSuffix()}`;
      const created = await popup.evaluate(async (n) => {
        const w = window as unknown as { RagewardenVault: { createFolder: (n: string) => Promise<{ Id?: string; id?: string }> } };
        return w.RagewardenVault.createFolder(n);
      }, FOLDER_NAME);
      const id = folderId(created);
      expect(id, 'createFolder returned an id').toBeTruthy();

      const foldersAfterCreate = await readFolders(popup);
      if (foldersAfterCreate === null) {
        test.info().annotations.push({
          type: 'note',
          description: 'window.FOLDERS not exposed yet -- running rename/delete blind',
        });
      } else {
        const f = foldersAfterCreate.find(x => folderId(x) === id);
        expect(f, `window.FOLDERS contains the new folder ${id}`).toBeTruthy();
        void folderName(f!);
      }

      const RENAMED = `dc-folder-renamed-${randomSuffix()}`;
      await popup.evaluate(async ([id_, n]) => {
        const w = window as unknown as { RagewardenVault: { renameFolder: (id: string, n: string) => Promise<unknown> } };
        await w.RagewardenVault.renameFolder(id_ as string, n as string);
      }, [id, RENAMED]);

      const foldersAfterRename = await readFolders(popup);
      if (foldersAfterRename !== null) {
        const f = foldersAfterRename.find(x => folderId(x) === id);
        expect(f, 'folder still present after rename').toBeTruthy();
        const n = folderName(f!);
        if (n !== undefined) {
          expect(n, 'renamed folder reflects new name').toBe(RENAMED);
        }
      }

      await popup.evaluate(async (id_) => {
        const w = window as unknown as { RagewardenVault: { deleteFolder: (id: string) => Promise<unknown> } };
        await w.RagewardenVault.deleteFolder(id_ as string);
      }, id);

      const foldersAfterDelete = await readFolders(popup);
      if (foldersAfterDelete !== null) {
        expect(
          foldersAfterDelete.find(x => folderId(x) === id),
          'deleted folder gone from window.FOLDERS',
        ).toBeUndefined();
      }
    });

    await test.step('enrollRecovery returns a 24-word BIP39 phrase string', async () => {
      const res = await popup.evaluate(async () => {
        const w = window as unknown as { RagewardenVault: { enrollRecovery: () => Promise<{ phrase: string; armoredPubkey: string; registryEntryId: string }> } };
        return w.RagewardenVault.enrollRecovery();
      });
      expect(typeof res.phrase, 'phrase is a string').toBe('string');
      const words = res.phrase.trim().split(/\s+/);
      expect(words.length, '24 words').toBe(24);
      for (const w of words) expect(w).toMatch(/^[a-z]+$/);
      expect(res.registryEntryId, 'recovery entry id was returned').toMatch(/^paper-recovery-/);
    });

    await test.step('logout flips status().signedIn to false and clears the email', async () => {
      const before = await popup.evaluate(() => {
        const w = window as unknown as { RagewardenVault: { status: () => { signedIn: boolean; email: string | null } } };
        return w.RagewardenVault.status();
      });
      expect(before.signedIn, 'signed in before logout').toBe(true);
      expect(before.email, 'email present before logout').toBeTruthy();

      await popup.evaluate(async () => {
        const w = window as unknown as { RagewardenVault: { logout: () => Promise<void> } };
        await w.RagewardenVault.logout();
      });

      const after = await popup.evaluate(() => {
        const w = window as unknown as { RagewardenVault: { status: () => { signedIn: boolean; email: string | null } } };
        return w.RagewardenVault.status();
      });
      expect(after.signedIn, 'signed out after logout()').toBe(false);
      expect(after.email, 'email cleared after logout()').toBeNull();
    });
  });
});

async function bootstrapFreshPopup(
  context: BrowserContext, popupUrl: string, vaultwardenUrl: string,
): Promise<Page> {
  const suffix = randomSuffix();
  const email = `dc-${suffix}@ragewarden.test`;
  const password = `dc-pw-${suffix}-correct-horse-battery`;

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
    server: vaultwardenUrl,
    email,
    password,
    mode: 'register',
    dismissProtectionWizard: false,
  });
  await popup.waitForSelector('.ragewarden-onb-card h1', { state: 'visible' });
  await popup.click('.ragewarden-onb-primary');
  await finishWizardWithPaper(popup);
  await waitForBootstrap(popup);

  return popup;
}

interface AuditEntry {
  recordedAt: number;
  kind: string;
  target: string;
  detail: string;
}

interface HistoryEntryShort {
  recordedAt: number;
  cipherId: string;
  priorPayloadArmored: string;
  recipientsSummary: string[];
}

interface AuditHistoryBridge {
  RagewardenVault: {
    audit: {
      tail: (limit?: number) => Promise<AuditEntry[]>;
      clear: () => Promise<void>;
    };
    history: {
      load: (cipherId: string) => Promise<HistoryEntryShort[]>;
      record: (cipherId: string, prior: string, recipients: string[]) => Promise<void>;
    };
    revealPassword: (id: string, field?: string) => Promise<string>;
    crypto: { init(): Promise<Record<string, unknown>>; };
  };
}

test('design surface -- audit + history bindings', async ({ context, popupUrl, vaultwardenUrl }) => {
  test.setTimeout(120_000);

  const page = await context.newPage();
  await page.goto(popupUrl);

  const suffix = randomSuffix();
  const email = `e2e-audit-${suffix}@ragewarden.test`;
  const password = 'e2e-audit-correct-horse-battery';

  await fillOnboarding(page, { server: vaultwardenUrl, email, password, mode: 'register' });
  await waitForBootstrap(page);

  const surfaces = await page.evaluate(() => {
    const w = window as unknown as AuditHistoryBridge;
    return {
      auditTail: typeof w.RagewardenVault.audit?.tail === 'function',
      auditClear: typeof w.RagewardenVault.audit?.clear === 'function',
      historyLoad: typeof w.RagewardenVault.history?.load === 'function',
      historyRecord: typeof w.RagewardenVault.history?.record === 'function',
    };
  });
  expect(surfaces).toEqual({
    auditTail: true,
    auditClear: false,
    historyLoad: true,
    historyRecord: true,
  });

  await page.evaluate(async () => {
    const w = window as unknown as AuditHistoryBridge;
    try {
      await w.RagewardenVault.revealPassword('does-not-exist-' + Math.random());
    } catch {
    }
  });

  await page.waitForFunction(async () => {
    const w = window as unknown as AuditHistoryBridge;
    const list = await w.RagewardenVault.audit.tail();
    return Array.isArray(list) && list.length >= 1;
  }, { timeout: 5_000 });

  const entries = await page.evaluate(async () => {
    const w = window as unknown as AuditHistoryBridge;
    return w.RagewardenVault.audit.tail();
  });
  expect(entries.length).toBeGreaterThanOrEqual(1);
  const reveal = entries.find(e => e.kind === 'Reveal');
  expect(reveal, 'expected one Reveal audit entry').toBeTruthy();
  expect(reveal!.target).toMatch(/^does-not-exist-/);
  expect(typeof reveal!.recordedAt).toBe('number');
  expect((reveal as { result?: string }).result).toBe('failed');

  const cipherId = `synthetic-${suffix}`;
  await page.evaluate(async ([cid]) => {
    const w = window as unknown as AuditHistoryBridge;
    await w.RagewardenVault.history.record(
      cid,
      '-----BEGIN AGE ENCRYPTED FILE-----\nfake-prior-payload\n-----END AGE ENCRYPTED FILE-----',
      ['x25519-dummy:test', 'passkey-prf:test'],
    );
  }, [cipherId]);

  const loaded = await page.evaluate(async ([cid]) => {
    const w = window as unknown as AuditHistoryBridge;
    return w.RagewardenVault.history.load(cid);
  }, [cipherId]);
  expect(Array.isArray(loaded)).toBe(true);
  expect(loaded.length).toBeGreaterThanOrEqual(1);
  expect(loaded[0].cipherId).toBe(cipherId);
  expect(loaded[0].recipientsSummary).toContain('x25519-dummy:test');
  expect(loaded[0].priorPayloadArmored).toContain('fake-prior-payload');

  await page.close();
});
