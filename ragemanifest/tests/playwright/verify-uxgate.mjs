// Verifies the undecryptable/internal-item UX gate on the design mockup:
//   - internal registry/history ciphers never render in the vault list
//   - an undecryptable item renders dimmed with a 'Not on this device' badge
//   - clicking it lands on the explanation screen (no decrypt affordances)
//   - the Protect banner counts only (!rage && decryptable) candidates
//   - the bulk-protect wizard targets the same candidate set
// Run: python3 -m http.server 8123 in design/, then node verify-uxgate.mjs
import { chromium } from '@playwright/test';

const OUT = process.env.UXGATE_OUT
  || '/private/tmp/claude-501/-Users-usr-NixOS/6670025e-a26c-476f-aa35-c7c71aeef087/scratchpad';
const URL = 'http://127.0.0.1:8123/RageDroid.html';

let failures = 0;
const check = (label, ok, extra = '') => {
  console.log(`${label}: ${ok ? 'PASS' : 'FAIL'}${extra ? ' ' + extra : ''}`);
  if (!ok) failures++;
};

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });
const pageErrors = [];
page.on('pageerror', e => pageErrors.push(e.message));
await page.goto(URL, { waitUntil: 'networkidle' });
await page.locator('.phone').waitFor({ timeout: 30000 });

// open the tweaks panel; the Start select is the router
await page.evaluate(() => window.postMessage({ type: '__activate_edit_mode' }, '*'));
await page.waitForFunction(() => document.querySelectorAll('select').length > 0, { timeout: 10000 });
const setStart = (screen) => page.evaluate((value) => {
  const sel = [...document.querySelectorAll('select')]
    .find(s => [...s.options].some(o => o.value === value));
  const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set;
  setter.call(sel, value);
  sel.dispatchEvent(new Event('change', { bubbles: true }));
}, screen);

// ── vault list ──────────────────────────────────────────────────────────────
await setStart('vault');
await page.locator('.phone').getByText('Banking -- phone only').waitFor({ timeout: 10000 });

check('INTERNAL-HIDDEN (__ragedroid_recipients_v1__)',
  await page.locator('.phone').getByText('__ragedroid_recipients_v1__').count() === 0);
check('INTERNAL-HIDDEN (legacy recipients note)',
  await page.locator('.phone').getByText('Ragewarden Recipients (do not edit)').count() === 0);

const dimRow = page.locator('.phone [data-off-device]');
check('DIMMED-ROW-PRESENT', await dimRow.count() === 1);
const opacity = await dimRow.evaluate(el => getComputedStyle(el).opacity);
check('DIMMED-ROW-OPACITY', Number(opacity) < 0.7, `(${opacity})`);
check('NOT-ON-DEVICE-BADGE',
  await dimRow.getByText('Not on this device').count() === 1);

// protect banner: spotify + netflix are the only (!rage && decryptable) items;
// the internal registry items are rage:false and must not inflate the count,
// the undecryptable rage item must not appear either.
const banner = await page.locator('.phone').getByText(/unprotected/).first().textContent();
check('PROTECT-BANNER-COUNT', /^\s*2 items are unprotected/.test(banner), `(${banner.trim()})`);

await page.locator('.phone').screenshot({ path: OUT + '/uxgate-1-vault-dimmed.png' });

// ── click the dimmed row -> explanation screen, no decrypt affordances ──────
await dimRow.click();
await page.locator('.phone').getByText(/can.t be opened here/).waitFor({ timeout: 10000 });
check('EXPLANATION-COPY',
  await page.locator('.phone').getByText(/wrapped to 2 recipients, none on this device/).count() >= 1);
check('NO-DECRYPT-AFFORDANCES',
  await page.locator('.phone').getByRole('button', { name: /Reveal|Autofill|Copy/ }).count() === 0);
check('NOTHING-DECRYPTED-NOTE',
  await page.locator('.phone').getByText('Nothing was decrypted').count() === 1);
await page.locator('.phone').screenshot({ path: OUT + '/uxgate-2-not-on-device.png' });

// back returns to the vault
await page.locator('.phone').getByRole('button', { name: 'Back to vault' }).click();
await page.locator('.phone').getByText('Banking -- phone only').waitFor({ timeout: 10000 });
check('BACK-TO-VAULT', true);

// ── bulk-protect wizard targets the same candidate set ─────────────────────
await setStart('bulk-protect');
const headline = await page.locator('.phone').getByText(/not rage-protected/).textContent();
check('BULK-PROTECT-TARGETS', /^\s*2 items /.test(headline), `(${headline.trim()})`);
await page.locator('.phone').screenshot({ path: OUT + '/uxgate-3-bulk.png' });

// ── the tweaks Start select can land on the explanation screen directly ────
await setStart('not-on-device');
await page.locator('.phone').getByText(/can.t be opened here/).waitFor({ timeout: 10000 });
check('START-SELECT-ROUTE', true);

check('NO-PAGE-ERRORS', pageErrors.length === 0, pageErrors.join(' | '));

await browser.close();
console.log(failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
