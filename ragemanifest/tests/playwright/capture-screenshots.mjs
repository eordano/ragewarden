#!/usr/bin/env node
import { chromium } from 'playwright';
import { spawn } from 'child_process';
import { mkdir, writeFile, rm } from 'fs/promises';
import { setTimeout as sleep } from 'timers/promises';
import { join, resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..', '..', '..');
const designDir = join(repoRoot, 'design');
const outDir = process.env.RAGEWARDEN_SCREENSHOT_DIR
    || join(__dirname, 'screenshots');

const PORT = parseInt(process.env.RAGEWARDEN_SCREENSHOT_PORT || '8765', 10);
const EXEC = process.env.PLAYWRIGHT_CHROMIUM_PATH;

const startScreens = [
    'lock', 'first-run', 'vault', 'search',
    'settings', 'add', 'add-recipient', 'paper-recovery',
    'audit', 'backfill',
];

async function openVaultRow(page, name) {
    const row = page.getByText(name, { exact: true }).first();
    await row.waitFor({ state: 'visible' });
    await row.click();
}

const navScreens = [
    {
        name: 'detail',
        from: 'vault',
        async navigate(page) {
            await openVaultRow(page, 'GitHub');
        },
    },
    {
        name: 'kind-detail',
        from: 'vault',
        async navigate(page) {
            await openVaultRow(page, 'Passport -- recovery info');
        },
    },
    {
        name: 'recipient',
        from: 'settings',
        async navigate(page) {
            const row = page.getByText('Primary YubiKey', { exact: true }).first();
            await row.waitFor({ state: 'visible' });
            await row.click();
        },
    },
    {
        name: 'detail-revealed',
        from: 'vault',
        async navigate(page) {
            await openVaultRow(page, 'GitHub');
            await page.waitForSelector('text=Password', { timeout: 5000 });
            await page.getByRole('button', { name: 'Reveal' }).first().click();
            await sleep(4200);
            await page.evaluate(() => {
                const allDivs = Array.from(document.querySelectorAll('div'));
                const label = allDivs.find(d => /^Password$/.test((d.textContent || '').trim()));
                const target = label || allDivs.find(d => /Auto-clear in /.test(d.textContent || ''));
                if (target) target.scrollIntoView({ block: 'start' });
                const scrollers = allDivs.filter(d => {
                    const cs = window.getComputedStyle(d);
                    return cs.overflowY === 'auto' || cs.overflowY === 'scroll';
                });
                scrollers.forEach(s => { s.scrollTop = 0; });
            });
            await sleep(250);
        },
    },
];

const themes = (process.env.RAGEWARDEN_SCREENSHOT_THEMES || 'light,dark').split(',');

async function main() {
    await rm(outDir, { recursive: true, force: true });
    await mkdir(outDir, { recursive: true });

    const server = spawn(
        'python3',
        ['-m', 'http.server', String(PORT), '--bind', '127.0.0.1'],
        { cwd: designDir, stdio: ['ignore', 'ignore', 'ignore'] },
    );
    await sleep(800);

    const browser = await chromium.launch(EXEC ? { executablePath: EXEC } : {});
    const written = [];
    try {
        for (const theme of themes) {
            const ctx = await browser.newContext({
                viewport: { width: 412, height: 880 },
                deviceScaleFactor: 2,
            });
            const page = await ctx.newPage();
            await routeFor(page, PORT, theme);

            let i = 0;
            for (const start of startScreens) {
                const file = await capture(page, theme, ++i, start, async () => {
                    await page.goto(
                        `http://127.0.0.1:${PORT}/RageDroid.html?start=${start}&t=${Date.now()}`,
                        { waitUntil: 'networkidle' },
                    );
                    await sleep(900);
                }, outDir);
                written.push(file);
            }

            for (const nav of navScreens) {
                const file = await capture(page, theme, ++i, nav.name, async () => {
                    await page.goto(
                        `http://127.0.0.1:${PORT}/RageDroid.html?start=${nav.from}&t=${Date.now()}`,
                        { waitUntil: 'networkidle' },
                    );
                    await sleep(700);
                    try {
                        await nav.navigate(page);
                        await sleep(700);
                    } catch (err) {
                        console.warn(`  could not navigate to ${nav.name} from ${nav.from}: ${err.message}`);
                    }
                }, outDir);
                written.push(file);
            }
            await ctx.close();
        }

        await writeFile(
            join(outDir, 'manifest.json'),
            JSON.stringify({
                generatedAt: new Date().toISOString(),
                themes,
                files: written,
            }, null, 2),
        );
        console.log(`\nwrote ${written.length} screenshots to ${outDir}/`);
    } finally {
        await browser.close();
        server.kill();
    }
}

async function routeFor(page, port, theme) {
    await page.route(/RageDroid\.html/, async (route, req) => {
        const u = new URL(req.url());
        const start = u.searchParams.get('start') || 'lock';
        const original = await fetch(`http://127.0.0.1:${port}/RageDroid.html`).then(r => r.text());
        const patched = original
            .replace(/"startScreen":\s*"[a-z-]+"/, `"startScreen": "${start}"`)
            .replace(/"theme":\s*"[a-z]+"/, `"theme": "${theme}"`);
        await route.fulfill({
            status: 200,
            contentType: 'text/html; charset=utf-8',
            body: patched,
        });
    });

    await page.route(/screens-vault\.jsx/, async (route, req) => {
        const original = await fetch(`http://127.0.0.1:${port}/screens-vault.jsx`).then(r => r.text());
        const patched = original.replace(
            /\}, \[phase, chosenAction\]\);/,
            '}, []); // patched for screenshot harness -- see capture-screenshots.mjs',
        );
        await route.fulfill({
            status: 200,
            contentType: 'application/javascript; charset=utf-8',
            body: patched,
        });
    });
}

async function capture(page, theme, idx, name, prepare, outDir) {
    const file = join(
        outDir,
        `${theme}-${String(idx).padStart(2, '0')}-${name}.png`,
    );
    await prepare();
    await page.screenshot({ path: file });
    console.log(`  ${theme} -> ${name}`);
    return file;
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
