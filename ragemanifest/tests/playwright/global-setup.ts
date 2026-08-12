import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { promisify } from 'node:util';
import {
  cpSync, existsSync, mkdirSync, openSync, closeSync, readdirSync, readFileSync,
  rmSync, statSync, writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { createServer } from 'node:net';
import { EXTENSION_DIST, PLAYWRIGHT_DIR } from './playwright.config';

const execFileP = promisify(execFile);

const __dirname = dirname(fileURLToPath(import.meta.url));
const RAGEMANIFEST_ROOT = resolve(__dirname, '..', '..');
const WORKSPACE_ROOT = resolve(RAGEMANIFEST_ROOT, '..');
const PKG_DIR = join(RAGEMANIFEST_ROOT, 'pkg');
const BUILD_SCRIPT = join(RAGEMANIFEST_ROOT, 'build.mjs');
const CHROMIUM_DIST = join(RAGEMANIFEST_ROOT, 'dist', 'chromium');
const STATE_FILE = join(PLAYWRIGHT_DIR, '.playwright-state.json');

const CACHE_DIR = join(PLAYWRIGHT_DIR, '.vaultwarden-cache');
const CARGO_BIN = join(CACHE_DIR, 'bin', 'vaultwarden');
const RUNTIME_DATA_DIR = join(CACHE_DIR, 'data');
const RUNTIME_LOG = join(CACHE_DIR, 'vaultwarden.log');

const VAULTWARDEN_VERSION = '1.36.0';
const VAULTWARDEN_IMAGE = `vaultwarden/server:${VAULTWARDEN_VERSION}`;
const VAULTWARDEN_GIT_TAG = VAULTWARDEN_VERSION;
const HEALTH_TIMEOUT_MS = 60_000;
const NATIVE_HEALTH_TIMEOUT_MS = 90_000;

type LaunchMode = 'env-url' | 'container' | 'native';

interface State {
  mode: LaunchMode;
  vaultwardenUrl: string;
  vaultwardenContainerId?: string;
  containerRuntime?: 'docker' | 'podman';
  vaultwardenPid?: number;
  vaultwardenPort?: number;
}

async function buildWasmIfStale(): Promise<void> {
  const pkgJs = join(PKG_DIR, 'ragemanifest.js');
  const pkgWasm = join(PKG_DIR, 'ragemanifest_bg.wasm');
  const fresh = existsSync(pkgJs) && existsSync(pkgWasm);
  if (fresh) {
    const sourcesNewer = sourceMtime() > Math.min(statSync(pkgJs).mtimeMs, statSync(pkgWasm).mtimeMs);
    if (!sourcesNewer) {
      console.log('[global-setup] reusing existing wasm-pack output at', PKG_DIR);
      return;
    }
    console.log('[global-setup] pkg/ stale relative to src/ -- rebuilding');
  }
  console.log('[global-setup] running wasm-pack build --target web ragemanifest');
  await runStreaming('wasm-pack', ['build', '--target', 'web', 'ragemanifest'], WORKSPACE_ROOT);
  if (!existsSync(pkgJs) || !existsSync(pkgWasm)) {
    throw new Error('wasm-pack completed but pkg/ outputs are missing');
  }
}

function sourceMtime(): number {
  let max = 0;
  const walk = (dir: string) => {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) {
        const m = statSync(full).mtimeMs;
        if (m > max) max = m;
      }
    }
  };
  walk(join(RAGEMANIFEST_ROOT, 'src'));
  walk(join(RAGEMANIFEST_ROOT, 'ext', 'glue'));
  return max;
}

async function stageExtension(): Promise<void> {
  console.log('[global-setup] running canonical build: node build.mjs chromium --test-hooks');
  await runStreaming('node', [BUILD_SCRIPT, 'chromium', '--test-hooks'], RAGEMANIFEST_ROOT);

  if (!existsSync(join(CHROMIUM_DIST, 'manifest.json'))) {
    throw new Error(`build.mjs completed but ${CHROMIUM_DIST}/manifest.json is missing`);
  }
  if (!existsSync(join(CHROMIUM_DIST, 'popup', 'RageDroid.html'))) {
    throw new Error(`build.mjs completed but ${CHROMIUM_DIST}/popup/RageDroid.html is missing`);
  }

  console.log('[global-setup] staging canonical chromium build into', EXTENSION_DIST);
  rmSync(EXTENSION_DIST, { recursive: true, force: true });
  mkdirSync(EXTENSION_DIST, { recursive: true });
  cpSync(CHROMIUM_DIST, EXTENSION_DIST, { recursive: true });

  const manifestPath = join(EXTENSION_DIST, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const popupEntry =
    manifest?.action?.default_popup ?? manifest?.side_panel?.default_path ?? null;
  if (popupEntry !== 'popup/RageDroid.html') {
    throw new Error(
      `staged manifest entry-point = ${JSON.stringify(popupEntry)} ` +
      `(expected "popup/RageDroid.html" via action.default_popup or side_panel.default_path); ` +
      `build.mjs may have regressed`,
    );
  }
}

async function bringUpVaultwarden(): Promise<State> {
  const explicitUrl = process.env.VAULTWARDEN_URL;
  if (explicitUrl && explicitUrl.length > 0) {
    console.log(
      `[global-setup] using pre-running Vaultwarden at ${explicitUrl} (VAULTWARDEN_URL set)`,
    );
    await waitForAlive(explicitUrl, HEALTH_TIMEOUT_MS);
    return { mode: 'env-url', vaultwardenUrl: explicitUrl };
  }

  // Explicit configuration beats autodetection, the same way VAULTWARDEN_URL
  // and RAGEWARDEN_CONTAINER_RUNTIME already do. Inside the devshell this is
  // always set, and a docker daemon that happens to be running should not
  // quietly take precedence over the binary the environment chose.
  if (process.env.RAGEWARDEN_VAULTWARDEN_BIN) {
    return startNativeBinary();
  }

  const explicitRuntime = process.env.RAGEWARDEN_CONTAINER_RUNTIME;
  if (explicitRuntime === 'docker' || explicitRuntime === 'podman') {
    if (!(await isOnPath(explicitRuntime))) {
      throw new Error(
        `RAGEWARDEN_CONTAINER_RUNTIME=${explicitRuntime} but \`${explicitRuntime}\` is not on PATH`,
      );
    }
    return startContainer(explicitRuntime);
  }

  if (await isOnPath('docker')) {
    return startContainer('docker');
  }

  if (await isOnPath('podman')) {
    console.log('[global-setup] docker not found; falling back to podman');
    return startContainer('podman');
  }

  if (process.env.RAGEWARDEN_VAULTWARDEN_BIN || process.env.RAGEWARDEN_USE_CARGO_VAULTWARDEN === '1') {
    return startNativeBinary();
  }

  throw new Error(
    [
      '[global-setup] could not bring up Vaultwarden.',
      '',
      'Neither docker nor podman is on PATH, and no fallback was opted into.',
      'Pick one:',
      '',
      '  (0) On NixOS, enter the devshell -- it exports RAGEWARDEN_VAULTWARDEN_BIN',
      '      and the matching Playwright browsers:',
      '        nix develop .#ragewarden',
      '',
      '  (a) Run a Vaultwarden any way you like and export VAULTWARDEN_URL:',
      '        VAULTWARDEN_URL=http://127.0.0.1:8080 npm test',
      '',
      '  (b) Install a container runtime (docker, colima, podman, ...) so the',
      '      existing Tier-2 container path can run.',
      '',
      `  (c) Have Rust available and opt into building Vaultwarden ${VAULTWARDEN_VERSION} from`,
      '      source (slow first time, ~5-10 min, then cached):',
      '        RAGEWARDEN_USE_CARGO_VAULTWARDEN=1 npm test',
      '',
      'See ragemanifest/README.md -> "Tier-2 (Playwright) without Docker" for details.',
    ].join('\n'),
  );
}

async function pullContainerImage(runtime: 'docker' | 'podman'): Promise<void> {
  if (process.env.RAGEWARDEN_SKIP_PULL === '1') return;
  console.log(`[global-setup] ${runtime} pull ${VAULTWARDEN_IMAGE}`);
  try {
    await execFileP(runtime, ['pull', VAULTWARDEN_IMAGE], { timeout: 120_000 });
  } catch (e) {
    console.warn(
      `[global-setup] ${runtime} pull failed (continuing -- image may already be cached):`,
      (e as Error).message,
    );
  }
}

async function startContainer(runtime: 'docker' | 'podman'): Promise<State> {
  await pullContainerImage(runtime);
  console.log(`[global-setup] starting Vaultwarden via ${runtime}`);
  const { stdout } = await execFileP(runtime, [
    'run', '--detach', '--rm',
    '--publish', '0:80',
    '--env', 'SIGNUPS_ALLOWED=true',
    '--env', 'WEB_VAULT_ENABLED=false',
    '--env', 'ROCKET_PORT=80',
    '--env', 'DOMAIN=http://localhost',
    '--env', 'LOGIN_RATELIMIT_MAX_BURST=1000',
    '--env', 'LOGIN_RATELIMIT_SECONDS=1',
    '--env', 'ADMIN_RATELIMIT_MAX_BURST=1000',
    '--env', 'ADMIN_RATELIMIT_SECONDS=1',
    VAULTWARDEN_IMAGE,
  ]);
  const containerId = stdout.trim();
  if (!containerId) throw new Error(`${runtime} run returned no container id`);

  const { stdout: portOut } = await execFileP(runtime, ['port', containerId, '80/tcp']);
  const match = portOut.match(/0\.0\.0\.0:(\d+)|127\.0\.0\.1:(\d+)|\[::\]:(\d+)/);
  if (!match) throw new Error(`could not parse ${runtime} port output: ${portOut}`);
  const port = Number(match[1] ?? match[2] ?? match[3]);
  const url = `http://127.0.0.1:${port}`;
  console.log(
    '[global-setup] Vaultwarden bound at', url,
    `container=${containerId.slice(0, 12)} runtime=${runtime}`,
  );

  await waitForAlive(url, HEALTH_TIMEOUT_MS);
  return {
    mode: 'container',
    vaultwardenUrl: url,
    vaultwardenContainerId: containerId,
    vaultwardenPort: port,
    containerRuntime: runtime,
  };
}

/**
 * A Vaultwarden the environment already provides.
 *
 * The devshell exports this (devshells/ragewarden.nix). Without it a NixOS box
 * with no container runtime had only the `cargo install` path, which is a
 * ten-minute first run and needs network -- so in practice Tier-2 simply did not
 * get run there.
 */
async function ensureCargoVaultwarden(): Promise<string> {
  const provided = process.env.RAGEWARDEN_VAULTWARDEN_BIN;
  if (provided && provided.length > 0) {
    if (!existsSync(provided)) {
      throw new Error(
        `RAGEWARDEN_VAULTWARDEN_BIN=${provided} but that path does not exist`,
      );
    }
    console.log('[global-setup] using provided vaultwarden binary at', provided);
    return provided;
  }
  if (existsSync(CARGO_BIN)) {
    console.log('[global-setup] reusing cached vaultwarden binary at', CARGO_BIN);
    return CARGO_BIN;
  }
  if (!(await isOnPath('cargo'))) {
    throw new Error(
      'RAGEWARDEN_USE_CARGO_VAULTWARDEN=1 but `cargo` is not on PATH. Install Rust (https://rustup.rs) first.',
    );
  }
  mkdirSync(CACHE_DIR, { recursive: true });
  console.log(
    `[global-setup] cargo install vaultwarden ${VAULTWARDEN_VERSION} from git ` +
    `(this can take 5-10 min on first run; cached at ${CARGO_BIN})`,
  );
  await runStreaming(
    'cargo',
    [
      'install',
      '--git', 'https://github.com/dani-garcia/vaultwarden.git',
      '--tag', VAULTWARDEN_GIT_TAG,
      '--locked',
      '--features', 'sqlite',
      '--root', CACHE_DIR,
      'vaultwarden',
    ],
    WORKSPACE_ROOT,
  );
  if (!existsSync(CARGO_BIN)) {
    throw new Error(`cargo install completed but ${CARGO_BIN} is missing`);
  }
  return CARGO_BIN;
}

async function findFreePort(): Promise<number> {
  return new Promise((resolveP, rejectP) => {
    const srv = createServer();
    srv.unref();
    srv.on('error', rejectP);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      if (addr && typeof addr === 'object') {
        const port = addr.port;
        srv.close(() => resolveP(port));
      } else {
        srv.close();
        rejectP(new Error('could not determine free port'));
      }
    });
  });
}

async function startNativeBinary(): Promise<State> {
  const bin = await ensureCargoVaultwarden();
  rmSync(RUNTIME_DATA_DIR, { recursive: true, force: true });
  mkdirSync(RUNTIME_DATA_DIR, { recursive: true });
  const port = await findFreePort();
  const url = `http://127.0.0.1:${port}`;
  console.log('[global-setup] spawning native Vaultwarden on', url, '(log ->', RUNTIME_LOG + ')');

  const env = {
    ...process.env,
    SIGNUPS_ALLOWED: 'true',
    WEB_VAULT_ENABLED: 'false',
    ROCKET_ADDRESS: '127.0.0.1',
    ROCKET_PORT: String(port),
    DOMAIN: url,
    DATA_FOLDER: RUNTIME_DATA_DIR,
    LOG_LEVEL: process.env.LOG_LEVEL ?? 'warn',
    LOGIN_RATELIMIT_MAX_BURST: '1000',
    LOGIN_RATELIMIT_SECONDS: '1',
    ADMIN_RATELIMIT_MAX_BURST: '1000',
    ADMIN_RATELIMIT_SECONDS: '1',
  };
  const logFd = openSync(RUNTIME_LOG, 'a');
  const child: ChildProcess = spawn(bin, [], {
    cwd: CACHE_DIR,
    env,
    stdio: ['ignore', logFd, logFd],
    detached: false,
  });
  closeSync(logFd);
  if (!child.pid) throw new Error('failed to spawn native vaultwarden (no pid)');
  child.on('exit', (code, sig) => {
    console.warn(`[global-setup] native vaultwarden exited code=${code} signal=${sig}`);
  });
  child.unref();

  try {
    await waitForAlive(url, NATIVE_HEALTH_TIMEOUT_MS);
  } catch (e) {
    try { if (child.pid) process.kill(child.pid, 'SIGTERM'); } catch {}
    const tail = existsSync(RUNTIME_LOG)
      ? readFileSync(RUNTIME_LOG, 'utf8').split('\n').slice(-40).join('\n')
      : '(no log)';
    throw new Error(
      `${(e as Error).message}\n--- last lines of ${RUNTIME_LOG} ---\n${tail}`,
    );
  }

  return {
    mode: 'native',
    vaultwardenUrl: url,
    vaultwardenPid: child.pid,
    vaultwardenPort: port,
  };
}

async function isOnPath(cmd: string): Promise<boolean> {
  try {
    await execFileP('which', [cmd]);
    return true;
  } catch {
    return false;
  }
}

async function waitForAlive(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown = null;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${url}/alive`);
      if (res.ok) {
        console.log('[global-setup] /alive returned', res.status);
        return;
      }
      lastErr = `status ${res.status}`;
    } catch (e) {
      lastErr = e;
    }
    await delay(250);
  }
  throw new Error(`Vaultwarden /alive never returned 2xx within ${timeoutMs}ms (last: ${lastErr})`);
}

async function runStreaming(cmd: string, args: string[], cwd: string): Promise<void> {
  await new Promise<void>((resolveP, rejectP) => {
    const proc = spawn(cmd, args, { cwd, stdio: 'inherit' });
    proc.on('error', rejectP);
    proc.on('exit', code => {
      if (code === 0) resolveP();
      else rejectP(new Error(`${cmd} ${args.join(' ')} exited with code ${code}`));
    });
  });
}

export default async function globalSetup(): Promise<void> {
  await buildWasmIfStale();
  await stageExtension();
  const state = await bringUpVaultwarden();
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
  process.env.VAULTWARDEN_URL = state.vaultwardenUrl;
}

export { STATE_FILE };
export type { State, LaunchMode };
