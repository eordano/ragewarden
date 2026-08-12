import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { STATE_FILE } from './global-setup';
import type { LaunchMode } from './global-setup';

const execFileP = promisify(execFile);

interface PersistedState {
  mode?: LaunchMode;
  vaultwardenContainerId?: string;
  containerRuntime?: 'docker' | 'podman';
  vaultwardenPid?: number;
}

export default async function globalTeardown(): Promise<void> {
  if (!existsSync(STATE_FILE)) return;
  let state: PersistedState = {};
  try {
    state = JSON.parse(readFileSync(STATE_FILE, 'utf8')) as PersistedState;
  } catch {
  }

  const mode: LaunchMode = state.mode ?? (state.vaultwardenContainerId ? 'container' : state.vaultwardenPid ? 'native' : 'env-url');

  switch (mode) {
    case 'container': {
      const runtime = state.containerRuntime ?? 'docker';
      const id = state.vaultwardenContainerId;
      if (id) {
        console.log(`[global-teardown] stopping Vaultwarden container ${id.slice(0, 12)} via ${runtime}`);
        try {
          await execFileP(runtime, ['stop', id], { timeout: 30_000 });
        } catch (e) {
          console.warn(`[global-teardown] ${runtime} stop failed:`, (e as Error).message);
        }
      }
      break;
    }
    case 'native': {
      const pid = state.vaultwardenPid;
      if (pid) {
        console.log(`[global-teardown] sending SIGTERM to native Vaultwarden pid=${pid}`);
        try {
          process.kill(pid, 'SIGTERM');
        } catch (e) {
          const code = (e as NodeJS.ErrnoException).code;
          if (code !== 'ESRCH') {
            console.warn('[global-teardown] kill SIGTERM failed:', (e as Error).message);
          }
        }
      }
      break;
    }
    case 'env-url':
      break;
  }

  rmSync(STATE_FILE, { force: true });
}
