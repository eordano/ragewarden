import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WORKSPACE = resolve(__dirname, '..', '..', '..', '..');

export const RAGETERM_BIN =
    process.env.RAGETERM_BIN ?? join(WORKSPACE, 'target', 'debug', 'rageterm');

export interface RunOptions {
    stdin?: string;
    env?: Record<string, string>;
    timeoutMs?: number;
}

export interface RunResult {
    code: number;
    stdout: string;
    stderr: string;
}

/**
 * A run that had a controlling terminal. stdout and stderr are not separable on
 * a pty -- both ends of the program write to the same device, and the answer we
 * type is echoed back by the line discipline -- so there is one `output`.
 */
export interface TtyRunResult {
    code: number;
    output: string;
}

/**
 * `script(1)` from util-linux, used only to hand a child a real pty.
 *
 * rageterm's destructive confirmations (`delete`, `folders remove`,
 * `recipients remove`) read from /dev/tty and refuse when there is none --
 * deliberately, so that `printf 'y\n' | rageterm delete x` cannot answer its own
 * prompt and so `--yes`, which exists for the *read* gate on a software-only
 * vault, cannot reach an irreversible one. Asserting the refusal needs nothing.
 * Asserting that the confirmed path still works needs an actual terminal, and a
 * pty is the only honest way to produce one: it does not weaken the gate, it
 * satisfies it the way a human at a prompt does.
 */
function findScriptBin(): string | null {
    if (process.env.RAGEWARDEN_SCRIPT_BIN) return process.env.RAGEWARDEN_SCRIPT_BIN;
    for (const dir of (process.env.PATH ?? '').split(':')) {
        if (!dir) continue;
        const candidate = join(dir, 'script');
        if (existsSync(candidate)) return candidate;
    }
    return null;
}

const shellQuote = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

export class RagetermDriver {
    readonly configDir: string;
    readonly env: Record<string, string>;
    private password = '';

    constructor(opts: { server: string; configDir?: string }) {
        this.configDir = opts.configDir ?? mkdtempSync(join(tmpdir(), 'rageterm-fuzz-'));
        this.env = {
            RAGEWARDEN_CONFIG_DIR: this.configDir,
            RAGEWARDEN_SERVER: opts.server,
            PATH: process.env.PATH ?? '',
            HOME: process.env.HOME ?? '',
        };
    }

    async run(args: string[], opts: RunOptions = {}): Promise<RunResult> {
        return new Promise((resolveP) => {
            const proc = spawn(RAGETERM_BIN, args, {
                env: { ...this.env, ...(opts.env ?? {}) },
                stdio: ['pipe', 'pipe', 'pipe'],
            });
            let stdout = '';
            let stderr = '';
            proc.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString('utf8'); });
            proc.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8'); });
            const t = setTimeout(() => {
                proc.kill('SIGKILL');
            }, opts.timeoutMs ?? 30_000);
            proc.on('exit', code => {
                clearTimeout(t);
                resolveP({ code: code ?? -1, stdout, stderr });
            });
            if (opts.stdin !== undefined) {
                proc.stdin.write(opts.stdin);
            }
            proc.stdin.end();
        });
    }

    /**
     * Same as `run`, but with a controlling terminal, and `answer` typed at the
     * first prompt that appears on it.
     *
     * Throws rather than skipping when no pty allocator is on PATH: a missing
     * `script(1)` is a broken harness, not a reason to stop asserting that
     * `rageterm delete` deletes. Set RAGEWARDEN_SCRIPT_BIN to point at one, or
     * add `pkgs.util-linux` to devshells/ragewarden.nix.
     */
    async runOnTty(args: string[], answer: string, opts: RunOptions = {}): Promise<TtyRunResult> {
        const scriptBin = findScriptBin();
        if (!scriptBin) {
            throw new Error(
                'runOnTty needs script(1) from util-linux to allocate a pty, and none is on ' +
                'PATH. Set RAGEWARDEN_SCRIPT_BIN, or add pkgs.util-linux to ' +
                'devshells/ragewarden.nix.',
            );
        }
        const cmd = [RAGETERM_BIN, ...args].map(shellQuote).join(' ');
        return new Promise((resolveP) => {
            // -q: no "Script started" preamble. -e: exit with the child's status,
            // not with script's own.
            const proc = spawn(scriptBin, ['-q', '-e', '-c', cmd, '/dev/null'], {
                env: { TERM: 'dumb', ...this.env, ...(opts.env ?? {}) },
                stdio: ['pipe', 'pipe', 'pipe'],
            });
            let output = '';
            proc.stdout.on('data', (chunk: Buffer) => { output += chunk.toString('utf8'); });
            proc.stderr.on('data', (chunk: Buffer) => { output += chunk.toString('utf8'); });
            const t = setTimeout(() => { proc.kill('SIGKILL'); }, opts.timeoutMs ?? 30_000);
            proc.on('exit', code => {
                clearTimeout(t);
                resolveP({ code: code ?? -1, output: output.replace(/\r/g, '') });
            });
            proc.stdin.write(`${answer}\n`);
            proc.stdin.end();
        });
    }

    async register(email: string, password: string): Promise<RunResult> {
        this.password = password;
        return this.run(
            ['register', '--server', this.env.RAGEWARDEN_SERVER, '--email', email,
             '--name', 'fuzz-user'],
            { stdin: `${password}\n${password}\n`, timeoutMs: 60_000 },
        );
    }

    async login(email: string, password: string): Promise<RunResult> {
        this.password = password;
        return this.run(
            ['login', '--server', this.env.RAGEWARDEN_SERVER, '--email', email],
            { stdin: `${password}\n`, timeoutMs: 60_000 },
        );
    }

    async sync(): Promise<RunResult> {
        return this.run(['sync']);
    }

    async enrollSoftwareIdentity(): Promise<RunResult> {
        return this.run(['enroll-software-identity']);
    }

    async enrollRecovery(): Promise<RunResult> {
        return this.run(['enroll-recovery', '--no-confirm']);
    }

    async setSecureNote(name: string, value: string): Promise<RunResult> {
        return this.run(['set', name, '--from-stdin'], { stdin: value });
    }

    async setLogin(name: string, value: string): Promise<RunResult> {
        return this.run(['set', name, '--type', 'login', '--from-stdin'], { stdin: value });
    }

    /**
     * `--yes` is not optional here.
     *
     * rageterm gates every release of a software-protected secret behind either
     * a hardware tap or a typed confirmation on a tty. This driver spawns with
     * pipes and no controlling terminal, so with neither flag nor device it hits
     * ConsentError::NoConsentSurface and exits non-zero -- which is the correct
     * product behaviour, and it is asserted directly in tests/ragewarden-e2e.nix
     * ("no consent surface means no plaintext").
     *
     * These are cross-client round-trip tests; consenting explicitly is what
     * `--yes` is for. Without it, four tests fail on a gate they are not
     * testing.
     *
     * `--yes` covers the *read* gate only. It does not answer a destructive
     * confirmation -- `delete` and friends want a terminal regardless -- so those
     * go through `runOnTty` instead.
     */
    async get(name: string): Promise<RunResult> {
        return this.run(['get', name, '--newline', '--yes']);
    }

    async listJson(): Promise<{ name: string; kind: string; source: string }[]> {
        const r = await this.run(['list', '--json']);
        if (r.code !== 0) throw new Error(`list --json failed: ${r.stderr}`);
        return JSON.parse(r.stdout);
    }

    async recipientsList(): Promise<RunResult> {
        return this.run(['recipients', 'list']);
    }

    /**
     * Same consent gate as get(): reencrypt decrypts before it re-encrypts.
     * --allow-revoke because a browser passkey stanza can only be written by the
     * browser that holds the authenticator; the popup keeps its Software entry.
     */
    async rotate(name: string): Promise<RunResult> {
        return this.run(['reencrypt', name, '--yes', '--allow-revoke']);
    }
}
