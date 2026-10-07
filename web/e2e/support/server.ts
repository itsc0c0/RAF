/**
 * R$F servers for the end-to-end suite.
 *
 * Every server gets its own private temporary R$F home with the demo workspace (`raf demo load`),
 * listens on 127.0.0.1 on a free port and serves the built workbench (`web/dist`). R$F settings from
 * the caller's environment (`RAF_*`) are not passed on; `PYTHONPATH` and the rest of the ordinary
 * environment are.
 */
import { execFile, spawn } from 'node:child_process';
import {
  closeSync,
  existsSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { createServer } from 'node:net';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

/** `web/` */
export const WEB_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIST_INDEX = path.join(WEB_DIR, 'dist', 'index.html');

/** Set by the global setup for the test workers and the global teardown. */
export const ENV = {
  /** Directory that holds the directory of every server of this run. */
  root: 'RAF_E2E_ROOT',
  /** Base URL of the shared server (tests that change nothing). */
  baseURL: 'RAF_E2E_BASE_URL',
} as const;

const PID_FILE = 'server.pid';
const START_TIMEOUT_MS = 60_000;

export interface RafServer {
  /** `http://127.0.0.1:<port>` */
  baseURL: string;
  /** The server's own directory: R$F home, logs, PID file. */
  dir: string;
  /** `RAF_HOME` of the server. */
  home: string;
  pid: number;
  /** The bearer token every API request needs, when the server was started with one. */
  token?: string;
}

/** The `raf` executable: `RAF_BIN` (absolute, or relative to `web/`), by default `../.venv/bin/raf`. */
export function rafBin(): string {
  return path.resolve(WEB_DIR, process.env.RAF_BIN || '../.venv/bin/raf');
}

/**
 * The Python of raf's environment (only the token-protected server needs it): `RAF_PYTHON`, by
 * default the `python` next to `RAF_BIN` in the virtualenv's `bin/`.
 */
function pythonBin(): string {
  return process.env.RAF_PYTHON
    ? path.resolve(WEB_DIR, process.env.RAF_PYTHON)
    : path.join(path.dirname(rafBin()), 'python');
}

/** Fails early, saying what to do, when the suite cannot run. */
export function checkPrerequisites(): void {
  if (!existsSync(DIST_INDEX)) {
    throw new Error(
      `The web workbench is not built: ${DIST_INDEX} is missing. Run \`npm run build\` in web/ first ` +
        '(the end-to-end suite tests the production build that `raf serve` serves).',
    );
  }
  if (!existsSync(rafBin())) {
    throw new Error(
      `raf was not found at ${rafBin()}. Set RAF_BIN to the raf executable of a virtualenv with R$F ` +
        'installed (by default ../.venv/bin/raf, created by `uv sync` in the repository root).',
    );
  }
}

/** The caller's environment without R$F settings, with the server's own R$F home. */
function rafEnv(home: string, extra: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.startsWith('RAF_')) env[key] = value;
  }
  return { ...env, RAF_HOME: home, NO_COLOR: '1', ...extra };
}

async function raf(args: string[], env: NodeJS.ProcessEnv): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    execFile(
      rafBin(),
      args,
      { env, timeout: 120_000, maxBuffer: 16 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error)
          reject(new Error(`\`raf ${args.join(' ')}\` failed: ${error.message}\n${stdout}${stderr}`));
        else resolve();
      },
    );
  });
}

async function freePort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const probe = createServer();
    probe.on('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      probe.close(() => resolve(port));
    });
  });
}

/**
 * The process still runs with this R$F home. A PID is reused once its process has exited and been
 * reaped, so it is only signalled while it is still the server (checked on Linux; elsewhere it is
 * enough that the PID exists).
 */
function isServer(pid: number, home: string): boolean {
  try {
    process.kill(pid, 0);
  } catch {
    return false;
  }
  if (!existsSync('/proc/self/environ')) return true;
  try {
    return readFileSync(`/proc/${pid}/environ`, 'utf8').split('\0').includes(`RAF_HOME=${home}`);
  } catch {
    return false;
  }
}

/** SIGTERM (uvicorn shuts down gracefully), SIGKILL after 10 s. */
async function stopProcess(pid: number, home: string): Promise<void> {
  if (!isServer(pid, home)) return;
  process.kill(pid, 'SIGTERM');
  const deadline = Date.now() + 10_000;
  while (isServer(pid, home) && Date.now() < deadline) await delay(100);
  if (isServer(pid, home)) process.kill(pid, 'SIGKILL');
}

/**
 * Stops every server under `root` by the PID recorded in its directory: the shared server, and any
 * server a test worker did not get to stop (a crashed worker). Then removes `root`.
 */
export async function stopServersUnder(root: string): Promise<void> {
  if (!existsSync(root)) return;
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const dir = path.join(root, entry.name);
    const pidFile = path.join(dir, PID_FILE);
    if (!entry.isDirectory() || !existsSync(pidFile)) continue;
    const pid = Number(readFileSync(pidFile, 'utf8'));
    if (Number.isInteger(pid) && pid > 0) await stopProcess(pid, path.join(dir, 'home'));
  }
  rmSync(root, { recursive: true, force: true });
}

function tail(file: string, lines = 40): string {
  return existsSync(file) ? readFileSync(file, 'utf8').split('\n').slice(-lines).join('\n') : '';
}

/**
 * The application `raf serve` runs, with the bearer-token middleware that `raf serve` adds on a
 * non-loopback address, bound to loopback like `raf tui` does: `raf serve` never asks for a token on
 * 127.0.0.1, and the suite never listens on another address.
 */
const TOKEN_APP = [
  'import os, sys',
  'import uvicorn',
  'from raf.apps.api.app import create_app',
  'app = create_app(host="127.0.0.1", token=os.environ["RAF_API_TOKEN"])',
  'uvicorn.run(app, host="127.0.0.1", port=int(sys.argv[1]), log_level="warning")',
].join('\n');

async function getJson(url: string, token?: string): Promise<unknown> {
  const response = await fetch(url, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    signal: AbortSignal.timeout(5_000),
  });
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return await response.json();
}

/** The server on `baseURL` is this one: it is healthy and its workspaces live in `home`. */
async function servesHome(baseURL: string, home: string, token?: string): Promise<boolean> {
  try {
    await getJson(`${baseURL}/api/v1/health`);
    const workspaces = (await getJson(`${baseURL}/api/v1/workspaces`, token)) as {
      items?: Array<{ path?: string }>;
    };
    return (workspaces.items ?? []).some((item) => item.path?.startsWith(home + path.sep) ?? false);
  } catch {
    return false;
  }
}

/** It serves this checkout's build (`raf serve` finds `web/dist` next to the sources it runs). */
async function checkUi(server: RafServer): Promise<void> {
  const served = await (await fetch(`${server.baseURL}/`, { signal: AbortSignal.timeout(5_000) })).text();
  if (served !== readFileSync(DIST_INDEX, 'utf8')) {
    await stopServer(server);
    throw new Error(
      `The R$F server does not serve ${DIST_INDEX}: ${rafBin()} runs the sources of another checkout. ` +
        'Point PYTHONPATH at the src/ directory of this checkout, or RAF_BIN at its virtualenv.',
    );
  }
}

/** Starts a server with a fresh demo workspace, in a new directory under `parent`. */
export async function startServer({
  parent,
  name,
  token,
}: {
  parent: string;
  name: string;
  /** Require this bearer token for every API request except the health route (see TOKEN_APP). */
  token?: string;
}): Promise<RafServer> {
  const dir = mkdtempSync(path.join(parent, `${name}-`));
  const home = path.join(dir, 'home');
  const env = rafEnv(home, token ? { RAF_API_TOKEN: token } : {});
  await raf(['demo', 'load', '--yes'], env);

  // A free port can be taken between the probe and the bind: then try another one.
  for (let attempt = 1; ; attempt += 1) {
    const port = await freePort();
    const baseURL = `http://127.0.0.1:${port}`;
    const log = path.join(dir, `server-${attempt}.log`);
    const out = openSync(log, 'a');
    const child = token
      ? spawn(pythonBin(), ['-c', TOKEN_APP, String(port)], { env, stdio: ['ignore', out, out] })
      : spawn(rafBin(), ['serve', '--host', '127.0.0.1', '--port', String(port)], {
          env,
          stdio: ['ignore', out, out],
        });
    closeSync(out);
    const failed = new Promise<Error>((resolve) => child.once('error', resolve));
    if (child.pid === undefined) throw await failed;
    child.unref();
    const server: RafServer = { baseURL, dir, home, pid: child.pid, token };
    writeFileSync(path.join(dir, PID_FILE), String(child.pid));

    const deadline = Date.now() + START_TIMEOUT_MS;
    while (child.exitCode === null && child.signalCode === null && Date.now() < deadline) {
      if (await servesHome(baseURL, home, token)) {
        await checkUi(server);
        return server;
      }
      await delay(100);
    }
    await stopProcess(child.pid, home);
    const output = tail(log);
    const exited = child.exitCode ?? child.signalCode;
    if (exited !== null && attempt < 3 && /address already in use|errno 98/i.test(output)) continue;
    rmSync(dir, { recursive: true, force: true });
    throw new Error(
      exited !== null
        ? `The R$F server exited (${exited}) before it answered on ${baseURL}:\n${output}`
        : `The R$F server did not answer on ${baseURL} within ${START_TIMEOUT_MS / 1000} s:\n${output}`,
    );
  }
}

/** Stops a server and removes its directory. */
export async function stopServer(server: RafServer): Promise<void> {
  await stopProcess(server.pid, server.home);
  rmSync(server.dir, { recursive: true, force: true });
}
