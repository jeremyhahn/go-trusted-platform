import { spawn } from 'child_process';
import fs from 'fs';
import https from 'https';
import os from 'os';
import path from 'path';
import { generateAttestationCA, loadAttestation, type AttestationMaterial } from './fixtures/soft-authenticator';
import { pickPorts, renderConfig } from './ports';

/**
 * Real-server Playwright global setup (#2034, epic #1665).
 *
 * Starts the platform daemon `make build WITH_WEB=1` produced (bin/platformd,
 * the console embedded) in a fresh temporary directory, on the in-process TPM
 * simulator and the embedded in-memory quicbaas that platformd.test.yaml
 * configures, and waits until /health/ready answers 200. global-teardown.ts
 * stops it and removes the directory.
 *
 * If the daemon exits or never becomes ready, setup throws with the tail of
 * its log: the suite must fail on a server that does not start, never fall
 * back to mocks.
 */

export const DEFAULT_PORT = 18443;

/** The TLS port the test daemon listens on; E2E_PORT overrides it. */
export function e2ePort(): number {
  const raw = process.env.E2E_PORT;
  const port = raw ? Number(raw) : DEFAULT_PORT;
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`E2E_PORT=${raw} is not a TCP port`);
  }
  return port;
}

/** Where setup records the daemon's pid and directory for teardown. */
export function stateFile(port: number): string {
  return path.join(os.tmpdir(), `platformd-e2e-${port}.json`);
}

export interface ServerState {
  pid: number;
  dir: string;
  log: string;
}

/** Where setup generates the WebAuthn attestation CA in a run directory. */
export function attestationDir(runDir: string): string {
  return path.join(runDir, 'webauthn-attestation');
}

/**
 * The attestation material of the daemon setup started on port, for a
 * test's SoftAuthenticator.
 */
export function runAttestation(port: number = e2ePort()): AttestationMaterial {
  const file = stateFile(port);
  if (!fs.existsSync(file)) {
    throw new Error(`[real-server] ${file} is missing: global-setup did not start platformd`);
  }
  const state = JSON.parse(fs.readFileSync(file, 'utf8')) as ServerState;
  return loadAttestation(attestationDir(state.dir));
}

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const READY_TIMEOUT_MS = Number(process.env.E2E_READY_TIMEOUT_MS || 240_000);

function probe(url: string): Promise<number> {
  return new Promise((resolve) => {
    const req = https.get(url, { rejectUnauthorized: false }, (res) => {
      res.resume();
      resolve(res.statusCode ?? 0);
    });
    req.on('error', () => resolve(0));
    req.setTimeout(5_000, () => {
      req.destroy();
      resolve(0);
    });
  });
}

function tail(file: string, lines = 40): string {
  try {
    return fs.readFileSync(file, 'utf8').split('\n').slice(-lines).join('\n');
  } catch {
    return '(no log)';
  }
}

async function globalSetup(): Promise<void> {
  const port = e2ePort();
  const binary = process.env.PLATFORMD_BIN || path.join(REPO_ROOT, 'bin', 'platformd');
  if (!fs.existsSync(binary)) {
    throw new Error(`[real-server] ${binary} is missing: run \`make web-e2e\` (it builds with WITH_WEB=1)`);
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'platformd-e2e-'));
  for (const sub of ['trusted-data/etc', 'trusted-data/log', 'trusted-data/quicbaas/wal', 'trusted-data/www']) {
    fs.mkdirSync(path.join(dir, sub), { recursive: true });
  }
  // The WebAuthn attestation CA platformd.test.yaml names as
  // quicbaas.webauthn-attestation-roots-file (relative to dir).
  generateAttestationCA(attestationDir(dir));
  const template = fs.readFileSync(path.join(__dirname, 'platformd.test.yaml'), 'utf8');
  // The public port from E2E_PORT and an internal port of its own, so the
  // two TLS listeners never bind one address.
  fs.writeFileSync(path.join(dir, 'config.yaml'), renderConfig(template, pickPorts(port)));

  const log = path.join(dir, 'platformd.log');
  const out = fs.openSync(log, 'a');
  // `serve` explicitly: --socket-path is a serve flag. The socket lives in
  // the run directory, never the daemon default under /run (#2034). gRPC
  // off: the console uses REST only, and gRPC TCP over the embedded
  // quicbaas refuses to start without platform tokens or mTLS.
  const socket = path.join(dir, 'platformd.sock');
  const args = ['serve', '--config', 'config.yaml', '--init', '--socket-path', socket, '--enable-grpc=false'];
  const child = spawn(binary, args, {
    cwd: dir,
    detached: true,
    stdio: ['ignore', out, out],
  });
  fs.closeSync(out);
  child.unref();
  if (!child.pid) {
    throw new Error(`[real-server] could not spawn ${binary}`);
  }
  // An object, not a let: the exit handler writes it from a callback.
  const status: { exited: number | null } = { exited: null };
  child.on('exit', (code, sig) => {
    status.exited = code ?? (sig ? 128 : -1);
  });

  const state: ServerState = { pid: child.pid, dir, log };
  fs.writeFileSync(stateFile(port), JSON.stringify(state));
  console.log(`[real-server] platformd pid ${child.pid} in ${dir}, waiting for /health/ready on ${port}`);

  const ready = `https://localhost:${port}/health/ready`;
  const deadline = Date.now() + READY_TIMEOUT_MS;
  let failure: string;
  for (;;) {
    if (status.exited !== null) {
      failure = `platformd exited with ${status.exited} before ready`;
      break;
    }
    if ((await probe(ready)) === 200) {
      console.log('[real-server] platformd ready');
      return;
    }
    if (Date.now() >= deadline) {
      failure = `${ready} not 200 after ${READY_TIMEOUT_MS} ms`;
      break;
    }
    await new Promise((r) => setTimeout(r, 1_000));
  }
  const logTail = tail(log);
  await stopServer(port, { keepDir: true });
  throw new Error(`[real-server] ${failure}; log ${log}, tail:\n${logTail}`);
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Stops the daemon setup started on port: SIGTERM to its process group, then
 * SIGKILL after 15 s, and removes its directory unless keepDir (a failed start
 * keeps it so the log can be read).
 */
export async function stopServer(port: number, opts: { keepDir?: boolean } = {}): Promise<void> {
  const file = stateFile(port);
  if (!fs.existsSync(file)) {
    return;
  }
  const state = JSON.parse(fs.readFileSync(file, 'utf8')) as ServerState;
  const signal = (sig: NodeJS.Signals) => {
    try {
      process.kill(-state.pid, sig);
    } catch {
      try {
        process.kill(state.pid, sig);
      } catch {
        // already gone
      }
    }
  };
  signal('SIGTERM');
  const deadline = Date.now() + 15_000;
  while (alive(state.pid) && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 250));
  }
  if (alive(state.pid)) {
    signal('SIGKILL');
  }
  fs.rmSync(file, { force: true });
  if (!opts.keepDir && !process.env.E2E_KEEP_DATA) {
    fs.rmSync(state.dir, { recursive: true, force: true });
  } else {
    console.log(`[real-server] kept ${state.dir}`);
  }
}

export default globalSetup;
