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
 * configures, with the in-memory gateway datapath (bin/e2e-datapath) on the
 * run's sdn.gateway.datapath-socket, and waits until /health/ready answers 200. global-teardown.ts
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
  /** The in-memory gateway datapath's pid; absent in an older state file. */
  datapathPid?: number;
}

/** The placeholder platformd.test.yaml carries for the datapath socket. */
export const DATAPATH_SOCKET_PLACEHOLDER = '__E2E_DATAPATH_SOCKET__';
const DATAPATH_READY_TIMEOUT_MS = 10_000;

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
  // The in-memory gateway datapath (test/e2e/datapath) on the run
  // directory's socket: platformd reaches its load balancer, NAT64 and perf
  // verbs through sdn.gateway.datapath-socket, so AddVIP has a backend.
  const datapathSocket = path.join(dir, 'dp.sock');
  const datapathPid = await startDatapath(dir, datapathSocket);
  const template = fs.readFileSync(path.join(__dirname, 'platformd.test.yaml'), 'utf8');
  if (!template.includes(DATAPATH_SOCKET_PLACEHOLDER)) {
    stopPid(datapathPid);
    throw new Error(`[real-server] platformd.test.yaml has no ${DATAPATH_SOCKET_PLACEHOLDER}`);
  }
  // The public port from E2E_PORT and an internal port of its own, so the
  // two TLS listeners never bind one address.
  const rendered = renderConfig(template, pickPorts(port)).split(DATAPATH_SOCKET_PLACEHOLDER).join(datapathSocket);
  fs.writeFileSync(path.join(dir, 'config.yaml'), rendered);

  const log = path.join(dir, 'platformd.log');
  const out = fs.openSync(log, 'a');
  // `serve` explicitly: --socket-path is a serve flag. The socket lives in
  // the run directory, never the daemon default under /run (#2034). gRPC
  // and QUIC off: the console uses REST only, and both gRPC TCP and QUIC
  // over the embedded quicbaas refuse to start without platform tokens or
  // mTLS (the IAM policy enforcement point is not implemented there).
  const socket = path.join(dir, 'platformd.sock');
  const args = ['serve', '--config', 'config.yaml', '--init', '--socket-path', socket, '--enable-grpc=false', '--enable-quic=false'];
  const child = spawn(binary, args, {
    cwd: dir,
    detached: true,
    stdio: ['ignore', out, out],
  });
  fs.closeSync(out);
  child.unref();
  if (!child.pid) {
    stopPid(datapathPid);
    throw new Error(`[real-server] could not spawn ${binary}`);
  }
  // An object, not a let: the exit handler writes it from a callback.
  const status: { exited: number | null } = { exited: null };
  child.on('exit', (code, sig) => {
    status.exited = code ?? (sig ? 128 : -1);
  });

  const state: ServerState = { pid: child.pid, dir, log, datapathPid };
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

/**
 * Starts the in-memory gateway datapath (E2E_DATAPATH_BIN, else
 * bin/e2e-datapath, which `make web-e2e-platformd` builds) on socket and waits
 * until the socket exists. Throws with its log tail if it is missing, exits or
 * never listens.
 */
async function startDatapath(dir: string, socket: string): Promise<number> {
  const binary = process.env.E2E_DATAPATH_BIN || path.join(REPO_ROOT, 'bin', 'e2e-datapath');
  if (!fs.existsSync(binary)) {
    throw new Error(`[real-server] ${binary} is missing: run \`make web-e2e\` (web-e2e-platformd builds it)`);
  }
  const log = path.join(dir, 'datapath.log');
  const out = fs.openSync(log, 'a');
  const child = spawn(binary, ['-socket', socket], {
    cwd: dir,
    detached: true,
    stdio: ['ignore', out, out],
  });
  fs.closeSync(out);
  child.unref();
  if (!child.pid) {
    throw new Error(`[real-server] could not spawn ${binary}`);
  }
  const pid = child.pid;
  const status: { exited: number | null } = { exited: null };
  child.on('exit', (code, sig) => {
    status.exited = code ?? (sig ? 128 : -1);
  });
  const deadline = Date.now() + DATAPATH_READY_TIMEOUT_MS;
  while (!fs.existsSync(socket)) {
    if (status.exited !== null || Date.now() >= deadline) {
      stopPid(pid);
      const why = status.exited !== null ? `exited with ${status.exited}` : `no ${socket} after ${DATAPATH_READY_TIMEOUT_MS} ms`;
      throw new Error(`[real-server] e2e datapath ${why}; log ${log}, tail:\n${tail(log)}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  console.log(`[real-server] e2e datapath pid ${pid} on ${socket}`);
  return pid;
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Sends sig to pid's process group, else to pid alone. */
function signalPid(pid: number, sig: NodeJS.Signals): void {
  try {
    process.kill(-pid, sig);
  } catch {
    try {
      process.kill(pid, sig);
    } catch {
      // already gone
    }
  }
}

/** SIGTERM to pid without waiting, for a setup that fails before the state file. */
function stopPid(pid: number): void {
  signalPid(pid, 'SIGTERM');
}

/** SIGTERM to pid's process group, then SIGKILL after 15 s. */
async function stopProcess(pid: number): Promise<void> {
  signalPid(pid, 'SIGTERM');
  const deadline = Date.now() + 15_000;
  while (alive(pid) && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 250));
  }
  if (alive(pid)) {
    signalPid(pid, 'SIGKILL');
  }
}

/**
 * Stops the daemon setup started on port, then its in-memory datapath: SIGTERM
 * to each process group, then SIGKILL after 15 s, and removes its directory unless keepDir (a failed start
 * keeps it so the log can be read).
 */
export async function stopServer(port: number, opts: { keepDir?: boolean } = {}): Promise<void> {
  const file = stateFile(port);
  if (!fs.existsSync(file)) {
    return;
  }
  const state = JSON.parse(fs.readFileSync(file, 'utf8')) as ServerState;
  await stopProcess(state.pid);
  if (state.datapathPid) {
    await stopProcess(state.datapathPid);
  }
  fs.rmSync(file, { force: true });
  if (!opts.keepDir && !process.env.E2E_KEEP_DATA) {
    fs.rmSync(state.dir, { recursive: true, force: true });
  } else {
    console.log(`[real-server] kept ${state.dir}`);
  }
}

export default globalSetup;
