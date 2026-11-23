import { createHash } from 'crypto';
import { Page, Route, Request } from '@playwright/test';

/**
 * API Mock Fixture for E2E Tests
 *
 * Provides utilities for mocking backend API responses using Playwright's
 * page.route() functionality. Enables testing UI interactions without
 * requiring a real backend.
 */

// Types matching the backend API responses

export interface TenantInfo {
  id: string;
  name: string;
  display_name?: string;
  state: 'created' | 'active' | 'suspended' | 'deleted';
  member_count: number;
  created_at: string;
  updated_at: string;
}

export interface ApiError {
  error: string;
  errorCode?: string;
  status: number;
  /**
   * Machine-readable discriminator the platform emits alongside the
   * prose (e.g. `SERVICE_NOT_CONFIGURED` from the REST service
   * registry). Mirrors `reason` in the real error envelope.
   */
  reason?: string;
  /** Platform service the envelope names, when it names one. */
  service?: string;
}

/**
 * Builds the JSON body the platform's REST layer answers for an error,
 * including the machine-readable `reason`/`service` discriminator pair
 * when the fixture supplies one.
 *
 * Every mocked error route must go through this: a body that drops
 * `reason` silently turns a "service not configured on this node"
 * fixture into a plain error, so a page keying off the discriminator
 * would be tested against a contract the mock never emits.
 */
export function errorEnvelope(err: ApiError): string {
  const body: Record<string, unknown> = {
    message: err.error,
    code: err.errorCode || `HTTP_${err.status}`,
  };
  if (err.reason !== undefined) {
    body.reason = err.reason;
  }
  if (err.service !== undefined) {
    body.service = err.service;
  }
  return JSON.stringify(body);
}

// Mock data generators

/**
 * Generate a mock tenant info object.
 */
export function createMockTenantInfo(
  overrides: Partial<TenantInfo> = {}
): TenantInfo {
  const now = new Date();

  return {
    id: 'tenant-abc-123',
    name: 'Test Workspace',
    display_name: 'Test Workspace',
    state: 'active',
    member_count: 5,
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
    ...overrides,
  };
}

// API Mock configuration

export interface TenantApiMockConfig {
  tenantInfo?: TenantInfo;
  fetchError?: ApiError | null;
}

// State management for mocked APIs

/**
 * Mock the tenant API endpoints.
 *
 * Handles:
 * - GET /api/v1/tenant - Get tenant information
 *
 * @param page - Playwright page object
 * @param config - Mock configuration options
 * @returns Object with methods to interact with the mock state
 */
export async function mockTenantApi(
  page: Page,
  config: TenantApiMockConfig = {}
): Promise<{
  getTenantInfo: () => TenantInfo;
  setTenantInfo: (info: Partial<TenantInfo>) => void;
  setError: (error: ApiError | null) => void;
}> {
  let tenantInfo = config.tenantInfo || createMockTenantInfo();
  let fetchError = config.fetchError || null;

  // Match both /tenant and /tenant/ (trailing slash due to Next.js config)
  await page.route('**/api/v1/tenant*', async (route: Route, request: Request) => {
    const method = request.method();

    if (method === 'GET') {
      if (fetchError) {
        await route.fulfill({
          status: fetchError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: fetchError.error,
            code: fetchError.errorCode || `HTTP_${fetchError.status}`,
          }),
        });
        return;
      }

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(tenantInfo),
      });
      return;
    }

    await route.continue();
  });

  return {
    getTenantInfo: () => ({ ...tenantInfo }),
    setTenantInfo: (info: Partial<TenantInfo>) => {
      tenantInfo = { ...tenantInfo, ...info };
    },
    setError: (error: ApiError | null) => {
      fetchError = error;
    },
  };
}

// ============================================================================
// VM operations API (#1727)
// ============================================================================

/** One compute API call the VM operations mock answered. */
export interface VMOperationCall {
  method: string;
  path: string;
  body: unknown;
}

/** Initial state of the VM operations mock. */
export interface VMOperationsMockConfig {
  vmId?: string;
  vmName?: string;
  state?: string;
}

/**
 * Mock the compute VM operations: GetVM, SuspendVM, ResumeVM, AttestVM,
 * GetVMMetrics, Attach/Detach/ResizeDisk, Create/GetSnapshot, MigrateVM,
 * PrepareMigration and FinalizeMigration. Every answered call is recorded.
 */
export async function mockVMOperationsApi(
  page: Page,
  config: VMOperationsMockConfig = {}
): Promise<{ calls: () => VMOperationCall[]; state: () => string }> {
  const vmId = config.vmId ?? 'vm-ops-1';
  let state = config.state ?? 'VM_STATE_RUNNING';
  const calls: VMOperationCall[] = [];
  const now = new Date().toISOString();
  const ok = (message: string) => ({ status: { success: true, message } });

  // The real GetVM shape (instanceToVMProto): config carries the name, and
  // there are no metrics, no snapshots and no flattened fields.
  const vm = () => ({
    id: vmId,
    config: {
      name: config.vmName ?? 'ops-vm',
      cpu: { cores: 2 },
      memory: { sizeMb: 2048 },
      disks: [],
      networks: [],
    },
    state,
    createdAt: now,
    updatedAt: now,
  });

  const snapshot = (id: string, name: string) => ({
    id,
    vmId,
    config: { name },
    createdAt: now,
    sizeBytes: 4096,
    vmState: state,
  });

  await page.route('**/api/v1/compute/**', async (route: Route, request: Request) => {
    const method = request.method();
    const path = new URL(request.url()).pathname.replace(/^.*\/api\/v1\/compute/, '');
    let body: unknown = null;
    try {
      body = request.postDataJSON();
    } catch {
      body = null;
    }
    const json = async (status: number, data: unknown) => {
      calls.push({ method, path, body });
      await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
    };
    const vmBase = `/vms/${vmId}`;

    if (method === 'GET' && path === vmBase) return json(200, { vm: vm() });
    if (method === 'GET' && path === '/vms') {
      return json(200, { vms: [vm()], pagination: { page: 1, pageSize: 100, totalPages: 1, totalItems: 1 } });
    }
    if (method === 'POST' && path === `${vmBase}/suspend`) {
      state = 'VM_STATE_PAUSED';
      return json(200, ok('VM suspended'));
    }
    if (method === 'POST' && path === `${vmBase}/resume`) {
      state = 'VM_STATE_RUNNING';
      return json(200, ok('VM resumed'));
    }
    if (method === 'POST' && path === `${vmBase}/attest`) {
      return json(200, {
        ...ok('Attestation collected'),
        quote: 'cXVvdGU=',
        signature: 'c2ln',
        pcrValues: [{ index: 0, value: 'AA==' }, { index: 7, value: 'AQ==' }],
        signatureAlgorithm: 'SHA256-RSAPSS',
      });
    }
    if (method === 'GET' && path === `${vmBase}/metrics`) {
      return json(200, {
        metrics: {
          cpuUsagePercent: 42,
          memoryUsedMb: 1536,
          memoryAvailableMb: 512,
          diskReadBytes: 1,
          diskWriteBytes: 2,
          networkRxBytes: 3,
          networkTxBytes: 4,
          uptimeSeconds: 3600,
        },
      });
    }
    if (method === 'POST' && path === `${vmBase}/disks`) return json(200, ok('Disk attached'));
    if (method === 'DELETE' && path.startsWith(`${vmBase}/disks/`)) return json(200, ok('Disk detached'));
    if (method === 'PATCH' && path.startsWith(`${vmBase}/disks/`)) return json(200, ok('Disk resized'));
    if (method === 'POST' && path === `${vmBase}/snapshots`) {
      const name = (body as { config?: { name?: string } } | null)?.config?.name ?? 'snap';
      return json(201, { ...ok('Snapshot created'), snapshot: snapshot('snap-new', name) });
    }
    if (method === 'GET' && path === `${vmBase}/snapshots`) return json(200, { snapshots: [] });
    if (method === 'GET' && path.startsWith(`${vmBase}/snapshots/`)) {
      const id = path.slice(`${vmBase}/snapshots/`.length);
      return json(200, { snapshot: snapshot(id, `stored-${id}`) });
    }
    if (method === 'POST' && path === `${vmBase}/migrate`) return json(200, ok('Migration started'));
    if (method === 'POST' && path === '/migrations/prepare') {
      const spec = (body as { spec?: unknown } | null)?.spec as { memoryMb?: unknown; cpus?: unknown } | undefined;
      const positive = (n: unknown) => typeof n === 'number' && Number.isInteger(n) && n > 0;
      if (!spec || typeof spec !== 'object' || !positive(spec.memoryMb) || !positive(spec.cpus)) {
        return json(400, { message: 'migration spec is required', code: 'INVALID_ARGUMENT' });
      }
      return json(200, { ...ok('Receiver ready'), receiverId: 'rx-42', port: 49152, tlsHostname: 'rx-42-tls' });
    }
    if (method === 'POST' && /^\/migrations\/[^/]+\/finalize$/.test(path)) {
      return json(200, ok('Migration finalized'));
    }
    return json(404, { message: 'not mocked', code: 'HTTP_404' });
  });

  return { calls: () => [...calls], state: () => state };
}

/**
 * BMC API mock (#1736): the `/api/v1/bmc/{profileID}/...` routes with the
 * platform envelope. Mutations change the state the next read returns, and
 * every mutating request is recorded in order. A non-numeric profile ID is
 * answered 404 and not recorded, as the server routes (`{profileID:[0-9]+}`)
 * do.
 */
export interface BmcApiMockState {
  power: { state: string };
  bootDevice: { device: string; persistent?: boolean };
  virtualMedia: { mounted: boolean; image_url?: string; media_type?: string };
  sensors: Array<{ name: string; value: number; units: string; status: string }>;
  systemInfo: {
    manufacturer: string;
    product: string;
    serial_number: string;
    firmware_version: string;
    bios_version: string;
    power_state: string;
  };
  provision: {
    provision_id: string;
    profile_id: string;
    status: string;
    message?: string;
    started_at: string;
    updated_at: string;
  };
  certificate: {
    subject: string;
    issuer: string;
    serial_number: string;
    not_before: string;
    not_after: string;
    days_remaining: number;
    subject_alternative_names?: string[];
    fingerprint: string;
  };
}

export interface BmcApiMockRequest {
  method: string;
  op: string;
  body: unknown;
}

export interface BmcApiMockConfig {
  state?: Partial<BmcApiMockState>;
  /** Answers every request to this op with the error */
  errors?: Record<string, ApiError>;
}

export async function mockBmcApi(
  page: Page,
  config: BmcApiMockConfig = {}
): Promise<{ state: BmcApiMockState; requests: BmcApiMockRequest[] }> {
  // The shapes are the server's JSON types (pkg/webservice/v1/bmc/types.go,
  // pkg/bmc/types.go, pkg/provisioning/baremetal); the mock rejects the
  // requests the handlers reject.
  const state: BmcApiMockState = {
    power: { state: 'On' },
    bootDevice: { device: 'disk', persistent: true },
    virtualMedia: { mounted: false },
    sensors: [
      { name: 'CPU1 Temp', value: 54, units: 'C', status: 'OK' },
      { name: 'Fan1', value: 7200, units: 'RPM', status: 'OK' },
    ],
    systemInfo: {
      manufacturer: 'Dell Inc.',
      product: 'PowerEdge R640',
      serial_number: 'SN-R640-01',
      firmware_version: '7.00.00',
      bios_version: '2.19.1',
      power_state: 'On',
    },
    provision: {
      provision_id: 'prov-0',
      profile_id: '1',
      status: 'complete',
      started_at: '2026-11-01T00:00:00Z',
      updated_at: '2026-11-01T00:40:00Z',
    },
    certificate: {
      subject: 'CN=bmc-1',
      issuer: 'CN=Platform Intermediate CA',
      serial_number: '1736',
      not_before: '2026-11-12T00:00:00Z',
      not_after: '2027-11-12T00:00:00Z',
      days_remaining: 365,
      fingerprint: 'SHA256:5B:9D:3F:2E',
    },
    ...config.state,
  };
  const requests: BmcApiMockRequest[] = [];
  const bootDevices = ['none', 'pxe', 'disk', 'cdrom', 'virtual_media'];

  const ok = (payload: unknown, status = 200) => ({
    status,
    contentType: 'application/json',
    body: JSON.stringify({ code: status, success: true, payload }),
  });
  const badRequest = (error: string) => ({
    status: 400,
    contentType: 'application/json',
    body: errorEnvelope({ status: 400, error }),
  });

  await page.route('**/api/v1/bmc/*/*', async (route: Route, request: Request) => {
    const segments = new URL(request.url()).pathname.split('/').filter(Boolean);
    const op = segments[segments.length - 1];
    const profileID = decodeURIComponent(segments[segments.length - 2] ?? '');
    const method = request.method();
    // The server routes take {profileID:[0-9]+} and parse it as uint64, so a non-numeric ID matches no route.
    if (!/^[0-9]+$/.test(profileID)) {
      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: errorEnvelope({ status: 404, error: `no route ${method} bmc/${profileID}/${op}` }),
      });
      return;
    }
    const error = config.errors?.[op];
    if (error) {
      await route.fulfill({ status: error.status, contentType: 'application/json', body: errorEnvelope(error) });
      return;
    }
    const body = request.postData() ? request.postDataJSON() : null;
    if (method !== 'GET') {
      requests.push({ method, op, body });
    }
    switch (`${method} ${op}`) {
      case 'GET power':
        await route.fulfill(ok(state.power));
        return;
      case 'GET boot-device':
        await route.fulfill(ok({ device: state.bootDevice.device }));
        return;
      case 'POST boot-device': {
        const req = (body ?? {}) as { device?: string; persistent?: boolean };
        if (!req.device || !bootDevices.includes(req.device)) {
          await route.fulfill(badRequest(`invalid boot device: ${req.device ?? ''}`));
          return;
        }
        state.bootDevice = { device: req.device, persistent: req.persistent };
        await route.fulfill(ok({ message: 'boot device set' }));
        return;
      }
      case 'GET virtual-media':
        await route.fulfill(ok(state.virtualMedia));
        return;
      case 'POST virtual-media': {
        const isoURL = (body as { iso_url?: unknown } | null)?.iso_url;
        if (typeof isoURL !== 'string' || isoURL === '') {
          await route.fulfill(badRequest('iso_url is required'));
          return;
        }
        state.virtualMedia = { mounted: true, image_url: isoURL };
        await route.fulfill(ok({ message: 'ISO mounted' }));
        return;
      }
      case 'DELETE virtual-media':
        state.virtualMedia = { mounted: false };
        await route.fulfill(ok({ message: 'ISO unmounted' }));
        return;
      case 'GET sensors':
        await route.fulfill(ok(state.sensors));
        return;
      case 'GET system-info':
        await route.fulfill(ok(state.systemInfo));
        return;
      case 'GET provision':
        await route.fulfill(ok(state.provision));
        return;
      case 'POST provision': {
        const now = new Date().toISOString();
        state.provision = {
          provision_id: 'prov-1',
          profile_id: profileID,
          status: 'pending',
          started_at: now,
          updated_at: now,
        };
        await route.fulfill(ok(state.provision, 201));
        return;
      }
      case 'GET cert':
        await route.fulfill(ok(state.certificate));
        return;
      default:
        await route.fulfill({ status: 404, contentType: 'application/json', body: errorEnvelope({ status: 404, error: `no route ${method} ${op}` }) });
    }
  });

  return { state, requests };
}

// ============================================================================
// BMC users and web certificate (#1720)
// ============================================================================

export interface MockBMCUser {
  slot: number;
  username: string;
  enabled: boolean;
  /** IPMI privilege code: 0x01 callback, 0x02 user, 0x03 operator, 0x04 administrator, 0x0f no-access. */
  privilege: number;
  channel: number;
}

export interface BMCApiCall {
  method: string;
  path: string;
  body: unknown;
}

export interface BMCApiMockConfig {
  profileID?: string;
  users?: MockBMCUser[];
  /** When set and not 200, GET /users answers this status with an error envelope. */
  listStatus?: number;
  /** GET /users waits this many milliseconds before answering. */
  listDelayMs?: number;
}

/**
 * mockBMCApi serves /api/v1/bmc/{profileID}/users... and /cert from an
 * in-memory user table and records every call, so a spec can assert the
 * verb, path and body the page sent.
 */
export async function mockBMCApi(
  page: Page,
  config: BMCApiMockConfig = {}
): Promise<{ calls: BMCApiCall[]; users: () => MockBMCUser[] }> {
  const profileID = config.profileID ?? '7';
  let users: MockBMCUser[] = (config.users ?? []).map((u) => ({ ...u }));
  const calls: BMCApiCall[] = [];
  const privilegeCodes: Record<string, number> = {
    'no-access': 0x0f,
    callback: 0x01,
    user: 0x02,
    operator: 0x03,
    administrator: 0x04,
  };
  const ok = (route: Route, payload: unknown) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ payload }),
    });

  await page.route(`**/api/v1/bmc/${profileID}/**`, async (route: Route, request: Request) => {
    const method = request.method();
    const path = new URL(request.url()).pathname.replace(/\/$/, '');
    const raw = request.postData();
    const body: unknown = raw ? JSON.parse(raw) : undefined;
    calls.push({ method, path, body });

    const prefix = `/api/v1/bmc/${profileID}`;
    const rest = path.slice(prefix.length);
    const slotMatch = rest.match(/^\/users\/(\d+)(\/(password|privilege))?$/);

    if (rest === '/users' && method === 'GET') {
      if (config.listDelayMs) {
        await new Promise((resolve) => setTimeout(resolve, config.listDelayMs));
      }
      if (config.listStatus !== undefined && config.listStatus !== 200) {
        await route.fulfill({
          status: config.listStatus,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'BMC listing failed' }),
        });
        return;
      }
      await ok(route, users);
      return;
    }
    if (rest === '/users' && method === 'POST') {
      const b = body as { slot: number; username: string; enabled: boolean; privilege: string; channel: number };
      const created: MockBMCUser = {
        slot: b.slot,
        username: b.username,
        enabled: b.enabled,
        privilege: privilegeCodes[b.privilege] ?? 0x02,
        channel: b.channel,
      };
      users = [...users.filter((u) => u.slot !== created.slot), created];
      await ok(route, created);
      return;
    }
    if (rest === '/cert' && method === 'PUT') {
      await ok(route, { status: 'ok' });
      return;
    }
    if (slotMatch) {
      const slot = Number(slotMatch[1]);
      const sub = slotMatch[3];
      if (!sub && method === 'DELETE') {
        users = users.filter((u) => u.slot !== slot);
        await ok(route, { status: 'ok' });
        return;
      }
      if (sub === 'password' && method === 'PUT') {
        await ok(route, { status: 'ok' });
        return;
      }
      if (sub === 'privilege' && method === 'PUT') {
        const b = body as { privilege: string; channel: number };
        users = users.map((u) =>
          u.slot === slot ? { ...u, privilege: privilegeCodes[b.privilege] ?? u.privilege, channel: b.channel } : u
        );
        await ok(route, { status: 'ok' });
        return;
      }
    }
    await route.fulfill({
      status: 404,
      contentType: 'application/json',
      body: JSON.stringify({ message: 'not found' }),
    });
  });

  return { calls, users: () => users.map((u) => ({ ...u })) };
}

/**
 * Calls the container-ops mock recorded, so a test can assert the page
 * sent the request the operation needs.
 */
export interface ContainerOpsCalls {
  getContainer: number;
  getMetrics: number;
  exec: unknown[];
  attest: unknown[];
  vmAttest: unknown[];
  vmVerify: unknown[];
}

export interface ContainerOpsMockConfig {
  containerId?: string;
  containerName?: string;
  vmId?: string;
  vmName?: string;
  /** Base64 stdout the exec mock answers. */
  execStdout?: string;
  execExitCode?: number;
  /** Verified flag the VM verify mock answers. */
  vmVerified?: boolean;
  /**
   * 1-based call number from which the VM verify POST answers 500
   * { error: 'attestation unavailable' }; unset means never.
   */
  vmVerifyFailFrom?: number;
  /**
   * 1-based call number from which the container attest POST answers 500
   * { error: 'attestation unavailable' }; unset means never.
   */
  attestFailFrom?: number;
  /** Exec calls from this 1-based index on answer 500. */
  execFailFrom?: number;
}

/**
 * Mock the container detail operations of #1721 and the VM attest/verify
 * round trip:
 *
 * - GET  /api/v1/compute/containers/:id          - GetContainer
 * - GET  /api/v1/compute/containers/:id/metrics  - GetContainerMetrics
 * - POST /api/v1/compute/containers/:id/exec     - ExecContainer
 * - POST /api/v1/compute/containers/:id/attest   - AttestContainer
 * - GET  /api/v1/compute/vms/:id                 - GetVM (detail page load)
 * - POST /api/v1/compute/vms/:id/attest          - AttestVM
 * - POST /api/v1/compute/vms/:id/attest/verify   - VerifyVMAttestation
 */
export async function mockContainerOpsApi(
  page: Page,
  config: ContainerOpsMockConfig = {}
): Promise<ContainerOpsCalls> {
  const containerId = config.containerId || 'ctr-1';
  const vmId = config.vmId || 'vm-1';
  const now = new Date().toISOString();
  const calls: ContainerOpsCalls = {
    getContainer: 0,
    getMetrics: 0,
    exec: [],
    attest: [],
    vmAttest: [],
    vmVerify: [],
  };
  const json = (route: Route, body: unknown) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  const unavailable = (route: Route) =>
    route.fulfill({
      status: 500,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'attestation unavailable' }),
    });
  const failsAt = (failFrom: number | undefined, call: number) =>
    failFrom !== undefined && call >= failFrom;

  await page.route('**/api/v1/compute/containers/**', async (route: Route, request: Request) => {
    const path = new URL(request.url()).pathname.replace(/\/+$/, '');
    const match = path.match(/\/containers\/([^/]+)(?:\/(\w+))?$/);
    if (!match || decodeURIComponent(match[1]) !== containerId) {
      await route.fallback();
      return;
    }
    const op = match[2];
    const method = request.method();
    if (method === 'GET' && !op) {
      calls.getContainer++;
      await json(route, {
        container: {
          id: containerId,
          config: { name: config.containerName || 'web-frontend', image: 'nginx:1.27' },
          state: 'CONTAINER_STATE_RUNNING',
          createdAt: now,
          startedAt: now,
          hostId: 'host-a',
        },
      });
      return;
    }
    if (method === 'GET' && op === 'metrics') {
      calls.getMetrics++;
      await json(route, {
        metrics: {
          cpuUsagePercent: 12.5,
          memoryUsedMb: 256,
          memoryLimitMb: 512,
          diskReadBytes: 1024,
          diskWriteBytes: 2048,
          networkRxBytes: 4096,
          networkTxBytes: 8192,
          uptimeSeconds: 3600,
        },
      });
      return;
    }
    if (method === 'POST' && op === 'exec') {
      calls.exec.push(request.postDataJSON());
      if (failsAt(config.execFailFrom, calls.exec.length)) {
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'exec unavailable' }),
        });
        return;
      }
      await json(route, {
        status: { success: true },
        exitCode: config.execExitCode ?? 0,
        stdout: config.execStdout ?? Buffer.from('hello from container\n').toString('base64'),
      });
      return;
    }
    if (method === 'POST' && op === 'attest') {
      calls.attest.push(request.postDataJSON());
      if (failsAt(config.attestFailFrom, calls.attest.length)) {
        await unavailable(route);
        return;
      }
      await json(route, {
        status: { success: true },
        quote: 'cXVvdGU=',
        signature: 'c2ln',
        pcrValues: [{ index: 0, value: 'AAAA' }],
        containerId,
        imageDigest: 'aW1hZ2UtZGlnZXN0',
        configDigest: 'Y29uZmlnLWRpZ2VzdA==',
        verified: true,
        timestamp: now,
      });
      return;
    }
    await route.fallback();
  });

  await page.route('**/api/v1/compute/vms/**', async (route: Route, request: Request) => {
    const path = new URL(request.url()).pathname.replace(/\/+$/, '');
    const match = path.match(/\/vms\/([^/]+)((?:\/\w+)*)$/);
    if (!match || decodeURIComponent(match[1]) !== vmId) {
      await route.fallback();
      return;
    }
    const op = match[2];
    const method = request.method();
    if (method === 'GET' && op === '') {
      await json(route, {
        vm: {
          id: vmId,
          config: {
            name: config.vmName || 'build-vm',
            cpu: { cores: 2 },
            memory: { sizeMb: '2048' },
            disks: [],
            networks: [],
          },
          state: 'VM_STATE_RUNNING',
          createdAt: now,
          updatedAt: now,
          metrics: {
            cpuUsagePercent: 10,
            memoryUsedMb: '512',
            memoryAvailableMb: '1536',
            diskReadBytes: '0',
            diskWriteBytes: '0',
            networkRxBytes: '0',
            networkTxBytes: '0',
            uptimeSeconds: 60,
          },
        },
      });
      return;
    }
    if (method === 'POST' && op === '/attest') {
      calls.vmAttest.push(request.postDataJSON());
      await json(route, {
        status: { success: true },
        quote: 'cXVvdGU=',
        signature: 'c2ln',
        signatureAlgorithm: 'SHA256-RSAPSS',
      });
      return;
    }
    if (method === 'POST' && op === '/attest/verify') {
      calls.vmVerify.push(request.postDataJSON());
      if (failsAt(config.vmVerifyFailFrom, calls.vmVerify.length)) {
        await unavailable(route);
        return;
      }
      const verified = config.vmVerified ?? true;
      await json(route, {
        status: { success: true },
        verified,
        message: verified ? 'quote signature and nonce valid' : 'quote signature invalid',
      });
      return;
    }
    await route.fallback();
  });

  return calls;
}
