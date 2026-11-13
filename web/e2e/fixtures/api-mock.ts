import { Page, Route, Request } from '@playwright/test';

/**
 * API Mock Fixture for E2E Tests
 *
 * Provides utilities for mocking backend API responses using Playwright's
 * page.route() functionality. Enables testing UI interactions without
 * requiring a real backend.
 */

// Types matching the backend API responses

export interface Invitation {
  id: string;
  email: string;
  role: string;
  status: 'pending' | 'accepted' | 'expired' | 'revoked';
  token: string;
  expires_at: string;
  created_at: string;
}

export interface InvitationListResponse {
  invitations: Invitation[];
  total: number;
}

export interface TenantInfo {
  id: string;
  name: string;
  display_name?: string;
  state: 'created' | 'active' | 'suspended' | 'deleted';
  member_count: number;
  created_at: string;
  updated_at: string;
}

export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  timestamp: string;
  services?: Record<string, { status: string; latency_ms?: number }>;
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

let invitationIdCounter = 1;

/**
 * Generate a mock invitation object.
 */
export function createMockInvitation(
  overrides: Partial<Invitation> = {}
): Invitation {
  const id = overrides.id || `inv-${invitationIdCounter++}`;
  const now = new Date();
  const expires = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000); // 7 days

  return {
    id,
    email: `user${invitationIdCounter}@example.com`,
    role: 'member',
    status: 'pending',
    token: `token-${id}-${Date.now()}`,
    expires_at: expires.toISOString(),
    created_at: now.toISOString(),
    ...overrides,
  };
}

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

export interface InvitationApiMockConfig {
  initialInvitations?: Invitation[];
  createSuccess?: boolean;
  revokeSuccess?: boolean;
  fetchError?: ApiError | null;
  createError?: ApiError | null;
  revokeError?: ApiError | null;
}

export interface TenantApiMockConfig {
  tenantInfo?: TenantInfo;
  fetchError?: ApiError | null;
}

export interface HealthApiMockConfig {
  status?: 'healthy' | 'degraded' | 'unhealthy';
  version?: string;
  error?: ApiError | null;
}

// State management for mocked APIs

interface InvitationApiState {
  invitations: Invitation[];
  config: InvitationApiMockConfig;
}

/**
 * Mock the invitations API endpoints.
 *
 * Handles:
 * - GET /api/v1/invitations - List invitations
 * - POST /api/v1/invitations - Create invitation
 * - DELETE /api/v1/invitations/:id - Revoke invitation
 *
 * @param page - Playwright page object
 * @param config - Mock configuration options
 * @returns Object with methods to interact with the mock state
 */
export async function mockInvitationApi(
  page: Page,
  config: InvitationApiMockConfig = {}
): Promise<{
  getInvitations: () => Invitation[];
  addInvitation: (invitation: Invitation) => void;
  clearInvitations: () => void;
  setError: (endpoint: 'fetch' | 'create' | 'revoke', error: ApiError | null) => void;
}> {
  const state: InvitationApiState = {
    invitations: config.initialInvitations || [],
    config: {
      createSuccess: true,
      revokeSuccess: true,
      fetchError: null,
      createError: null,
      revokeError: null,
      ...config,
    },
  };

  // Route handler for invitations API
  // Match both /invitations and /invitations/ (trailing slash due to Next.js config)
  await page.route('**/api/v1/invitations*', async (route: Route, request: Request) => {
    const method = request.method();
    const url = request.url();

    // Skip if this is a specific invitation URL (e.g., /invitations/inv-123)
    const invitationIdMatch = url.match(/\/invitations\/([^/?]+)/);
    if (invitationIdMatch) {
      // This is a specific invitation operation, let it fall through to the next handler
      await route.continue();
      return;
    }

    if (method === 'GET') {
      // List invitations
      if (state.config.fetchError) {
        await route.fulfill({
          status: state.config.fetchError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.fetchError.error,
            code: state.config.fetchError.errorCode || `HTTP_${state.config.fetchError.status}`,
          }),
        });
        return;
      }

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          invitations: state.invitations,
          total: state.invitations.length,
        }),
      });
      return;
    }

    if (method === 'POST') {
      // Create invitation
      if (state.config.createError) {
        await route.fulfill({
          status: state.config.createError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.createError.error,
            code: state.config.createError.errorCode || `HTTP_${state.config.createError.status}`,
          }),
        });
        return;
      }

      try {
        const body = request.postDataJSON();
        const newInvitation = createMockInvitation({
          email: body.email,
          role: body.role || 'member',
        });

        state.invitations.unshift(newInvitation);

        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            invitation: newInvitation,
          }),
        });
      } catch {
        await route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Invalid request body', code: 'HTTP_400' }),
        });
      }
      return;
    }

    await route.continue();
  });

  // Route handler for individual invitation (revoke)
  await page.route('**/api/v1/invitations/*', async (route: Route, request: Request) => {
    const method = request.method();
    const url = request.url();

    if (method === 'DELETE') {
      // Revoke invitation
      if (state.config.revokeError) {
        await route.fulfill({
          status: state.config.revokeError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.revokeError.error,
            code: state.config.revokeError.errorCode || `HTTP_${state.config.revokeError.status}`,
          }),
        });
        return;
      }

      // Extract invitation ID from URL
      const match = url.match(/\/invitations\/([^/?]+)/);
      const invitationId = match ? match[1] : null;

      if (invitationId) {
        const index = state.invitations.findIndex((inv) => inv.id === invitationId);
        if (index !== -1) {
          state.invitations.splice(index, 1);
        }
      }

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true }),
      });
      return;
    }

    await route.continue();
  });

  return {
    getInvitations: () => [...state.invitations],
    addInvitation: (invitation: Invitation) => {
      state.invitations.unshift(invitation);
    },
    clearInvitations: () => {
      state.invitations = [];
    },
    setError: (endpoint: 'fetch' | 'create' | 'revoke', error: ApiError | null) => {
      if (endpoint === 'fetch') {
        state.config.fetchError = error;
      } else if (endpoint === 'create') {
        state.config.createError = error;
      } else if (endpoint === 'revoke') {
        state.config.revokeError = error;
      }
    },
  };
}

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
// Admin tenant API mock (#1673): /api/v1/tenants and its sub-routes
// ============================================================================

/** A tenant record as the admin tenant pages read it. */
export interface AdminTenant {
  id: string;
  name: string;
  displayName?: string;
  /** protojson enum names, as the webservice serialises Tenant.state */
  state:
    | 'TENANT_STATE_ACTIVE'
    | 'TENANT_STATE_SUSPENDED'
    | 'TENANT_STATE_PENDING'
    | 'TENANT_STATE_DELETING'
    | 'TENANT_STATE_DELETED';
  computeQuota?: { maxVms?: number; maxContainers?: number; maxVcpus?: number; maxMemoryMb?: number };
  createdAt: string;
  updatedAt: string;
}

/** One request the admin tenant mock answered. */
export interface AdminTenantCall {
  method: string;
  path: string;
  /** The request's query string, e.g. `?limit=100&offset=0`. */
  query: string;
  body: unknown;
}

export function createMockAdminTenant(overrides: Partial<AdminTenant> = {}): AdminTenant {
  return {
    id: 'tenant-1',
    name: 'acme',
    displayName: 'Acme Corp',
    state: 'TENANT_STATE_ACTIVE',
    computeQuota: { maxVms: 10, maxContainers: 5, maxVcpus: 40, maxMemoryMb: 65536 },
    createdAt: '2026-01-01T00:00:00Z',
    updatedAt: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

/**
 * Mock the admin tenant routes with an in-memory tenant store. Every
 * request is recorded in calls, so a test can assert which operation ran.
 */
export async function mockAdminTenantsApi(
  page: Page,
  config: { tenants?: AdminTenant[]; quotaAvailable?: boolean } = {}
): Promise<{ calls: AdminTenantCall[]; tenants: () => AdminTenant[] }> {
  let tenants = [...(config.tenants ?? [createMockAdminTenant()])];
  const calls: AdminTenantCall[] = [];
  let dekVersion = 1;
  const ok = { success: true, message: 'ok' };

  const reply = (route: Route, status: number, payload: unknown) =>
    route.fulfill({
      status,
      contentType: 'application/json',
      body: JSON.stringify({ code: status, error: '', success: status < 400, payload }),
    });
  const notFound = (route: Route) =>
    route.fulfill({
      status: 404,
      contentType: 'application/json',
      body: JSON.stringify({ code: 404, error: 'tenant not found', success: false }),
    });

  await page.route('**/api/v1/tenants**', async (route: Route, request: Request) => {
    const method = request.method();
    const url = new URL(request.url());
    const path = url.pathname.replace(/\/+$/, '');
    let body: unknown;
    try {
      body = request.postDataJSON();
    } catch {
      body = undefined;
    }
    calls.push({ method, path, query: url.search, body });
    const parts = path.replace(/^.*\/api\/v1\/tenants/, '').split('/').filter(Boolean).map(decodeURIComponent);
    const input = (body ?? {}) as Record<string, unknown>;

    if (parts.length === 0) {
      if (method === 'GET') {
        // The server pages the list: limit defaults to 100, offset to 0.
        const limit = Number(url.searchParams.get('limit') ?? '') || 100;
        const offset = Number(url.searchParams.get('offset') ?? '') || 0;
        return reply(route, 200, { tenants: tenants.slice(offset, offset + limit), total: tenants.length });
      }
      if (method === 'POST') {
        const created = createMockAdminTenant({
          id: `tenant-${tenants.length + 1}`,
          name: String(input.name ?? ''),
          displayName: input.displayName as string | undefined,
        });
        tenants = [...tenants, created];
        return reply(route, 201, { status: ok, tenant: created });
      }
    }
    if (parts[0] === 'sync' && method === 'POST') return reply(route, 200, { status: ok });
    if (parts[0] === 'by-name' && parts.length === 2 && method === 'GET') {
      const found = tenants.find((t) => t.name === parts[1]);
      return found ? reply(route, 200, { tenant: found }) : notFound(route);
    }

    const tenant = tenants.find((t) => t.id === parts[0]);
    if (!tenant) return notFound(route);
    const sub = parts.slice(1).join('/');
    const update = (patch: Partial<AdminTenant>) => {
      Object.assign(tenant, patch);
      return tenant;
    };

    switch (`${method} ${sub}`) {
      case 'GET ':
        return reply(route, 200, { tenant });
      case 'PUT ':
      {
        // The server ignores an empty display name and keeps the old one.
        const submitted = input.displayName as string | undefined;
        return reply(route, 200, {
          status: ok,
          tenant: submitted ? update({ displayName: submitted }) : tenant,
        });
      }
      case 'DELETE ':
        tenants = tenants.filter((t) => t.id !== tenant.id);
        return reply(route, 200, { status: ok });
      case 'POST suspend':
        update({ state: 'TENANT_STATE_SUSPENDED' });
        return reply(route, 200, { status: ok });
      case 'POST resume':
        update({ state: 'TENANT_STATE_ACTIVE' });
        return reply(route, 200, { status: ok });
      case 'PUT quotas': {
        // Like TenantGRPCServer.UpdateQuotas: a supplied compute section
        // replaces every limit, so an omitted field becomes zero.
        const c = input.compute as Record<string, unknown> | undefined;
        if (c) {
          const num = (v: unknown) => Number(v ?? 0) || 0;
          update({
            computeQuota: {
              maxVms: num(c.maxVms),
              maxContainers: num(c.maxContainers),
              maxVcpus: num(c.maxVcpus),
              maxMemoryMb: num(c.maxMemoryMb),
            },
          });
        }
        return reply(route, 200, { status: ok });
      }
      case 'POST quota-check':
        return reply(route, 200, {
          tenantId: tenant.id,
          resource: input.resource,
          amount: input.amount,
          available: config.quotaAvailable ?? true,
        });
      case 'GET dek':
        return reply(route, 200, {
          dekStatus: {
            tenantId: tenant.id,
            path: `tenants/${tenant.id}/dek`,
            version: dekVersion,
            algorithm: 'AES-256-GCM',
            status: 'ACTIVE',
            isDefault: true,
            createdAt: tenant.createdAt,
            usageCount: 10,
            bytesUsed: 1024,
            maxUsageCount: 1000,
            maxBytesUsed: 1048576,
            warningPercent: 80,
            usagePercent: 1,
            needsRotation: false,
          },
        });
      case 'POST dek/rotate':
        dekVersion += 1;
        return reply(route, 200, {
          tenantId: tenant.id,
          oldVersion: dekVersion - 1,
          newVersion: dekVersion,
          timestamp: '2026-01-02T00:00:00Z',
        });
      case 'POST barrier/init':
        // TenantGRPCServer.InitTenantBarrier refuses any Shamir setting.
        if (Number(input.threshold ?? 0) !== 0 || Number(input.shares ?? 0) !== 0) {
          return route.fulfill({
            status: 400,
            contentType: 'application/json',
            body: JSON.stringify({
              code: 400,
              error: 'tenant barrier: Shamir threshold/shares are not supported',
              success: false,
            }),
          });
        }
        return reply(route, 200, { status: ok });
      case 'POST barrier/unseal':
      case 'POST barrier/seal':
        return reply(route, 200, { status: ok });
      default:
        return route.continue();
    }
  });

  return { calls, tenants: () => [...tenants] };
}

/**
 * Mock the health API endpoint.
 *
 * Handles:
 * - GET /api/v1/health - Health check
 *
 * @param page - Playwright page object
 * @param config - Mock configuration options
 */
export async function mockHealthApi(
  page: Page,
  config: HealthApiMockConfig = {}
): Promise<void> {
  const status = config.status || 'healthy';
  const version = config.version || '1.0.0';

  // Match both /health and /health/ (trailing slash due to Next.js config)
  await page.route('**/api/v1/health*', async (route: Route, request: Request) => {
    if (request.method() === 'GET') {
      if (config.error) {
        await route.fulfill({
          status: config.error.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: config.error.error,
            code: config.error.errorCode || `HTTP_${config.error.status}`,
          }),
        });
        return;
      }

      const response: HealthResponse = {
        status,
        version,
        timestamp: new Date().toISOString(),
        services: {
          database: { status: 'healthy', latency_ms: 5 },
          cache: { status: 'healthy', latency_ms: 1 },
          tpm: { status: 'healthy', latency_ms: 10 },
        },
      };

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response),
      });
      return;
    }

    await route.continue();
  });
}

// ============================================================================
// Container registry (#1723)
// ============================================================================

export interface RegistryApiMockConfig {
  /** Repository name to its tags. Deleting a tag removes it here. */
  repositories?: Record<string, string[]>;
  /** Status payload; Health follows RegistryHealthStatus (1 = healthy). */
  status?: {
    Health: number;
    Version?: string;
    ReadOnly?: boolean;
    Components?: { Name?: string; Status?: number }[];
  };
  statusError?: ApiError;
  deleteError?: ApiError;
}

export interface RegistryApiMockState {
  repositories: Record<string, string[]>;
  deleted: string[];
}

/**
 * Mock the registry status route and the OCI distribution tag list and
 * manifest delete routes. Returns the live state so a test can assert
 * which manifests were deleted.
 */
export async function mockRegistryApi(
  page: Page,
  config: RegistryApiMockConfig = {}
): Promise<RegistryApiMockState> {
  const state: RegistryApiMockState = {
    repositories: Object.fromEntries(
      Object.entries(config.repositories ?? {}).map(([k, v]) => [k, [...v]])
    ),
    deleted: [],
  };
  const status = config.status ?? { Health: 1, Version: '1.0.0', ReadOnly: false, Components: [] };

  await page.route('**/api/v1/compute/images/status*', async (route: Route, request: Request) => {
    if (request.method() !== 'GET') {
      await route.continue();
      return;
    }
    if (config.statusError) {
      await route.fulfill({
        status: config.statusError.status,
        contentType: 'application/json',
        body: errorEnvelope(config.statusError),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ payload: status }),
    });
  });

  await page.route('**/v2/**', async (route: Route, request: Request) => {
    const path = decodeURIComponent(new URL(request.url()).pathname).replace(/\/$/, '');
    const tagsMatch = /^\/v2\/(.+)\/tags\/list$/.exec(path);
    if (tagsMatch && request.method() === 'GET') {
      const name = tagsMatch[1];
      const tags = state.repositories[name];
      if (!tags) {
        await route.fulfill({
          status: 404,
          contentType: 'application/json',
          body: JSON.stringify({ errors: [{ code: 'NAME_UNKNOWN', message: 'repository name not known to registry' }] }),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ name, tags }),
      });
      return;
    }
    const manifestMatch = /^\/v2\/(.+)\/manifests\/([^/]+)$/.exec(path);
    if (manifestMatch && request.method() === 'DELETE') {
      if (config.deleteError) {
        await route.fulfill({
          status: config.deleteError.status,
          contentType: 'application/json',
          body: errorEnvelope(config.deleteError),
        });
        return;
      }
      const [, name, reference] = manifestMatch;
      state.repositories[name] = (state.repositories[name] ?? []).filter((t) => t !== reference);
      state.deleted.push(`${name}:${reference}`);
      await route.fulfill({ status: 202, body: '' });
      return;
    }
    await route.continue();
  });

  return state;
}

/**
 * Mock all common API endpoints with default configurations.
 *
 * @param page - Playwright page object
 * @param options - Configuration for each API mock
 */
export async function mockAllApis(
  page: Page,
  options: {
    invitation?: InvitationApiMockConfig;
    tenant?: TenantApiMockConfig;
    health?: HealthApiMockConfig;
  } = {}
): Promise<{
  invitation: Awaited<ReturnType<typeof mockInvitationApi>>;
  tenant: Awaited<ReturnType<typeof mockTenantApi>>;
}> {
  const [invitation, tenant] = await Promise.all([
    mockInvitationApi(page, options.invitation),
    mockTenantApi(page, options.tenant),
    mockHealthApi(page, options.health),
  ]);

  return { invitation, tenant };
}

/**
 * A request the IDevID mock received.
 */
export interface IDevIDApiCall {
  /** HTTP method */
  method: string;
  /** Path below /api/v1/idevid, without a trailing slash ('' for the root) */
  path: string;
  /** Parsed JSON body, if any */
  body: unknown;
}

export interface IDevIDApiMockConfig {
  /** HasIDevID result (default true) */
  hasIDevID?: boolean;
  /** HasIAK result (default false) */
  hasIAK?: boolean;
  /** Responses that override the defaults, keyed by 'METHOD /path' (e.g. 'POST /iak/csr') */
  responses?: Record<string, { status?: number; body: unknown }>;
}

const idevidOk = { success: true, message: 'ok' };

/**
 * Mock the IDevID/IAK API (pkg/webservice/v1/rest/idevid/router.go).
 *
 * Handles every route below /api/v1/idevid with a canned success response
 * and records each call so a test can assert the request the page sent.
 *
 * @param page - Playwright page object
 * @param config - Mock configuration options
 */
export async function mockIDevIDApi(
  page: Page,
  config: IDevIDApiMockConfig = {}
): Promise<{ calls: IDevIDApiCall[] }> {
  const calls: IDevIDApiCall[] = [];
  const defaults: Record<string, { status?: number; body: unknown }> = {
    'GET /exists': { body: { exists: config.hasIDevID ?? true } },
    'GET /iak/exists': { body: { exists: config.hasIAK ?? false } },
    'GET /attributes': {
      body: {
        attributes: {
          tpmManufacturer: 'Infineon',
          tpmModel: 'SLB9672',
          tpmVersion: '2.0',
          platformManufacturer: 'Acme',
          platformModel: 'Edge-1',
          platformVersion: '1.0',
          platformSerial: 'SN-0001',
        },
      },
    },
    'POST /iak/generate': { status: 201, body: { status: idevidOk } },
    'DELETE /iak': {
      status: 409,
      body: {
        message:
          'idevid: the IAK key is TPM-resident and is not evicted by this service; nothing was deleted (delete its certificate with DeleteIAKCertificate)',
        code: 'FAILED_PRECONDITION',
      },
    },
    // The server returns binary TCG_CSR_IDEVID bytes, base64 in protobuf JSON.
    'POST /iak/csr': { body: { status: idevidOk, csrPem: Buffer.from([0x00, 0x01, 0x02, 0xff, 0x10, 0x80]).toString('base64') } },
    'POST /ldevid': { status: 201, body: { status: idevidOk, certificatePem: '-----BEGIN CERTIFICATE-----\nLDEVIDCERT\n-----END CERTIFICATE-----' } },
    'POST /certificate': { body: { status: idevidOk } },
    'POST /iak/certificate': { body: { status: idevidOk } },
    'DELETE /iak/certificate': { body: { status: idevidOk } },
    'POST /flush': { body: { status: idevidOk, flushedCount: 3 } },
    'POST /activate-credential': { body: { status: idevidOk, decryptedSecret: 'U0VDUkVU' } },
  };
  const responses = { ...defaults, ...(config.responses ?? {}) };

  await page.route(/\/api\/v1\/idevid(\/|\?|$)/, async (route: Route, request: Request) => {
    const url = new URL(request.url());
    const path = url.pathname.replace(/^.*\/api\/v1\/idevid/, '').replace(/\/$/, '');
    const method = request.method();
    let body: unknown = undefined;
    const raw = request.postData();
    if (raw) {
      try {
        body = JSON.parse(raw);
      } catch {
        body = raw;
      }
    }
    calls.push({ method, path, body });

    const response = responses[`${method} ${path}`];
    if (!response) {
      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({ message: `no mock for ${method} ${path}`, code: 'HTTP_404' }),
      });
      return;
    }
    await route.fulfill({
      status: response.status ?? 200,
      contentType: 'application/json',
      body: JSON.stringify(response.body),
    });
  });

  return { calls };
}

/**
 * Create a mock WebAuthn registration flow.
 * Mocks the registration begin and finish endpoints.
 *
 * @param page - Playwright page object
 * @param options - Configuration options
 */
export async function mockWebAuthnRegistration(
  page: Page,
  options: {
    userId?: string;
    tenantId?: string;
    success?: boolean;
    error?: ApiError | null;
  } = {}
): Promise<void> {
  const userId = options.userId || 'new-user-123';
  const tenantId = options.tenantId || 'new-tenant-456';
  const success = options.success !== false;

  await page.route('**/api/v1/webauthn/registration/begin', async (route: Route) => {
    if (options.error) {
      await route.fulfill({
        status: options.error.status,
        contentType: 'application/json',
        body: JSON.stringify({ message: options.error.error, code: options.error.errorCode || `HTTP_${options.error.status}` }),
      });
      return;
    }

    // Return mock WebAuthn options
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        publicKey: {
          challenge: 'mock-challenge-base64',
          rp: { id: 'localhost', name: 'Trusted Platform' },
          user: {
            id: userId,
            name: 'testuser',
            displayName: 'Test User',
          },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          timeout: 60000,
          attestation: 'none',
        },
      }),
    });
  });

  await page.route('**/api/v1/webauthn/registration/finish', async (route: Route) => {
    if (!success || options.error) {
      await route.fulfill({
        status: options.error?.status || 400,
        contentType: 'application/json',
        body: JSON.stringify({ message: options.error?.error || 'Registration failed', code: options.error?.errorCode || 'HTTP_400' }),
      });
      return;
    }

    // Create a mock JWT token for the response
    const now = Math.floor(Date.now() / 1000);
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({
        sub: userId,
        user_id: userId,
        email: 'testuser@example.com',
        tenant_id: tenantId,
        is_tenant_owner: true,
        roles: ['owner'],
        iat: now,
        exp: now + 3600,
      })
    ).toString('base64url');
    const signature = Buffer.from('mock-signature').toString('base64url');
    const mockJwt = `${header}.${payload}.${signature}`;

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        success: true,
        payload: { token: mockJwt },
      }),
    });
  });
}

/** One captured request to a mocked TPM operation route. */
export interface TPMOpsCall {
  path: string;
  method: string;
  body: unknown;
}

/** Responses the TPM operations mock returns (#1725). */
export interface TPMOpsMockConfig {
  eventLog?: Record<string, unknown>;
  pcrValues?: Array<{ index: number; value: string }>;
  makeCredential?: { credentialBlob: string; encryptedSecret: string; secret?: string };
  activateSecret?: string;
  randomBytes?: string;
}

/**
 * Mock the TPM event log, PCR read and extend, MakeCredential,
 * ActivateCredential and GetRandom routes. Returns the captured calls.
 */
export async function mockTPMOpsApi(
  page: Page,
  config: TPMOpsMockConfig = {}
): Promise<TPMOpsCall[]> {
  const calls: TPMOpsCall[] = [];
  const zero = btoa(String.fromCharCode(...new Array(32).fill(0)));
  const pcrValues =
    config.pcrValues ?? Array.from({ length: 24 }, (_, index) => ({ index, value: zero }));

  const reply = (path: string, body: unknown) => async (route: Route, request: Request) => {
    const raw = request.postData();
    calls.push({ path, method: request.method(), body: raw ? JSON.parse(raw) : undefined });
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  };

  await page.route(
    '**/api/v1/tpm/eventlog**',
    reply('/eventlog', config.eventLog ?? { eventLog: btoa('tcg2-log'), format: 'tcg2' })
  );
  await page.route('**/api/v1/tpm/pcrs/extend', reply('/pcrs/extend', { status: {} }));
  await page.route(/\/api\/v1\/tpm\/pcrs(\?.*)?$/, reply('/pcrs', { pcrValues }));
  await page.route(
    '**/api/v1/tpm/make-credential',
    reply(
      '/make-credential',
      config.makeCredential ?? { credentialBlob: btoa('blob'), encryptedSecret: btoa('enc') }
    )
  );
  await page.route(
    '**/api/v1/tpm/activate-credential',
    reply('/activate-credential', { secret: config.activateSecret ?? btoa('\x01\x02\x03') })
  );
  await page.route(
    '**/api/v1/tpm/random',
    reply('/random', { randomBytes: config.randomBytes ?? btoa('\xde\xad\xbe\xef') })
  );
  return calls;
}

/**
 * Create a mock WebAuthn login flow.
 * Mocks the login begin and finish endpoints.
 *
 * @param page - Playwright page object
 * @param options - Configuration options
 */
export async function mockWebAuthnLogin(
  page: Page,
  options: {
    userId?: string;
    tenantId?: string;
    isTenantOwner?: boolean;
    success?: boolean;
    error?: ApiError | null;
  } = {}
): Promise<void> {
  const userId = options.userId || 'existing-user-123';
  const tenantId = options.tenantId || 'existing-tenant-456';
  const isTenantOwner = options.isTenantOwner !== false;
  const success = options.success !== false;

  await page.route('**/api/v1/webauthn/login/begin', async (route: Route, request: Request) => {
    if (options.error) {
      await route.fulfill({
        status: options.error.status,
        contentType: 'application/json',
        body: JSON.stringify({ message: options.error.error, code: options.error.errorCode || `HTTP_${options.error.status}` }),
      });
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        // No allowCredentials: the ceremony is discoverable-credential, so
        // the authenticator chooses and the server resolves the user from
        // the credential it returns.
        publicKey: {
          challenge: 'mock-challenge-base64',
          timeout: 60000,
          rpId: 'localhost',
        },
        session_id: 'mock-login-session',
      }),
    });
  });

  await page.route('**/api/v1/webauthn/login/finish', async (route: Route) => {
    if (!success || options.error) {
      await route.fulfill({
        status: options.error?.status || 401,
        contentType: 'application/json',
        body: JSON.stringify({ message: options.error?.error || 'Login failed', code: options.error?.errorCode || 'HTTP_401' }),
      });
      return;
    }

    // Create a mock JWT token
    const now = Math.floor(Date.now() / 1000);
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({
        sub: userId,
        user_id: userId,
        email: 'testuser@example.com',
        tenant_id: tenantId,
        is_tenant_owner: isTenantOwner,
        roles: isTenantOwner ? ['owner'] : ['member'],
        iat: now,
        exp: now + 3600,
      })
    ).toString('base64url');
    const signature = Buffer.from('mock-signature').toString('base64url');
    const mockJwt = `${header}.${payload}.${signature}`;

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        success: true,
        // The session the platform minted from the identity the backbone
        // resolved. The backbone's own bearer is not forwarded and neither
        // is its renewal credential, so a mock that included one would test
        // a payload the server does not send.
        payload: {
          bearer: mockJwt,
          expiresAt: new Date((now + 3600) * 1000).toISOString(),
        },
      }),
    });
  });
}

/**
 * Mock invitation validation endpoint for joining existing tenant.
 *
 * @param page - Playwright page object
 * @param options - Configuration options
 */
export async function mockInvitationValidation(
  page: Page,
  options: {
    valid?: boolean;
    tenantId?: string;
    tenantName?: string;
    role?: string;
    error?: ApiError | null;
  } = {}
): Promise<void> {
  const valid = options.valid !== false;
  const tenantId = options.tenantId || 'invited-tenant-123';
  const tenantName = options.tenantName || 'Invited Workspace';
  const role = options.role || 'member';

  await page.route('**/api/v1/invitations/validate*', async (route: Route) => {
    if (options.error || !valid) {
      await route.fulfill({
        status: options.error?.status || 400,
        contentType: 'application/json',
        body: JSON.stringify({
          message: options.error?.error || 'Invalid or expired invitation',
          code: options.error?.errorCode || 'HTTP_400',
        }),
      });
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        valid: true,
        tenant_id: tenantId,
        tenant_name: tenantName,
        role,
        email: 'invited@example.com',
      }),
    });
  });
}

// =============================================================================
// EAB credentials (#1667)
// =============================================================================

/** The REST handlers serialize protobuf enum names, so the mock does too. */
export type MockEABStatus =
  | 'EAB_CREDENTIAL_STATUS_ACTIVE'
  | 'EAB_CREDENTIAL_STATUS_REVOKED'
  | 'EAB_CREDENTIAL_STATUS_EXPIRED'
  | 'EAB_CREDENTIAL_STATUS_USED';

export interface MockEABCredential {
  /** uint64 credential ID; protojson serializes it as a decimal string. */
  id: string;
  keyId: string;
  /** uint64 device profile ID, a decimal string like id. */
  profileId: string;
  tenantId: string;
  expiresAt: string;
  status: MockEABStatus;
  createdAt: string;
  updatedAt: string;
}

export interface EABApiCall {
  method: string;
  path: string;
  body: unknown;
}

export function createMockEABCredential(
  overrides: Partial<MockEABCredential> = {}
): MockEABCredential {
  const id = overrides.id ?? '1';
  return {
    id,
    keyId: `kid-${id}`,
    profileId: '1',
    tenantId: 'tenant-test-123',
    expiresAt: '2030-01-01T00:00:00Z',
    status: 'EAB_CREDENTIAL_STATUS_ACTIVE',
    createdAt: '2026-01-01T00:00:00Z',
    updatedAt: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

/** A 1x1 PNG, base64 encoded, for the QR code response. */
const MOCK_QR_PNG =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';

/**
 * Mock the EAB credential REST API (/api/v1/eab/credentials...). The mock
 * keeps the credentials in memory so a mutation shows up on the next list,
 * and records every call for assertions.
 */
export async function mockEABApi(
  page: Page,
  initial: MockEABCredential[] = [createMockEABCredential()]
): Promise<{
  calls: EABApiCall[];
  getCredentials: () => MockEABCredential[];
}> {
  let credentials = initial.map((c) => ({ ...c }));
  // BigInt keeps timestamp-sized ids above Number.MAX_SAFE_INTEGER exact.
  let nextId =
    credentials.reduce((max, c) => (BigInt(c.id) > max ? BigInt(c.id) : max), BigInt(0)) +
    BigInt(1);
  const calls: EABApiCall[] = [];
  const ok = { success: true, message: 'ok' };

  const json = (route: Route, status: number, body: unknown) =>
    route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  const notFound = (route: Route) =>
    json(route, 404, { message: 'credential not found', code: 'NOT_FOUND' });

  await page.route(
    (url) => url.pathname.includes('/api/v1/eab/credentials'),
    async (route: Route, request: Request) => {
      const method = request.method();
      const url = new URL(request.url());
      const path = url.pathname
        .replace(/\/$/, '')
        .replace(/^.*\/api\/v1\/eab\/credentials/, '');
      let body: unknown = null;
      try {
        body = request.postDataJSON();
      } catch {
        body = request.postData();
      }
      calls.push({ method, path, body });

      const byId = (raw: string) => credentials.find((c) => c.id === raw);
      let m: RegExpMatchArray | null;

      if (method === 'GET' && path === '') {
        return json(route, 200, {
          credentials,
          pagination: {
            page: 1,
            pageSize: credentials.length,
            totalItems: credentials.length,
            totalPages: 1,
          },
        });
      }
      if (method === 'POST' && path === '') {
        const req = (body ?? {}) as { profileId?: string; tenantId?: string };
        const cred = createMockEABCredential({
          id: (nextId++).toString(),
          profileId: req.profileId ?? '0',
          tenantId: req.tenantId ?? '',
        });
        cred.keyId = `kid-created-${cred.id}`;
        credentials.push(cred);
        return json(route, 200, { status: ok, credential: { ...cred, hmacKey: 'hmac-secret-value' } });
      }
      if (method === 'POST' && path === '/validate') {
        const req = (body ?? {}) as { keyId?: string; hmacKey?: string };
        const valid = req.hmacKey === 'good-hmac' && credentials.some((c) => c.keyId === req.keyId);
        return json(route, 200, { status: ok, valid });
      }
      if (method === 'POST' && path === '/cleanup') {
        const before = credentials.length;
        credentials = credentials.filter((c) => c.status !== 'EAB_CREDENTIAL_STATUS_EXPIRED');
        return json(route, 200, { status: ok, deletedCount: before - credentials.length });
      }
      if (method === 'GET' && (m = path.match(/^\/key\/([^/]+)$/))) {
        const keyId = decodeURIComponent(m[1]);
        const cred = credentials.find((c) => c.keyId === keyId);
        return cred ? json(route, 200, { credential: cred }) : notFound(route);
      }
      if ((m = path.match(/^\/(\d+)(\/[a-z-]+)?$/))) {
        const cred = byId(m[1]);
        if (!cred) return notFound(route);
        const action = m[2] ?? '';
        if (method === 'GET' && action === '') return json(route, 200, { credential: cred });
        if (method === 'DELETE' && action === '') {
          credentials = credentials.filter((c) => c.id !== cred.id);
          return json(route, 200, { status: ok });
        }
        if (method === 'POST' && action === '/revoke') {
          cred.status = 'EAB_CREDENTIAL_STATUS_REVOKED';
          return json(route, 200, { status: ok });
        }
        if (method === 'POST' && action === '/used') {
          cred.status = 'EAB_CREDENTIAL_STATUS_USED';
          return json(route, 200, { status: ok });
        }
        if (method === 'GET' && action === '/qrcode') {
          return json(route, 200, { qrCode: MOCK_QR_PNG, format: 'png', size: 256 });
        }
        if (method === 'GET' && action === '/url') {
          return json(route, 200, {
            url: `/enroll?kid=${encodeURIComponent(cred.keyId)}`,
            timestamp: '2026-01-01T00:00:00Z',
          });
        }
      }
      return json(route, 404, { message: `unmocked EAB route ${method} ${path}` });
    }
  );

  return { calls, getCredentials: () => credentials.map((c) => ({ ...c })) };
}

// CA operations (GetCAInfo, SignCSR, VerifyCertificate)

export interface CAOperationsMockConfig {
  infoError?: ApiError | null;
  signError?: ApiError | null;
  verifyValid?: boolean;
  /** The certificate is revoked: only a request with verifyRevocation true sees it. */
  verifyRevoked?: boolean;
}

/**
 * Mock the CA operation endpoints.
 *
 * Handles:
 * - GET /api/v1/ca/info - CA identity, defaults and chain summaries
 * - POST /api/v1/ca/sign-csr - Certify the key a CSR names
 * - POST /api/v1/ca/certificates/verify - Verify a certificate
 *
 * @returns the request bodies the pages posted, and the Authorization
 *   header of each sign request, for assertions
 */
export async function mockCAOperationsApi(
  page: Page,
  config: CAOperationsMockConfig = {}
): Promise<{ signRequests: unknown[]; signAuthorizations: string[]; verifyRequests: unknown[] }> {
  const signRequests: unknown[] = [];
  const signAuthorizations: string[] = [];
  const verifyRequests: unknown[] = [];
  const now = new Date().toISOString();

  await page.route('**/api/v1/ca/info*', async (route: Route, request: Request) => {
    if (request.method() !== 'GET') {
      await route.continue();
      return;
    }
    if (config.infoError) {
      await route.fulfill({
        status: config.infoError.status,
        contentType: 'application/json',
        body: errorEnvelope(config.infoError),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        caInfo: {
          commonName: 'Platform Intermediate CA',
          isInitialized: true,
          isIntermediate: true,
          rootCert: { serial: '01', commonName: 'Platform Root CA', issuer: 'Platform Root CA' },
          intermediates: [
            { serial: '02', commonName: 'Platform Intermediate CA', issuer: 'Platform Root CA' },
          ],
          keyStores: [],
          defaultAlgorithm: 'ECDSA-P256',
          defaultValidityDays: 397,
        },
        timestamp: now,
      }),
    });
  });

  await page.route('**/api/v1/ca/sign-csr*', async (route: Route, request: Request) => {
    if (request.method() !== 'POST') {
      await route.continue();
      return;
    }
    signRequests.push(request.postDataJSON());
    // SignCSR needs a platform token granting ca:sign-csr, sent as a Bearer
    // Authorization header: the session cookie alone is refused.
    const authorization = request.headers()['authorization'] ?? '';
    signAuthorizations.push(authorization);
    if (!/^Bearer \S+$/.test(authorization)) {
      await route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: errorEnvelope({ status: 403, error: 'platform token with scope ca:sign-csr required' }),
      });
      return;
    }
    if (config.signError) {
      await route.fulfill({
        status: config.signError.status,
        contentType: 'application/json',
        body: errorEnvelope(config.signError),
      });
      return;
    }
    await route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify({
        status: { success: true, message: 'certificate issued successfully' },
        certificate: {
          serial: '0a1b2c',
          commonName: 'release-signer',
          issuer: 'Platform Intermediate CA',
          // Certificate.pem is proto bytes: protojson carries it as base64.
          pem: Buffer.from('-----BEGIN CERTIFICATE-----\nSIGNED\n-----END CERTIFICATE-----\n').toString(
            'base64'
          ),
        },
        timestamp: now,
      }),
    });
  });

  await page.route('**/api/v1/ca/certificates/verify*', async (route: Route, request: Request) => {
    if (request.method() !== 'POST') {
      await route.continue();
      return;
    }
    const verifyBody = request.postDataJSON() as { certificatePem?: unknown; verifyRevocation?: unknown } | null;
    verifyRequests.push(verifyBody);
    // VerifyCertificateRequest.certificate_pem is proto bytes: the server's
    // protojson decode needs standard base64 and fails on plain PEM.
    const wirePem = verifyBody?.certificatePem;
    const isBase64 =
      typeof wirePem === 'string' && wirePem.length % 4 === 0 && /^[A-Za-z0-9+/]*={0,2}$/.test(wirePem);
    const decoded = isBase64 ? Buffer.from(wirePem as string, 'base64').toString('utf8') : '';
    if (!decoded.startsWith('-----BEGIN CERTIFICATE-----')) {
      await route.fulfill({
        status: 400,
        contentType: 'application/json',
        body: errorEnvelope({
          status: 400,
          error: 'invalid request body: certificatePem must be base64',
        }),
      });
      return;
    }
    // The backend checks revocation only when verifyRevocation is true; a
    // revoked certificate with a valid chain passes plain X.509 verification.
    if (config.verifyRevoked && verifyBody?.verifyRevocation === true) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: { success: true },
          valid: false,
          chain: [],
          errors: ['certificate is revoked'],
          warnings: [],
          timestamp: now,
        }),
      });
      return;
    }
    const valid = config.verifyValid !== false;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        status: { success: true },
        valid,
        chain: valid ? ['0a1b2c', '02', '01'] : [],
        errors: valid ? [] : ['certificate has expired'],
        warnings: [],
        timestamp: now,
      }),
    });
  });

  return { signRequests, signAuthorizations, verifyRequests };
}

/**
 * Mock the invitation lookup and accept endpoints: GET /invitations/{id}
 * (GetInvitation), GET /invitations/token/{token} (GetInvitationByToken)
 * and POST /invitations/accept (AcceptInvitation). Returns the accept
 * request bodies the page sent.
 */
export async function mockInvitationLookupApi(
  page: Page,
  options: {
    invitation: Invitation;
    acceptError?: ApiError | null;
  }
): Promise<{ acceptRequests: () => Array<Record<string, unknown>> }> {
  const accepted: Array<Record<string, unknown>> = [];
  const inv = options.invitation;

  await page.route(/\/api\/v1\/invitations\/[^?]+/, async (route: Route, request: Request) => {
    const path = new URL(request.url()).pathname.replace(/\/+$/, '');
    const method = request.method();

    if (method === 'POST' && path.endsWith('/invitations/accept')) {
      const body = (request.postDataJSON() as Record<string, unknown>) ?? {};
      accepted.push(body);
      const present = (v: unknown) => v !== undefined && v !== null && String(v) !== '';
      if (!present(body.token) || !(present(body.userId) || present(body.user_id))) {
        await route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: errorEnvelope({
            status: 400,
            error: 'invitation: user ID is required',
            errorCode: 'INVALID_ARGUMENT',
          }),
        });
        return;
      }
      if (options.acceptError) {
        await route.fulfill({
          status: options.acceptError.status,
          contentType: 'application/json',
          body: errorEnvelope(options.acceptError),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true, user_id: 'user-new', tenant_id: 'tenant-1' }),
      });
      return;
    }

    if (method === 'GET') {
      const byToken = path.match(/\/invitations\/token\/([^/]+)$/);
      const byId = path.match(/\/invitations\/([^/]+)$/);
      const key = byToken ? decodeURIComponent(byToken[1]) : byId ? decodeURIComponent(byId[1]) : '';
      const found = byToken ? key === inv.token : key === inv.id;
      if (found) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ invitation: inv }),
        });
      } else {
        await route.fulfill({
          status: 404,
          contentType: 'application/json',
          body: errorEnvelope({ status: 404, error: 'invitation not found', errorCode: 'NOT_FOUND' }),
        });
      }
      return;
    }

    await route.continue();
  });

  return { acceptRequests: () => [...accepted] };
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

// ============================================================================
// Overlay API mock (#1722): VTEPs, VNIs, tunnels, tunnel stats, MAC forget
// ============================================================================

export interface OverlayApiMockConfig {
  vteps?: Array<{ nodeId: string; ip: string; healthy: boolean; lastSeen: string }>;
  vnis?: Array<{ id: string; config: { vni: number; name?: string }; createdAt: string; macCount: number }>;
  tunnels?: Array<{
    localVtep: string;
    remoteVtep: string;
    vni: number;
    state: string;
    bytesTx: number;
    bytesRx: number;
  }>;
  macs?: Array<{ mac: string; vni: number; remoteVtep: string; learnedAt: string }>;
  /**
   * Requests to fail, keyed '<METHOD> <path>' (for example 'DELETE /vnis/5001'
   * or 'GET /vteps'), with the HTTP status to answer. Use a status the client
   * does not retry (403, not 503).
   */
  failures?: Record<string, number>;
}

/** One request the overlay mock answered: method, path and query. */
export interface OverlayApiCall {
  method: string;
  path: string;
  query: Record<string, string>;
}

/**
 * Mock every /api/v1/overlay route the VTEPs page calls. Returns the list
 * of calls, in order, so tests can assert on the destructive requests.
 */
export async function mockOverlayApi(
  page: Page,
  config: OverlayApiMockConfig = {}
): Promise<OverlayApiCall[]> {
  const calls: OverlayApiCall[] = [];
  const vteps = [...(config.vteps ?? [])];
  let vnis = [...(config.vnis ?? [])];
  const tunnels = [...(config.tunnels ?? [])];
  let macs = [...(config.macs ?? [])];

  await page.route(
    (url) => url.pathname.startsWith('/api/v1/overlay/'),
    async (route: Route, request: Request) => {
      const url = new URL(request.url());
      const method = request.method();
      const path = url.pathname.replace('/api/v1/overlay', '');
      const query = Object.fromEntries(url.searchParams.entries());
      calls.push({ method, path, query });
      const json = (status: number, body: unknown) =>
        route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

      const failStatus = config.failures?.[`${method} ${path}`];
      if (failStatus !== undefined) {
        return json(failStatus, { error: { code: 'forbidden', message: 'denied' } });
      }
      if (method === 'GET' && path === '/vteps') return json(200, { vteps });
      if (method === 'GET' && path.startsWith('/vteps/')) {
        const nodeId = decodeURIComponent(path.slice('/vteps/'.length));
        const vtep = vteps.find((v) => v.nodeId === nodeId);
        return vtep
          ? json(200, { vtep })
          : json(404, { error: { code: 'not_found', message: 'vtep not found' } });
      }
      if (method === 'GET' && path === '/vnis') return json(200, { vnis });
      if (method === 'DELETE' && path.startsWith('/vnis/')) {
        const vni = Number(path.slice('/vnis/'.length));
        vnis = vnis.filter((v) => v.config.vni !== vni);
        // Controller.RemoveVNI removes every remote MAC of the VNI too.
        macs = macs.filter((m) => m.vni !== vni);
        return json(200, { status: { success: true, message: 'deleted' } });
      }
      if (method === 'GET' && path === '/tunnels') return json(200, { tunnels });
      if (method === 'GET' && path === '/tunnels/stats') {
        const tunnel = tunnels.find(
          (t) => t.remoteVtep === query.remote_vtep && String(t.vni) === query.vni
        );
        return tunnel
          ? json(200, { tunnel })
          : json(404, { error: { code: 'not_found', message: 'tunnel not found' } });
      }
      if (method === 'GET' && path === '/macs') {
        const listed =
          query.vni !== undefined ? macs.filter((m) => String(m.vni) === query.vni) : macs;
        return json(200, { macs: listed });
      }
      if (method === 'DELETE' && path === '/macs') {
        macs = macs.filter((m) => !(m.mac === query.mac && String(m.vni) === query.vni));
        return json(200, { status: { success: true, message: 'forgotten' } });
      }
      return route.continue();
    }
  );

  return calls;
}

/**
 * One recorded call to the vTPM bundle runtime API.
 */
export interface VTPMRuntimeCall {
  method: string;
  path: string;
  query: string;
  body: unknown;
}

export interface VTPMRuntimeApiMockConfig {
  /** Error to return for every runtime route (e.g. bundle not running) */
  error?: ApiError;
  /** Per-operation reply delay in ms, keyed by operation ('start', 'quote', 'pcrs/extend', 'pcrs', ...) */
  delayMs?: Record<string, number>;
  /**
   * Which listener's contract to speak (default 'webservice').
   * 'daemon' is pkg/api/rest/vtpm_handlers.go: no /pcrs routes (404),
   * GET /pcr/{index} and POST /pcr/{index}/extend instead, and a stop reply
   * of { bundle_id, action, success, message } without `stopped` (#452).
   */
  listener?: 'webservice' | 'daemon';
}

/**
 * Mock the vTPM bundle runtime API (#1726).
 *
 * Handles, for any bundle id:
 * - POST /api/v1/vtpm/bundles/{id}/start, /stop, /quote, /seal, /unseal
 * - POST /api/v1/vtpm/bundles/{id}/pcrs/extend
 * - GET  /api/v1/vtpm/bundles/{id}/pcrs?pcr_index=N
 *
 * Byte fields are base64 on the wire, as Go encodes []byte. Seal returns
 * base64("sealed:" + data) and unseal reverses it, so a round trip through
 * the page restores the original text.
 */
export async function mockVTPMRuntimeApi(
  page: Page,
  config: VTPMRuntimeApiMockConfig = {}
): Promise<{ calls: VTPMRuntimeCall[] }> {
  const calls: VTPMRuntimeCall[] = [];
  const ok = { success: true, message: 'ok' };
  const b64 = (s: string) => Buffer.from(s, 'binary').toString('base64');
  const unb64 = (s: string) => Buffer.from(s, 'base64').toString('binary');

  await page.route('**/api/v1/vtpm/bundles/**', async (route: Route, request: Request) => {
    const url = new URL(request.url());
    const m = url.pathname.match(
      /\/api\/v1\/vtpm\/bundles\/([^/]+)\/(start|stop|quote|seal|unseal|pcrs\/extend|pcrs|pcr\/\d+\/extend|pcr\/\d+)\/?$/
    );
    if (!m) {
      await route.continue();
      return;
    }
    const bundleId = decodeURIComponent(m[1]);
    const op = m[2];
    const daemon = config.listener === 'daemon';
    const daemonPCR = op.match(/^pcr\/(\d+)(\/extend)?$/);
    const method = request.method();
    const body = method === 'POST' ? (request.postDataJSON() as Record<string, unknown> | null) : null;
    calls.push({ method, path: `${op}`, query: url.search, body });

    const delay = config.delayMs?.[op] ?? 0;
    if (delay > 0) {
      await new Promise((resolve) => setTimeout(resolve, delay));
    }

    if (config.error) {
      await route.fulfill({
        status: config.error.status,
        contentType: 'application/json',
        body: errorEnvelope(config.error),
      });
      return;
    }

    // Each listener answers 404 on the other listener's PCR routes.
    const notMine = daemon ? op === 'pcrs' || op === 'pcrs/extend' : daemonPCR !== null;
    if (notMine) {
      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: errorEnvelope({ error: '404 page not found', status: 404 }),
      });
      return;
    }

    let reply: unknown;
    if (method === 'POST' && op === 'start') {
      reply = { status: ok, bundle_id: bundleId, running: true, socket_path: `/run/vtpm/${bundleId}.sock` };
    } else if (daemon && method === 'POST' && op === 'stop') {
      reply = { bundle_id: bundleId, action: 'stop', success: true, message: 'ok' };
    } else if (daemonPCR && daemonPCR[2] && method === 'POST') {
      reply = { bundle_id: bundleId, action: 'extend_pcr', success: true, message: 'ok' };
    } else if (daemonPCR && !daemonPCR[2] && method === 'GET') {
      reply = {
        bundle_id: bundleId,
        pcr_index: Number(daemonPCR[1]),
        value: b64('\xde\xad\xbe\xef'),
        timestamp: '2026-11-12T00:00:00Z',
      };
    } else if (method === 'POST' && op === 'stop') {
      reply = { status: ok, bundle_id: bundleId, stopped: true };
    } else if (method === 'POST' && op === 'quote') {
      reply = {
        status: ok,
        bundle_id: bundleId,
        quote: b64('mock-quote'),
        signature: b64('mock-signature'),
        pcr_values: { '0': b64('\x00\x11'), '7': b64('\xaa\xbb') },
        hash_algorithm: 'SHA256',
      };
    } else if (method === 'POST' && op === 'seal') {
      reply = { status: ok, bundle_id: bundleId, sealed_data: b64(`sealed:${unb64(String(body?.data ?? ''))}`) };
    } else if (method === 'POST' && op === 'unseal') {
      const raw = unb64(String(body?.sealed_data ?? ''));
      reply = { status: ok, bundle_id: bundleId, data: b64(raw.replace(/^sealed:/, '')) };
    } else if (method === 'POST' && op === 'pcrs/extend') {
      reply = { status: ok, bundle_id: bundleId, pcr_index: Number(body?.pcr_index ?? 0), extended: true };
    } else if (method === 'GET' && op === 'pcrs') {
      const idx = Number(url.searchParams.get('pcr_index') ?? '0');
      reply = { status: ok, bundle_id: bundleId, pcr_index: idx, value: b64('\xde\xad\xbe\xef') };
    } else {
      await route.continue();
      return;
    }

    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(reply) });
  });

  return { calls };
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
