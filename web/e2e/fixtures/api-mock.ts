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

// ============================================================================
// Platform daemon status, config and service lifecycle (#1752)
// ============================================================================

export interface DaemonServiceMock {
  name: string;
  status: string;
  uptime?: string;
  started_at?: string;
  start_count: number;
  stop_count: number;
  last_error?: string;
}

export interface PlatformDaemonApiMockConfig {
  status?: Record<string, unknown>;
  version?: Record<string, unknown>;
  config?: Record<string, unknown>;
  services?: DaemonServiceMock[];
  /** Answer every daemon route with this error */
  error?: ApiError;
}

export interface PlatformDaemonApiState {
  /** Each request the page made, as "METHOD /path" below /api/v1/platform */
  calls: string[];
  services: DaemonServiceMock[];
}

/**
 * Mock the daemon routes under /api/v1/platform: GET /status, /version,
 * /config and /services, GET /services/{name}, POST /config/reload and
 * POST /services/{name}/{start|stop|restart}. Start, stop and restart
 * change the mocked service's status.
 */
export async function mockPlatformDaemonApi(
  page: Page,
  config: PlatformDaemonApiMockConfig = {}
): Promise<PlatformDaemonApiState> {
  const state: PlatformDaemonApiState = {
    calls: [],
    services: (config.services ?? [
      { name: 'kms', status: 'running', uptime: '2h0m0s', start_count: 1, stop_count: 0 },
      { name: 'dns', status: 'stopped', start_count: 1, stop_count: 1 },
    ]).map((s) => ({ ...s })),
  };
  const routeRe = /\/api\/v1\/platform(\/(?:status|version|config|services)(?:\/[^?]*)?)(?:\?.*)?$/;

  await page.route(
    (url) => routeRe.test(url.pathname + url.search),
    async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      const path = routeRe.exec(url.pathname)?.[1] ?? '';
      const method = request.method();
      state.calls.push(`${method} ${path}`);
      const json = (status: number, body: unknown) =>
        route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
      const fail = (err: ApiError) =>
        route.fulfill({ status: err.status, contentType: 'application/json', body: errorEnvelope(err) });

      if (config.error) {
        return fail(config.error);
      }
      if (method === 'GET' && path === '/status') {
        return json(200, config.status ?? {
          status: 'running', version: '1.4.2', git_commit: 'abc1234', go_version: 'go1.24', timestamp: 1,
        });
      }
      if (method === 'GET' && path === '/version') {
        return json(200, config.version ?? { version: '1.4.2', git_commit: 'abc1234' });
      }
      if (method === 'GET' && path === '/config') {
        return json(200, config.config ?? { log_level: 'info', listen_port: 8443 });
      }
      if (method === 'POST' && path === '/config/reload') {
        return json(200, { status: { success: true, message: 'configuration reloaded' } });
      }
      if (method === 'GET' && path === '/services') {
        return json(200, { services: state.services, count: state.services.length, timestamp: 1 });
      }
      const m = /^\/services\/([^/]+)(?:\/(start|stop|restart))?$/.exec(path);
      const svc = m ? state.services.find((s) => s.name === decodeURIComponent(m[1] ?? '')) : undefined;
      if (!m || !svc) {
        return fail({ status: 404, error: 'service not found' });
      }
      const action = m[2];
      if (method === 'GET' && !action) {
        return json(200, svc);
      }
      if (method === 'POST' && action) {
        if (action === 'stop') {
          svc.status = 'stopped';
          svc.stop_count += 1;
        } else {
          svc.status = 'running';
          svc.start_count += 1;
          if (action === 'restart') svc.stop_count += 1;
        }
        return json(200, { service: svc.name, action, success: true, message: `${svc.name} ${action === 'stop' ? 'stopped' : `${action}ed`}` });
      }
      return fail({ status: 405, error: 'method not allowed' });
    }
  );
  return state;
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
