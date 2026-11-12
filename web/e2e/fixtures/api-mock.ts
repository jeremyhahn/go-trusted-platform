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
 * A tenant as the TenantService (/api/v1/tenants) returns it (#1758).
 */
export interface LifecycleTenant {
  id: string;
  name: string;
  displayName?: string;
  state: string;
  createdAt: string;
  updatedAt: string;
}

/** One recorded TenantService call: method, path below /api/v1/tenants, body. */
export interface TenantLifecycleCall {
  method: string;
  path: string;
  body: unknown;
}

/**
 * Mocks the TenantService lifecycle, quota, sync and DEK routes under
 * /api/v1/tenants and records every call it answers. Register it after
 * mockTenantApi: the later route wins.
 */
export async function mockTenantLifecycleApi(
  page: Page,
  config: { tenant?: Partial<LifecycleTenant>; quotaAvailable?: boolean; syncFails?: boolean } = {}
): Promise<{ calls: TenantLifecycleCall[]; tenant: () => LifecycleTenant }> {
  const now = new Date().toISOString();
  let tenant: LifecycleTenant = {
    id: 'tenant-abc-123',
    name: 'acme',
    displayName: 'Acme Corp',
    state: 'TENANT_STATE_ACTIVE',
    createdAt: now,
    updatedAt: now,
    ...config.tenant,
  };
  let dekVersion = 1;
  const calls: TenantLifecycleCall[] = [];

  await page.route(/\/api\/v1\/tenants\/.+/, async (route: Route, request: Request) => {
    const url = new URL(request.url());
    const path = url.pathname.replace(/^.*\/api\/v1\/tenants/, '').replace(/\/$/, '');
    const method = request.method();
    let body: unknown = undefined;
    try {
      body = request.postDataJSON();
    } catch {
      body = request.postData();
    }
    calls.push({ method, path, body });

    const json = (data: unknown, status = 200) =>
      route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
    const ok = { status: { success: true, message: 'ok' } };

    if (method === 'POST' && path === '/sync') {
      if (config.syncFails) {
        return json({ status: { success: false, message: 'sync completed with errors: boom' } });
      }
      return json(ok);
    }
    if (method === 'GET' && path.startsWith('/by-name/')) {
      const name = decodeURIComponent(path.slice('/by-name/'.length));
      if (name !== tenant.name) return json({ message: 'tenant not found', code: 'NOT_FOUND' }, 404);
      return json({ tenant });
    }
    const id = `/${tenant.id}`;
    if (path === id && method === 'GET') return json({ tenant });
    if (path === id && method === 'PUT') {
      const update = body as { displayName?: string };
      tenant = { ...tenant, displayName: update.displayName ?? tenant.displayName };
      return json({ tenant });
    }
    if (path === id && method === 'DELETE') return json(ok);
    if (path === `${id}/suspend` && method === 'POST') {
      tenant = { ...tenant, state: 'TENANT_STATE_SUSPENDED' };
      return json(ok);
    }
    if (path === `${id}/resume` && method === 'POST') {
      tenant = { ...tenant, state: 'TENANT_STATE_ACTIVE' };
      return json(ok);
    }
    if (path === `${id}/quotas` && method === 'GET') {
      return json({
        tenantId: tenant.id,
        compute: { maxVms: 2, maxContainers: 5, maxVcpus: 8, maxMemoryMb: 4096 },
      });
    }
    if (path === `${id}/quotas` && method === 'PUT') return json(ok);
    if (path === `${id}/quota-check` && method === 'POST') {
      const req = body as { resource: string; amount: number };
      const available = config.quotaAvailable ?? true;
      return json({
        tenantId: tenant.id,
        resource: req.resource,
        amount: req.amount,
        available,
        message: available ? 'within quota' : 'quota exceeded',
      });
    }
    if (path === `${id}/dek/rotate` && method === 'POST') {
      dekVersion += 1;
      return json({ tenantId: tenant.id, oldVersion: dekVersion - 1, newVersion: dekVersion, timestamp: now });
    }
    if (path === `${id}/dek` && method === 'GET') {
      return json({
        dekStatus: {
          tenantId: tenant.id,
          path: `tenants/${tenant.id}/dek`,
          version: dekVersion,
          algorithm: 'AES-256-GCM',
          status: 'active',
          isDefault: false,
          createdAt: now,
          usageCount: 10,
          bytesUsed: 2048,
          maxUsageCount: 1000,
          maxBytesUsed: 1048576,
          warningPercent: 80,
          usagePercent: 1,
          needsRotation: false,
        },
      });
    }
    return route.continue();
  });

  return { calls, tenant: () => ({ ...tenant }) };
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
