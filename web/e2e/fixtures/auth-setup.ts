import { Page, BrowserContext } from '@playwright/test';

/**
 * Auth Setup Fixture for E2E Tests
 *
 * Provides utilities for setting up authenticated sessions with mock JWT tokens
 * for testing protected routes without requiring a real backend.
 */

export interface JWTClaims {
  sub?: string;
  user_id?: string;
  email?: string;
  tenant_id?: string;
  is_tenant_owner?: boolean;
  roles?: string[];
  exp?: number;
  iat?: number;
}

export interface UserSession {
  userId: string;
  email: string;
  tenantId: string;
  isTenantOwner: boolean;
  roles: string[];
}

/**
 * Create a mock JWT token with specified claims.
 * Note: This token is NOT cryptographically signed - it's for testing only.
 * The frontend decodes JWT without verification for display purposes.
 *
 * @param claims - JWT claims to include in the token
 * @returns Base64url-encoded JWT token string
 */
export function createMockJWT(claims: JWTClaims): string {
  const header = {
    alg: 'HS256',
    typ: 'JWT',
  };

  const now = Math.floor(Date.now() / 1000);
  const payload: JWTClaims = {
    iat: now,
    exp: now + 3600, // 1 hour expiry
    ...claims,
  };

  // Base64url encode without padding
  const base64UrlEncode = (obj: object): string => {
    const json = JSON.stringify(obj);
    const base64 = Buffer.from(json).toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  const headerEncoded = base64UrlEncode(header);
  const payloadEncoded = base64UrlEncode(payload);

  // Mock signature (not cryptographically valid, but sufficient for client-side testing)
  const mockSignature = base64UrlEncode({ mock: 'signature' });

  return `${headerEncoded}.${payloadEncoded}.${mockSignature}`;
}

/**
 * Set JWT cookie in the browser context for authenticated testing.
 *
 * @param context - Playwright browser context
 * @param token - JWT token string
 * @param baseUrl - Base URL for the cookie domain
 */
export async function setJWTCookie(
  context: BrowserContext,
  token: string,
  baseUrl: string = 'http://localhost:3000'
): Promise<void> {
  const url = new URL(baseUrl);

  await context.addCookies([
    {
      name: 'jwt',
      value: token,
      domain: url.hostname,
      path: '/',
      httpOnly: false,
      secure: url.protocol === 'https:',
      sameSite: 'Strict',
      expires: Math.floor(Date.now() / 1000) + 3600, // 1 hour
    },
  ]);
}

/**
 * Clear authentication cookies from the browser context.
 *
 * @param context - Playwright browser context
 */
export async function clearAuthCookies(context: BrowserContext): Promise<void> {
  await context.clearCookies();
}

/**
 * Create a tenant owner session with full admin privileges.
 *
 * @param context - Playwright browser context
 * @param options - Session configuration options
 * @returns UserSession object with session details
 */
export async function createTenantOwnerSession(
  context: BrowserContext,
  options: {
    userId?: string;
    email?: string;
    tenantId?: string;
    roles?: string[];
    baseUrl?: string;
  } = {}
): Promise<UserSession> {
  const userId = options.userId || 'owner-user-123';
  const email = options.email || 'owner@example.com';
  const tenantId = options.tenantId || 'tenant-abc-123';
  const roles = options.roles || ['owner', 'admin'];
  const baseUrl = options.baseUrl || 'http://localhost:3000';

  const token = createMockJWT({
    sub: userId,
    user_id: userId,
    email,
    tenant_id: tenantId,
    is_tenant_owner: true,
    roles,
  });

  await setJWTCookie(context, token, baseUrl);

  return {
    userId,
    email,
    tenantId,
    isTenantOwner: true,
    roles,
  };
}

/**
 * Create a tenant member session with limited privileges.
 *
 * @param context - Playwright browser context
 * @param options - Session configuration options
 * @returns UserSession object with session details
 */
export async function createTenantMemberSession(
  context: BrowserContext,
  options: {
    userId?: string;
    email?: string;
    tenantId?: string;
    roles?: string[];
    baseUrl?: string;
  } = {}
): Promise<UserSession> {
  const userId = options.userId || 'member-user-456';
  const email = options.email || 'member@example.com';
  const tenantId = options.tenantId || 'tenant-abc-123';
  const roles = options.roles || ['member'];
  const baseUrl = options.baseUrl || 'http://localhost:3000';

  const token = createMockJWT({
    sub: userId,
    user_id: userId,
    email,
    tenant_id: tenantId,
    is_tenant_owner: false,
    roles,
  });

  await setJWTCookie(context, token, baseUrl);

  return {
    userId,
    email,
    tenantId,
    isTenantOwner: false,
    roles,
  };
}

/**
 * Create a tenant admin session with elevated privileges but not owner.
 * Admins can manage some resources but cannot manage invitations (owner-only).
 *
 * @param context - Playwright browser context
 * @param options - Session configuration options
 * @returns UserSession object with session details
 */
export async function createTenantAdminSession(
  context: BrowserContext,
  options: {
    userId?: string;
    email?: string;
    tenantId?: string;
    baseUrl?: string;
  } = {}
): Promise<UserSession> {
  const userId = options.userId || 'admin-user-789';
  const email = options.email || 'admin@example.com';
  const tenantId = options.tenantId || 'tenant-abc-123';
  const roles = ['admin'];
  const baseUrl = options.baseUrl || 'http://localhost:3000';

  const token = createMockJWT({
    sub: userId,
    user_id: userId,
    email,
    tenant_id: tenantId,
    is_tenant_owner: false,
    roles,
  });

  await setJWTCookie(context, token, baseUrl);

  return {
    userId,
    email,
    tenantId,
    isTenantOwner: false,
    roles,
  };
}

/**
 * Create a session for a user without a tenant (new user).
 *
 * @param context - Playwright browser context
 * @param options - Session configuration options
 * @returns UserSession object with session details
 */
export async function createNoTenantSession(
  context: BrowserContext,
  options: {
    userId?: string;
    email?: string;
    baseUrl?: string;
  } = {}
): Promise<UserSession> {
  const userId = options.userId || 'new-user-789';
  const email = options.email || 'newuser@example.com';
  const baseUrl = options.baseUrl || 'http://localhost:3000';

  const token = createMockJWT({
    sub: userId,
    user_id: userId,
    email,
    // No tenant_id - user has not joined a tenant yet
    is_tenant_owner: false,
    roles: [],
  });

  await setJWTCookie(context, token, baseUrl);

  return {
    userId,
    email,
    tenantId: '',
    isTenantOwner: false,
    roles: [],
  };
}

/**
 * Create a custom session with specific claims.
 *
 * @param context - Playwright browser context
 * @param claims - Custom JWT claims
 * @param baseUrl - Base URL for the cookie domain
 * @returns UserSession object with session details
 */
export async function createCustomSession(
  context: BrowserContext,
  claims: JWTClaims,
  baseUrl: string = 'http://localhost:3000'
): Promise<UserSession> {
  const token = createMockJWT(claims);
  await setJWTCookie(context, token, baseUrl);

  return {
    userId: claims.sub || claims.user_id || '',
    email: claims.email || '',
    tenantId: claims.tenant_id || '',
    isTenantOwner: claims.is_tenant_owner || false,
    roles: claims.roles || [],
  };
}

/**
 * Verify that a user is authenticated by checking JWT cookie presence.
 *
 * @param context - Playwright browser context
 * @returns True if JWT cookie exists, false otherwise
 */
export async function isAuthenticated(context: BrowserContext): Promise<boolean> {
  const cookies = await context.cookies();
  return cookies.some((cookie) => cookie.name === 'jwt');
}

/**
 * Get the current session from JWT cookie.
 *
 * @param context - Playwright browser context
 * @returns UserSession if authenticated, null otherwise
 */
export async function getCurrentSession(
  context: BrowserContext
): Promise<UserSession | null> {
  const cookies = await context.cookies();
  const jwtCookie = cookies.find((cookie) => cookie.name === 'jwt');

  if (!jwtCookie) {
    return null;
  }

  try {
    const parts = jwtCookie.value.split('.');
    if (parts.length !== 3) {
      return null;
    }

    // Decode payload (add padding if needed)
    let payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padLength = (4 - (payload.length % 4)) % 4;
    payload += '='.repeat(padLength);

    const decoded = JSON.parse(Buffer.from(payload, 'base64').toString('utf-8'));

    return {
      userId: decoded.sub || decoded.user_id || '',
      email: decoded.email || '',
      tenantId: decoded.tenant_id || '',
      isTenantOwner: decoded.is_tenant_owner || false,
      roles: decoded.roles || [],
    };
  } catch {
    return null;
  }
}

/**
 * Helper to set up authenticated page with tenant owner session.
 *
 * @param page - Playwright page object
 * @param options - Session configuration options
 * @returns UserSession object with session details
 */
export async function setupTenantOwnerPage(
  page: Page,
  options: {
    userId?: string;
    email?: string;
    tenantId?: string;
    roles?: string[];
    baseUrl?: string;
  } = {}
): Promise<UserSession> {
  return createTenantOwnerSession(page.context(), options);
}

/**
 * Helper to set up authenticated page with tenant member session.
 *
 * @param page - Playwright page object
 * @param options - Session configuration options
 * @returns UserSession object with session details
 */
export async function setupTenantMemberPage(
  page: Page,
  options: {
    userId?: string;
    email?: string;
    tenantId?: string;
    roles?: string[];
    baseUrl?: string;
  } = {}
): Promise<UserSession> {
  return createTenantMemberSession(page.context(), options);
}
