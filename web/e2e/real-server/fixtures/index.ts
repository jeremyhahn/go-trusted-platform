import { test as base, expect, type APIRequestContext, type BrowserContext, type Page } from '@playwright/test';
import { PlatformClient } from 'trusted-platform-sdk';
import { readFileSync } from 'node:fs';
import { e2ePort, runAttestation, stateFile, type ServerState } from '../global-setup';
import { SoftAuthenticator } from './soft-authenticator';
import { claimSystemAdmin } from './system-admin';

/**
 * Real-server fixtures (#2034, epic #1665).
 *
 *  - adminPage: a page signed in as the harness admin through the real
 *    WebAuthn ceremony, answered by the software authenticator (ruling 1028
 *    Q1 (c)). The first test of a worker registers the admin (self-service
 *    registration makes it the admin of a new tenant); later tests log in
 *    with the same passkey. Each test gets its own browser context.
 *  - sdk: the SDK PlatformClient on adminPage's session (the context's
 *    cookie jar, so the jwt cookie the server set).
 *  - tenant: the tenant the admin's session belongs to (its jwt tenant_id).
 *  - systemAdminPage: a page signed in as the system-tenant admin, for APIs
 *    only the system tenant may call (the proxy API). The node's admin is
 *    claimed through the admin claim ceremony (system-admin.ts) once per
 *    run; the bearer is persisted in the run directory and set as the jwt
 *    cookie of each test's context.
 *  - systemSdk: the SDK PlatformClient on systemAdminPage's session.
 *
 * The config seeds no tenant (platformd.test.yaml): the admin and its tenant
 * are created over the API here.
 */

export interface Tenant {
  id: string;
  name: string;
}

/** The harness admin of one worker: its passkey lives in the authenticator. */
export interface AdminAccount {
  email: string;
  authenticator: SoftAuthenticator;
}

interface WorkerFixtures {
  adminAccount: AdminAccount;
  systemAuthenticator: SoftAuthenticator;
}

interface TestFixtures {
  adminPage: Page;
  sdk: PlatformClient;
  tenant: Tenant;
  systemAdminPage: Page;
  systemSdk: PlatformClient;
}

/** The directory of the daemon global-setup started (its cwd). */
function runDir(): string {
  return (JSON.parse(readFileSync(stateFile(e2ePort()), 'utf8')) as ServerState).dir;
}

/** A context with the software authenticator answering every page of it. */
export async function authenticatedContext(
  context: BrowserContext,
  authenticator: SoftAuthenticator,
): Promise<BrowserContext> {
  await authenticator.install(context);
  return context;
}

/** The claims of the jwt session cookie of context. */
export async function sessionClaims(context: BrowserContext): Promise<Record<string, unknown>> {
  const jwt = (await context.cookies()).find((c) => c.name === 'jwt');
  if (!jwt) throw new Error('[real-server] no jwt session cookie');
  const payload = jwt.value.split('.')[1];
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<string, unknown>;
}

/** A fetch over a Playwright request context (its cookies, its TLS settings). */
export function requestFetch(request: APIRequestContext): typeof fetch {
  return async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => {
      headers[k] = v;
    });
    const body = init?.body;
    const res = await request.fetch(url, {
      method: init?.method ?? 'GET',
      headers,
      data: body == null ? undefined : typeof body === 'string' ? body : Buffer.from(await new Response(body).arrayBuffer()),
      failOnStatusCode: false,
      maxRedirects: 0,
    });
    const status = res.status();
    const noBody = status === 204 || status === 205 || status === 304 || init?.method === 'HEAD';
    return new Response(noBody ? null : new Uint8Array(await res.body()), { status, statusText: res.statusText(), headers: res.headers() });
  };
}

/** Registers email through the console form; resolves on /dashboard. */
async function registerAdmin(page: Page, email: string): Promise<void> {
  await page.goto('/auth/webauthn?status=not_registered');
  await page.getByPlaceholder('Enter your email').fill(email);
  await page.getByRole('button', { name: /register/i }).click();
  await expect(page).toHaveURL(/\/dashboard/, { timeout: 30_000 });
}

/** Logs in with the authenticator's passkey; resolves on /dashboard. */
async function loginAdmin(page: Page): Promise<void> {
  await page.goto('/auth/webauthn?status=registered');
  await page.getByRole('button', { name: /log in/i }).click();
  await expect(page).toHaveURL(/\/dashboard/, { timeout: 30_000 });
}

export const test = base.extend<TestFixtures, WorkerFixtures>({
  adminAccount: [
    async ({}, use, workerInfo) => {
      await use({
        email: `e2e-admin-w${workerInfo.workerIndex}-${Date.now().toString(36)}@example.com`,
        authenticator: new SoftAuthenticator(runAttestation()),
      });
    },
    { scope: 'worker' },
  ],

  systemAuthenticator: [
    async ({}, use) => {
      await use(new SoftAuthenticator(runAttestation()));
    },
    { scope: 'worker' },
  ],

  adminPage: async ({ browser, adminAccount, baseURL }, use) => {
    const context = await authenticatedContext(
      await browser.newContext({ baseURL, ignoreHTTPSErrors: true }),
      adminAccount.authenticator,
    );
    try {
      const page = await context.newPage();
      if (adminAccount.authenticator.count === 0) {
        await registerAdmin(page, adminAccount.email);
      } else {
        await loginAdmin(page);
      }
      await use(page);
    } finally {
      await context.close();
    }
  },

  sdk: async ({ adminPage, baseURL }, use) => {
    await use(
      new PlatformClient({
        baseUrl: new URL('/api', baseURL).href,
        fetch: requestFetch(adminPage.context().request),
        retry: { maxRetries: 0 },
      }),
    );
  },

  systemAdminPage: async ({ browser, systemAuthenticator, baseURL }, use) => {
    if (!baseURL) throw new Error('[real-server] no baseURL');
    const context = await browser.newContext({ baseURL, ignoreHTTPSErrors: true });
    try {
      const token = await claimSystemAdmin(context.request, runDir(), systemAuthenticator, new URL(baseURL).origin);
      // The cookie the server reads the session from (pkg/webservice/v1/jwt).
      await context.addCookies([{ name: 'jwt', value: token, url: baseURL }]);
      const page = await context.newPage();
      await page.goto('/dashboard');
      await use(page);
    } finally {
      await context.close();
    }
  },

  systemSdk: async ({ systemAdminPage, baseURL }, use) => {
    await use(
      new PlatformClient({
        baseUrl: new URL('/api', baseURL).href,
        fetch: requestFetch(systemAdminPage.context().request),
        retry: { maxRetries: 0 },
      }),
    );
  },

  tenant: async ({ adminPage, sdk }, use) => {
    const id = (await sessionClaims(adminPage.context())).tenant_id;
    if (typeof id !== 'string' || !id) throw new Error('[real-server] the admin session carries no tenant_id');
    const res = await sdk.tenant.getTenant(id);
    if (!res.success || !res.data) throw new Error(`[real-server] getTenant(${id}): ${JSON.stringify(res.error)}`);
    await use({ id, name: res.data.tenant.name });
  },
});

export { expect };
