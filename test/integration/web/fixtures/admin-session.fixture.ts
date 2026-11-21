/**
 * Server-issued admin session for real-server specs.
 *
 * The mock JWT in auth.fixture.ts carries a fake signature, so a real server
 * rejects it and a spec that only checks "some answer" passes on the 401.
 * This fixture takes a token the server itself issued (E2E_ADMIN_JWT, exported
 * by the runner that starts the server) and sets it as the session cookie.
 * Without that token the test is skipped rather than run unauthenticated.
 */
import { test as base, Page } from '@playwright/test';

export interface AdminSessionFixtures {
  /** Page with a server-issued admin session cookie set */
  adminPage: Page;
}

export const test = base.extend<AdminSessionFixtures>({
  adminPage: async ({ page, context, baseURL }, use, testInfo) => {
    const token = process.env.E2E_ADMIN_JWT ?? '';
    testInfo.skip(token === '', 'E2E_ADMIN_JWT is not set: no server-issued admin session');
    const url = new URL(baseURL ?? 'http://localhost:3000');
    await context.addCookies([
      {
        name: 'jwt',
        value: token,
        domain: url.hostname,
        path: '/',
        httpOnly: false,
        secure: url.protocol === 'https:',
        sameSite: 'Lax',
      },
    ]);
    await use(page);
  },
});

export { expect } from '@playwright/test';
