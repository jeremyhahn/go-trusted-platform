/**
 * A server-issued admin session for real-server specs (#2059).
 *
 * The runner signs in an admin against the server under test and exports the
 * session JWT as E2E_ADMIN_JWT. No token is minted or forged here: the fixture
 * only sets that JWT as the `jwt` cookie the webservice reads. Specs that use
 * `adminPage` skip when E2E_ADMIN_JWT is unset.
 */
import { test as base, Page } from '@playwright/test';

export interface AdminSessionFixtures {
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
