import { test as base, Page, BrowserContext, CDPSession } from '@playwright/test';

/**
 * Test fixtures for authentication
 *
 * Provides authenticated page context for tests that require login.
 */

export interface AuthFixtures {
  /** Page with authentication cookie set */
  authenticatedPage: Page;
  /** Set up virtual authenticator for WebAuthn testing */
  setupVirtualAuthenticator: (page: Page) => Promise<{ cdpSession: CDPSession; authenticatorId: string }>;
  /** Clean up virtual authenticator */
  cleanupVirtualAuthenticator: (cdpSession: CDPSession, authenticatorId: string) => Promise<void>;
}

/**
 * Create a mock JWT token for testing
 * This simulates what the backend would return after successful WebAuthn authentication
 */
function createMockJWT(): string {
  // Mock JWT structure - in real tests this would come from the backend
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      sub: 'test-user-id',
      username: 'testuser',
      email: 'testuser@platform.local',
      tenant_id: 'test-tenant-id',
      roles: ['admin', 'user'],
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
    })
  ).toString('base64url');
  const signature = 'mock-signature';

  return `${header}.${payload}.${signature}`;
}

/**
 * Extended test with authentication fixtures
 */
export const test = base.extend<AuthFixtures>({
  /**
   * Provides a page with authentication cookie pre-set
   * Use this for tests that need to access protected routes
   */
  authenticatedPage: async ({ page, context }, use) => {
    // Set the JWT cookie before navigating
    // IMPORTANT: httpOnly must be false so that frontend JS can read it
    await context.addCookies([
      {
        name: 'jwt',
        value: createMockJWT(),
        domain: 'localhost',
        path: '/',
        httpOnly: false,  // Must be false for frontend JS to read tenant_id
        secure: false,
        sameSite: 'Lax',
      },
    ]);

    await use(page);
  },

  /**
   * Set up a virtual authenticator for WebAuthn testing
   * Only works with Chromium
   */
  setupVirtualAuthenticator: async ({ }, use) => {
    const setup = async (page: Page) => {
      // Only works with Chromium
      if (page.context().browser()?.browserType().name() !== 'chromium') {
        throw new Error('Virtual authenticator only works with Chromium');
      }

      // Create CDP session for virtual authenticator
      const cdpSession = await page.context().newCDPSession(page);

      // Enable virtual authenticator environment
      await cdpSession.send('WebAuthn.enable');

      // Add virtual authenticator with platform authenticator capabilities
      const result = await cdpSession.send('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          transport: 'internal',
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
        },
      });

      return { cdpSession, authenticatorId: result.authenticatorId };
    };

    await use(setup);
  },

  /**
   * Clean up virtual authenticator
   */
  cleanupVirtualAuthenticator: async ({ }, use) => {
    const cleanup = async (cdpSession: CDPSession, authenticatorId: string) => {
      try {
        await cdpSession.send('WebAuthn.removeVirtualAuthenticator', {
          authenticatorId,
        });
        await cdpSession.send('WebAuthn.disable');
      } catch {
        // Ignore cleanup errors
      }
    };

    await use(cleanup);
  },
});

export { expect } from '@playwright/test';
