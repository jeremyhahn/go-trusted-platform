/**
 * API routes regression spec.
 *
 * Visits every WebUI page and asserts the platformd never returns the
 * "the requested API endpoint does not exist" envelope. This catches
 * unwired or mis-mounted REST routes the moment a page calls them.
 *
 * The spec runs against a real platformd backend (set BACKEND_URL).
 * Authenticated pages require a session cookie; supply one via the
 * E2E_SESSION_COOKIE env var, otherwise tests are skipped.
 */

import { test, expect, Page, Response, Request } from '@playwright/test';

const NOT_FOUND_MESSAGE = 'the requested API endpoint does not exist';

// All WebUI page paths that exercise REST endpoints.
const PAGES: { path: string; auth: boolean }[] = [
  { path: '/auth/webauthn', auth: false },
  { path: '/auth/login', auth: false },
  { path: '/', auth: true },
  { path: '/devices', auth: true },
  { path: '/devices/templates', auth: true },
  { path: '/devices/idevid', auth: true },
  { path: '/devices/vtpm', auth: true },
  { path: '/ca/certificates', auth: true },
  { path: '/ca/requests', auth: true },
  { path: '/attestation/manifests', auth: true },
  { path: '/attestation/quotes', auth: true },
  { path: '/attestation/eventlogs', auth: true },
  { path: '/attestation/verify', auth: true },
  { path: '/networking/dns', auth: true },
  { path: '/platform/health', auth: true },
  { path: '/platform/services', auth: true },
  { path: '/platform/events', auth: true },
  { path: '/platform/logs', auth: true },
  { path: '/provisioning/sessions', auth: true },
  { path: '/admin/invitations', auth: true },
  { path: '/admin/tenant', auth: true },
  { path: '/account', auth: true },
];

interface BadRoute {
  url: string;
  method: string;
  status: number;
  body: string;
}

async function captureNotFoundEnvelopes(page: Page): Promise<BadRoute[]> {
  const bad: BadRoute[] = [];
  page.on('response', async (resp: Response) => {
    if (resp.status() !== 404) return;
    const req: Request = resp.request();
    if (!req.url().includes('/api/')) return;
    let body = '';
    try {
      body = await resp.text();
    } catch {
      return;
    }
    if (body.includes(NOT_FOUND_MESSAGE)) {
      bad.push({ url: req.url(), method: req.method(), status: resp.status(), body });
    }
  });
  return bad;
}

const sessionCookie = process.env.E2E_SESSION_COOKIE;

test.describe('REST routes regression', () => {
  for (const page of PAGES) {
    test(`page ${page.path} does not trigger unregistered-endpoint envelopes`, async ({
      page: pwPage,
      context,
    }) => {
      if (page.auth && !sessionCookie) {
        test.skip(true, 'authenticated page requires E2E_SESSION_COOKIE');
      }
      if (page.auth && sessionCookie) {
        const url = new URL(process.env.BACKEND_URL || 'http://localhost:3000');
        await context.addCookies([
          {
            name: 'session',
            value: sessionCookie,
            domain: url.hostname,
            path: '/',
            httpOnly: true,
            sameSite: 'Lax',
          },
        ]);
      }
      const bad = await captureNotFoundEnvelopes(pwPage);
      const target = process.env.BACKEND_URL
        ? `${process.env.BACKEND_URL}${page.path}`
        : page.path;
      const resp = await pwPage.goto(target, { waitUntil: 'networkidle' });
      // Guard: navigation may legitimately redirect (e.g. unauth → login).
      if (resp) {
        expect(resp.status(), `navigation to ${page.path}`).toBeLessThan(500);
      }
      // Give SPA queries a beat to settle, then assert no unregistered routes.
      await pwPage.waitForTimeout(500);
      expect(bad, `unregistered REST endpoints hit by ${page.path}: ${JSON.stringify(bad, null, 2)}`).toHaveLength(0);
    });
  }
});
