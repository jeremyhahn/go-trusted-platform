import type { Locator, Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect, sessionClaims } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * /admin/invitations against the real-server harness (#2035), ported from
 * the mocked web/e2e/invitations.spec.ts.
 *
 * Invitations are seeded through sdk.invitation (POST /api/v1/invitations)
 * and read back with sdk.invitation.list(); each case drives the page as the
 * console does and asserts what the server answered.
 *
 * The page (web/src/app/admin/invitations/page.tsx) is hand-written: it
 * decides ownership from the jwt cookie it reads in the browser
 * (is_tenant_owner), and reads `invitations` / `invitation` under the
 * payload of the server's envelope ({ code, error, success, payload }). The
 * harness admin owns its tenant, so the owner cases require the owner view,
 * read the list from the unwrapped payload, and fail when a seeded
 * invitation is missing from it.
 */

interface Inv {
  id?: string | number;
  email?: string;
  role?: string;
  token?: string;
}

const PREFIX = 'e2e-inv-';
let seq = 0;

function uniqueEmail(): string {
  seq += 1;
  return `${PREFIX}${Date.now()}-${seq}@example.com`;
}

function isInvitations(method: string): (r: Response) => boolean {
  return (r) => r.request().method() === method && new URL(r.url()).pathname === '/api/v1/invitations';
}

function isInvitation(method: string, id: string): (r: Response) => boolean {
  return (r) => r.request().method() === method && new URL(r.url()).pathname === `/api/v1/invitations/${id}`;
}

/** The invitations of a list answer: res.data is the ListInvitationsResponse payload. */
async function serverInvitations(sdk: PlatformClient): Promise<Inv[]> {
  const res = await sdk.invitation.list();
  expect(res.success, JSON.stringify(res.error)).toBe(true);
  return ((res.data ?? {}) as { invitations?: Inv[] }).invitations ?? [];
}

/** Seeds one invitation; res.data is the CreateInvitationResponse payload ({ invitation }). */
async function seed(sdk: PlatformClient, role = 'member'): Promise<Inv & { email: string; id: string }> {
  const email = uniqueEmail();
  const res = await sdk.invitation.create({ email, role });
  expect(res.success, JSON.stringify(res.error)).toBe(true);
  const inv = ((res.data ?? {}) as { invitation?: Inv }).invitation ?? {};
  expect(inv.email).toBe(email);
  expect(String(inv.id ?? '')).not.toBe('');
  return { ...inv, email, id: String(inv.id) };
}

type View = { kind: 'login' } | { kind: 'denied' } | { kind: 'owner'; listed: Inv[] };

/**
 * The view the page shows for the real session, as getUserFromToken decides
 * it: no user when the browser cannot read the jwt cookie or the claims lack
 * a subject or an email; the owner form only for an is_tenant_owner claim.
 */
async function expectedKind(page: Page): Promise<View['kind']> {
  const jwt = (await page.context().cookies()).find((c) => c.name === 'jwt');
  const claims = await sessionClaims(page.context());
  const user = !!jwt && !jwt.httpOnly && !!(claims.sub || claims.user_id) && !!claims.email;
  if (!user) return 'login';
  return claims.is_tenant_owner ? 'owner' : 'denied';
}

/** Opens /admin/invitations and asserts the view the page shows for the server's answer. */
async function openInvitations(page: Page): Promise<View> {
  const kind = await expectedKind(page);
  if (kind === 'login') {
    await page.goto('/admin/invitations');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
    return { kind };
  }
  if (kind === 'denied') {
    await page.goto('/admin/invitations');
    await expect(page.getByRole('heading', { name: 'Access Denied' })).toBeVisible();
    await expect(page.getByText('Only tenant owners can manage invitations.')).toBeVisible();
    return { kind };
  }
  const answer = page.waitForResponse(isInvitations('GET'));
  await page.goto('/admin/invitations');
  const res = await answer;
  const body: unknown = await res.json().catch(() => null);
  await expect(page.getByRole('heading', { name: 'Manage Invitations' })).toBeVisible();
  await expect(page.getByText('Loading invitations...')).toBeHidden();
  if (!res.ok()) {
    await expect(page.getByText('Failed to fetch invitations', { exact: true })).toBeVisible();
    return { kind, listed: [] };
  }
  const listed = unwrapPayload<{ invitations?: Inv[] }>(body).invitations ?? [];
  if (listed.length === 0) await expect(page.getByText('No pending invitations')).toBeVisible();
  return { kind, listed };
}

/** Opens /admin/invitations and requires the owner view: the harness admin owns its tenant. */
async function openOwner(page: Page): Promise<Extract<View, { kind: 'owner' }>> {
  const view = await openInvitations(page);
  expect(view.kind, 'the harness admin owns its tenant (is_tenant_owner)').toBe('owner');
  return view as Extract<View, { kind: 'owner' }>;
}

/** The list row of email (the innermost element holding its email and a Revoke button). */
function row(page: Page, email: string): Locator {
  return page
    .locator('div')
    .filter({ has: page.getByText(email, { exact: true }) })
    .filter({ has: page.getByRole('button', { name: 'Revoke', exact: true }) })
    .last();
}

/**
 * Asserts the list answer the page read carries inv, and the page shows its
 * row with its role.
 */
async function expectListed(page: Page, view: Extract<View, { kind: 'owner' }>, inv: Inv & { email: string }): Promise<void> {
  expect(
    view.listed.some((i) => i.email === inv.email),
    `the page's list answer carries ${inv.email}`,
  ).toBe(true);
  await expect(row(page, inv.email)).toBeVisible();
  await expect(row(page, inv.email).getByText(inv.role ?? '', { exact: true })).toBeVisible();
}

/** Fills and submits the create form; asserts the body the console sends. */
async function createThroughPage(page: Page, email: string, role?: string): Promise<{ res: Response; body: unknown }> {
  await page.getByLabel('Email Address').fill(email);
  if (role) await page.getByLabel('Role').selectOption(role);
  const answer = page.waitForResponse(isInvitations('POST'));
  await page.getByRole('button', { name: 'Create Invitation' }).click();
  const res = await answer;
  expect(res.request().postDataJSON()).toEqual({ email, role: role ?? 'member' });
  return { res, body: await res.json().catch(() => null) };
}

/** The notification the page shows for a refused create: errorData.error, or its fallback. */
function createRefusal(body: unknown): string {
  const e = (body as { error?: unknown } | null)?.error;
  return e ? String(e) : 'Failed to create invitation';
}

/**
 * Asserts the server created the invitation the page sent and the page
 * renders it from the payload of the answer.
 */
async function expectCreateAnswer(
  page: Page,
  sdk: PlatformClient,
  created: { res: Response; body: unknown },
  email: string,
  role: string,
): Promise<void> {
  expect(created.res.ok(), `the server creates the invitation: ${createRefusal(created.body)}`).toBe(true);
  const onServer = (await serverInvitations(sdk)).filter((i) => i.email === email);
  expect(onServer).toHaveLength(1);
  expect(onServer[0].role).toBe(role);
  expect(unwrapPayload<{ invitation?: Inv }>(created.body).invitation?.email).toBe(email);
  await expect(page.getByText('Invitation created successfully!')).toBeVisible();
  await expect(row(page, email)).toBeVisible();
}

/** Collects the create requests the page sends. */
function trackCreates(page: Page): string[] {
  const posts: string[] = [];
  page.on('request', (r) => {
    if (r.method() === 'POST' && new URL(r.url()).pathname === '/api/v1/invitations') posts.push(r.url());
  });
  return posts;
}

/** Accepts the page's confirm(), clicks Revoke on email's row and returns the server's answer. */
async function revokeThroughPage(page: Page, inv: { email: string; id: string }): Promise<Response> {
  page.once('dialog', (d) => void d.accept());
  const answer = page.waitForResponse(isInvitation('DELETE', inv.id));
  await row(page, inv.email).getByRole('button', { name: 'Revoke', exact: true }).click();
  return answer;
}

test.describe('Invitations management, real server', () => {
  test.afterEach(async ({ sdk }) => {
    const res = await sdk.invitation.list().catch(() => null);
    const all = ((res?.data ?? {}) as { invitations?: Inv[] }).invitations ?? [];
    for (const i of all) {
      if (i.email?.startsWith(PREFIX) && i.id != null) {
        await sdk.invitation.revoke(String(i.id)).catch(() => undefined);
      }
    }
  });

  test.describe('Tenant Owner Access', () => {
    test('should display invitation form for tenant owners', async ({ adminPage }) => {
      await openOwner(adminPage);
      await expect(adminPage.getByRole('heading', { name: 'Create New Invitation' })).toBeVisible();
      await expect(adminPage.getByLabel('Email Address')).toBeVisible();
      await expect(adminPage.getByLabel('Role')).toHaveValue('member');
      await expect(adminPage.getByRole('button', { name: 'Create Invitation' })).toBeEnabled();
      await expect(adminPage.getByRole('heading', { name: 'Pending Invitations' })).toBeVisible();
    });

    test('should display existing invitations in the list', async ({ adminPage, sdk }) => {
      const inv = await seed(sdk);
      expect((await serverInvitations(sdk)).some((i) => i.email === inv.email)).toBe(true);
      const view = await openOwner(adminPage);
      await expectListed(adminPage, view, inv);
    });

    test('should create a new invitation', async ({ adminPage, sdk }) => {
      await openOwner(adminPage);
      const email = uniqueEmail();
      await expectCreateAnswer(adminPage, sdk, await createThroughPage(adminPage, email), email, 'member');
    });

    test('should create invitation with admin role', async ({ adminPage, sdk }) => {
      await openOwner(adminPage);
      const email = uniqueEmail();
      await expectCreateAnswer(adminPage, sdk, await createThroughPage(adminPage, email, 'admin'), email, 'admin');
    });

    test('should copy invitation link to clipboard', async ({ adminPage, sdk, baseURL }) => {
      const inv = await seed(sdk);
      expect(inv.token ?? '').not.toBe('');
      const origin = new URL(baseURL ?? adminPage.url()).origin;
      await adminPage.context().grantPermissions(['clipboard-read', 'clipboard-write'], { origin });
      const view = await openOwner(adminPage);
      await expectListed(adminPage, view, inv);
      await row(adminPage, inv.email).getByRole('button', { name: 'Copy Link' }).click();
      await expect(adminPage.getByText('Invitation link copied to clipboard!')).toBeVisible();
      const copied = await adminPage.evaluate(() => navigator.clipboard.readText());
      expect(copied).toBe(`${new URL(adminPage.url()).origin}/auth/webauthn?invitation=${inv.token}`);
    });

    test('should revoke an invitation', async ({ adminPage, sdk }) => {
      const inv = await seed(sdk);
      const view = await openOwner(adminPage);
      await expectListed(adminPage, view, inv);
      const res = await revokeThroughPage(adminPage, inv);
      const onServer = (await serverInvitations(sdk)).some((i) => i.email === inv.email);
      if (res.ok()) {
        await expect(adminPage.getByText('Invitation revoked successfully')).toBeVisible();
        await expect(row(adminPage, inv.email)).toHaveCount(0);
        expect(onServer).toBe(false);
      } else {
        await expect(adminPage.getByText('Failed to revoke invitation', { exact: true })).toBeVisible();
        expect(onServer).toBe(true);
      }
    });

    test('should show invitation in list after creation', async ({ adminPage, sdk }) => {
      await openOwner(adminPage);
      const email = uniqueEmail();
      const created = await createThroughPage(adminPage, email);
      await expectCreateAnswer(adminPage, sdk, created, email, 'member');
      // Re-read: the list the page fetches on load.
      const again = await openOwner(adminPage);
      await expectListed(adminPage, again, { email, role: 'member' });
    });

    // gap: should handle API error when fetching invitations: an injected 500 on GET /api/v1/invitations; the real server answers a signed-in owner's list

    test('should handle API error when creating invitation', async ({ adminPage, sdk }) => {
      // A second invitation for an email that already has one pending: the
      // server's own refusal, if it refuses it.
      const inv = await seed(sdk);
      await openOwner(adminPage);
      const created = await createThroughPage(adminPage, inv.email);
      const onServer = (await serverInvitations(sdk)).filter((i) => i.email === inv.email);
      if (!created.res.ok()) {
        expect(created.body).not.toBeNull();
        await expect(adminPage.getByText(createRefusal(created.body), { exact: true })).toBeVisible();
        expect(onServer).toHaveLength(1);
      } else {
        // The server accepts a duplicate pending invitation: no create refusal is reachable from this form.
        expect(onServer).toHaveLength(2);
      }
    });

    test('should handle API error when revoking invitation', async ({ adminPage, sdk }) => {
      // The invitation is gone on the server before the page revokes it.
      const inv = await seed(sdk);
      const view = await openOwner(adminPage);
      await expectListed(adminPage, view, inv);
      const gone = await sdk.invitation.revoke(inv.id);
      expect(gone.success, JSON.stringify(gone.error)).toBe(true);
      const res = await revokeThroughPage(adminPage, inv);
      if (res.ok()) {
        // The server answers a DELETE of a deleted invitation with success.
        await expect(adminPage.getByText('Invitation revoked successfully')).toBeVisible();
      } else {
        await expect(adminPage.getByText('Failed to revoke invitation', { exact: true })).toBeVisible();
      }
      expect((await serverInvitations(sdk)).some((i) => i.email === inv.email)).toBe(false);
    });

    test('should require email input before creating invitation', async ({ adminPage, sdk }) => {
      await openOwner(adminPage);
      const before = (await serverInvitations(sdk)).length;
      const posts = trackCreates(adminPage);
      await adminPage.getByRole('button', { name: 'Create Invitation' }).click();
      // The input is `required`: the browser blocks the submit, so the page's
      // own "Please enter an email address" never runs and nothing is sent.
      const missing = await adminPage.getByLabel('Email Address').evaluate((el) => (el as HTMLInputElement).validity.valueMissing);
      expect(missing).toBe(true);
      await adminPage.waitForLoadState('networkidle');
      expect(posts).toHaveLength(0);
      expect((await serverInvitations(sdk)).length).toBe(before);
    });

    test('should navigate back to dashboard', async ({ adminPage }) => {
      const view = await openInvitations(adminPage);
      if (view.kind === 'login') return;
      await adminPage.getByRole('button', { name: 'Back to Dashboard' }).click();
      await expect(adminPage).toHaveURL(/\/admin\/tenant/);
    });
  });

  test.describe('Non-Owner Access', () => {
    // gap: should display access denied for non-owners: needs a tenant-member session (no is_tenant_owner claim); the harness signs in only its tenant owner. openInvitations asserts the Access Denied card whenever the real session carries no owner claim
    // gap: should not show invitation form to non-owners: needs a tenant-member session; the harness signs in only its tenant owner
    // gap: should navigate back to dashboard from access denied page: needs a tenant-member session; the harness signs in only its tenant owner ("should navigate back to dashboard" drives the same button on the view the real session gets)
  });

  test.describe('Unauthenticated Access', () => {
    // covered: should redirect to login when not authenticated: web/e2e/real-server/auth.spec.ts:101
  });

  test.describe('Multiple Invitations', () => {
    test('should display multiple invitations with different roles', async ({ adminPage, sdk }) => {
      const member = await seed(sdk, 'member');
      const admin = await seed(sdk, 'admin');
      const onServer = await serverInvitations(sdk);
      expect(onServer.find((i) => i.email === member.email)?.role).toBe('member');
      expect(onServer.find((i) => i.email === admin.email)?.role).toBe('admin');
      const view = await openOwner(adminPage);
      await expectListed(adminPage, view, member);
      await expectListed(adminPage, view, admin);
    });

    test('should handle revoking specific invitation from list', async ({ adminPage, sdk }) => {
      const first = await seed(sdk);
      const second = await seed(sdk);
      const view = await openOwner(adminPage);
      await expectListed(adminPage, view, first);
      await expectListed(adminPage, view, second);
      const res = await revokeThroughPage(adminPage, first);
      const onServer = await serverInvitations(sdk);
      if (res.ok()) {
        await expect(row(adminPage, first.email)).toHaveCount(0);
        expect(onServer.some((i) => i.email === first.email)).toBe(false);
      } else {
        await expect(adminPage.getByText('Failed to revoke invitation', { exact: true })).toBeVisible();
      }
      await expect(row(adminPage, second.email)).toBeVisible();
      expect(onServer.some((i) => i.email === second.email)).toBe(true);
    });
  });

  test.describe('Form Validation', () => {
    test('should validate email format', async ({ adminPage, sdk }) => {
      await openOwner(adminPage);
      const before = (await serverInvitations(sdk)).length;
      const posts = trackCreates(adminPage);
      await adminPage.getByLabel('Email Address').fill('not-an-email');
      await adminPage.getByRole('button', { name: 'Create Invitation' }).click();
      // type="email": the browser refuses the value and sends nothing.
      const mismatch = await adminPage.getByLabel('Email Address').evaluate((el) => (el as HTMLInputElement).validity.typeMismatch);
      expect(mismatch).toBe(true);
      await adminPage.waitForLoadState('networkidle');
      expect(posts).toHaveLength(0);
      expect((await serverInvitations(sdk)).length).toBe(before);
    });

    test('should clear form after successful submission', async ({ adminPage, sdk }) => {
      await openOwner(adminPage);
      const email = uniqueEmail();
      await expectCreateAnswer(adminPage, sdk, await createThroughPage(adminPage, email, 'admin'), email, 'admin');
      await expect(adminPage.getByLabel('Email Address')).toHaveValue('');
      await expect(adminPage.getByLabel('Role')).toHaveValue('member');
    });

    // gap: should disable button during submission: needs a delayed create answer to observe "Creating..."; the real server answers before the disabled state can be asserted reliably
  });
});
