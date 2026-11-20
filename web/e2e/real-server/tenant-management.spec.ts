import { test, expect } from './fixtures';

/**
 * Tenant management pages against the real server.
 *
 * Ported from web/e2e/tenant-management.spec.ts (#2037). Members are seeded
 * through sdk.iam.createUser and invitations through sdk.invitation.create;
 * every assertion reads what the harness server returns. Error-injection,
 * empty-state, expired/accepted invitation and non-owner role cases had no
 * server behaviour behind them and are listed as gaps in the PR body.
 */

const unique = (prefix: string): string =>
  `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function must<T>(res: { success: boolean; data?: T; error?: any }, what: string): T {
  if (!res.success || res.data === undefined) {
    throw new Error(`${what} failed: ${JSON.stringify(res.error)}`);
  }
  return res.data;
}

test.describe('Tenant Members Management (real server)', () => {
  test('lists a member seeded through the SDK', async ({ adminPage, sdk, tenant }) => {
    const email = `${unique('member')}@tenant-mgmt.test`;
    must(
      await sdk.iam.createUser({ tenantId: tenant.id, email, name: 'Seeded Member', roles: ['member'] }),
      'createUser',
    );

    await adminPage.goto('/tenant/members');

    await expect(adminPage.locator('h1').filter({ hasText: /Members/i })).toBeVisible();
    await expect(adminPage.getByText(email)).toBeVisible();
  });

  test('member count matches the server list', async ({ adminPage, sdk, tenant }) => {
    const list = must(await sdk.iam.listUsers({ tenantId: tenant.id, pageSize: 100 }), 'listUsers');
    const total: number = list.total ?? list.users?.length ?? 0;

    await adminPage.goto('/tenant/members');

    await expect(
      adminPage.getByText(new RegExp(`${total} members? in your tenant`, 'i')),
    ).toBeVisible();
  });

  test('search filters the seeded members', async ({ adminPage, sdk, tenant }) => {
    const tag = unique('srch');
    const alice = `alice-${tag}@tenant-mgmt.test`;
    const bob = `bob-${tag}@tenant-mgmt.test`;
    must(await sdk.iam.createUser({ tenantId: tenant.id, email: alice, name: `Alice ${tag}` }), 'createUser');
    must(await sdk.iam.createUser({ tenantId: tenant.id, email: bob, name: `Bob ${tag}` }), 'createUser');

    await adminPage.goto('/tenant/members');
    await expect(adminPage.getByText(alice)).toBeVisible();
    await expect(adminPage.getByText(bob)).toBeVisible();

    await adminPage.getByRole('textbox', { name: 'Search members...' }).fill(`Alice ${tag}`);

    await expect(adminPage.getByText(alice)).toBeVisible();
    await expect(adminPage.getByText(bob)).not.toBeVisible();
  });

  test('removing a member deletes it on the server', async ({ adminPage, sdk, tenant }) => {
    const email = `${unique('remove')}@tenant-mgmt.test`;
    must(await sdk.iam.createUser({ tenantId: tenant.id, email, name: 'Remove Me' }), 'createUser');

    await adminPage.goto('/tenant/members');
    const row = adminPage.getByRole('row').filter({ hasText: email });
    await expect(row).toBeVisible();
    await row.getByRole('button', { name: /open menu/i }).click();
    await adminPage.getByRole('menuitem', { name: /remove member/i }).click();

    await expect(adminPage.getByText(/member removed/i).first()).toBeVisible();

    await expect
      .poll(async () => {
        const res = await sdk.iam.listUsers({ tenantId: tenant.id, emailFilter: email });
        return (res.data?.users ?? []).some((u: { email: string }) => u.email === email);
      })
      .toBe(false);
  });

  test('shows the invite member button', async ({ adminPage }) => {
    await adminPage.goto('/tenant/members');
    await expect(adminPage.getByRole('button', { name: /invite member/i })).toBeVisible();
  });

  test('redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/tenant/members');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });
});

test.describe('Tenant Quotas Management (real server)', () => {
  test('displays the quota sections the server returns', async ({ adminPage, sdk, tenant }) => {
    must(await sdk.tenant.getQuotas(tenant.id), 'getQuotas');

    await adminPage.goto('/tenant/quotas');

    await expect(adminPage.getByRole('heading', { name: /resource quotas/i })).toBeVisible();
    await expect(adminPage.getByRole('heading', { name: /compute resources/i })).toBeVisible();
    await expect(adminPage.getByRole('heading', { name: /network resources/i })).toBeVisible();
    await expect(adminPage.getByRole('heading', { name: /storage resources/i })).toBeVisible();
  });

  test('displays usage summary cards', async ({ adminPage }) => {
    await adminPage.goto('/tenant/quotas');

    await expect(adminPage.getByText(/compute usage/i)).toBeVisible();
    await expect(adminPage.getByText(/network usage/i)).toBeVisible();
    await expect(adminPage.getByText(/storage usage/i)).toBeVisible();
  });

  test('a fresh tenant reports healthy usage', async ({ adminPage }) => {
    await adminPage.goto('/tenant/quotas');
    await expect(adminPage.getByText(/healthy/i).first()).toBeVisible();
  });

  test('has a refresh button', async ({ adminPage }) => {
    await adminPage.goto('/tenant/quotas');
    await expect(adminPage.getByRole('button', { name: /refresh/i })).toBeVisible();
  });

  test('redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/tenant/quotas');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });
});

test.describe('Tenant Invitations (real server)', () => {
  test('lists invitations seeded through the SDK', async ({ adminPage, sdk }) => {
    const tag = unique('inv');
    const first = `pending1-${tag}@tenant-mgmt.test`;
    const second = `pending2-${tag}@tenant-mgmt.test`;
    must(await sdk.invitation.create({ email: first, role: 'member' }), 'invitation.create');
    must(await sdk.invitation.create({ email: second, role: 'admin' }), 'invitation.create');

    await adminPage.goto('/tenant/invitations');

    await expect(adminPage.locator('h1').filter({ hasText: /invitations/i })).toBeVisible();
    await expect(adminPage.getByText(first)).toBeVisible();
    await expect(adminPage.getByText(second)).toBeVisible();
  });

  test('shows a pending badge and summary cards', async ({ adminPage, sdk }) => {
    const email = `${unique('badge')}@tenant-mgmt.test`;
    must(await sdk.invitation.create({ email, role: 'member' }), 'invitation.create');

    await adminPage.goto('/tenant/invitations');

    const row = adminPage.getByRole('row').filter({ hasText: email });
    await expect(row.getByText('Pending', { exact: true })).toBeVisible();
    await expect(adminPage.getByText(/total invitations/i)).toBeVisible();
  });

  test('cancelling an invitation revokes it on the server', async ({ adminPage, sdk }) => {
    const email = `${unique('cancel')}@tenant-mgmt.test`;
    const created = must(await sdk.invitation.create({ email, role: 'member' }), 'invitation.create');
    const id: string = created.invitation.id;

    await adminPage.goto('/tenant/invitations');
    const row = adminPage.getByRole('row').filter({ hasText: email });
    await row.getByRole('button', { name: /open menu/i }).click();
    await adminPage.getByRole('menuitem', { name: /cancel invitation/i }).click();

    await expect(adminPage.getByText(/invitation cancelled/i).first()).toBeVisible();

    await expect
      .poll(async () => {
        const res = await sdk.invitation.get(id);
        return res.data?.invitation?.status ?? 'missing';
      })
      .not.toBe('pending');
  });

  test('resending an invitation succeeds on the server', async ({ adminPage, sdk }) => {
    const email = `${unique('resend')}@tenant-mgmt.test`;
    must(await sdk.invitation.create({ email, role: 'member' }), 'invitation.create');

    await adminPage.goto('/tenant/invitations');
    const row = adminPage.getByRole('row').filter({ hasText: email });
    await row.getByRole('button', { name: /open menu/i }).click();
    await adminPage.getByRole('menuitem', { name: /resend invitation/i }).click();

    await expect(adminPage.getByText(/invitation resent/i).first()).toBeVisible();
  });

  test('shows the send invitation button', async ({ adminPage }) => {
    await adminPage.goto('/tenant/invitations');
    await expect(adminPage.getByRole('button', { name: /send invitation/i })).toBeVisible();
  });

  test('redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/tenant/invitations');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });
});

test.describe('Responsive Layout (real server)', () => {
  test('members page renders on mobile', async ({ adminPage, sdk, tenant }) => {
    const email = `${unique('mobile')}@tenant-mgmt.test`;
    must(await sdk.iam.createUser({ tenantId: tenant.id, email, name: 'Mobile Member' }), 'createUser');
    await adminPage.setViewportSize({ width: 375, height: 667 });

    await adminPage.goto('/tenant/members');

    await expect(adminPage.locator('h1').filter({ hasText: /members/i })).toBeVisible();
    await expect(adminPage.getByText(email)).toBeVisible();
  });

  test('quotas page renders on mobile', async ({ adminPage }) => {
    await adminPage.setViewportSize({ width: 375, height: 667 });
    await adminPage.goto('/tenant/quotas');
    await expect(adminPage.getByRole('heading', { name: /resource quotas/i })).toBeVisible();
  });

  test('invitations page renders on tablet', async ({ adminPage, sdk }) => {
    const email = `${unique('tablet')}@tenant-mgmt.test`;
    must(await sdk.invitation.create({ email, role: 'member' }), 'invitation.create');
    await adminPage.setViewportSize({ width: 768, height: 1024 });

    await adminPage.goto('/tenant/invitations');

    await expect(adminPage.locator('h1').filter({ hasText: /invitations/i })).toBeVisible();
    await expect(adminPage.getByText(email)).toBeVisible();
  });
});
