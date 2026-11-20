import type { Page, Response } from '@playwright/test';
import { test, expect } from './fixtures';

/**
 * BMC users and web certificate pages (#1720, slice 3 of #1665), against the
 * real-server harness (#2035).
 *
 * The page lists the user slots the server returns for a profile. The
 * harness has no BMC behind any profile, so the listing answers what the
 * server says for an unreachable BMC; each case asserts the page renders
 * that answer. Cases that need a reachable BMC (create, delete, password,
 * privilege, certificate replace) are gaps in the PR body.
 */

const PROFILE = '7';

function isUsersList(r: Response): boolean {
  return r.request().method() === 'GET' && new URL(r.url()).pathname.endsWith(`/api/v1/bmc/${PROFILE}/users`);
}

async function gotoUsersPage(page: Page): Promise<Response> {
  const listing = page.waitForResponse(isUsersList);
  await page.goto('/devices/bmc/__placeholder__/users/');
  await page.getByText('Loading users...').waitFor();
  await page.waitForLoadState('networkidle');
  await page.evaluate((id) => window.history.pushState(null, '', `/devices/bmc/${id}/users/`), PROFILE);
  return listing;
}

test.describe('BMC users and web certificate, real server', () => {
  test('ListUsers: the page shows the slots the server listed, and Create User only after a listing', async ({ adminPage, sdk }) => {
    const res = await gotoUsersPage(adminPage);
    const create = adminPage.getByRole('button', { name: 'Create User' });

    if (res.ok()) {
      const listed = await sdk.bmc.listUsers(PROFILE);
      for (const user of listed.data ?? []) {
        await expect(adminPage.getByTestId(`bmc-user-${user.slot}`)).toContainText(user.username);
      }
      await expect(create).toBeEnabled();
    } else {
      // A failed listing must not read as "every slot is free".
      await expect(adminPage.getByText('No users found')).toBeVisible();
      await expect(create).toBeDisabled();
    }
  });

  test('a failed listing sends no create', async ({ adminPage }) => {
    const posts: string[] = [];
    adminPage.on('request', (r) => {
      if (r.method() === 'POST' && new URL(r.url()).pathname.endsWith(`/api/v1/bmc/${PROFILE}/users`)) posts.push(r.url());
    });
    const res = await gotoUsersPage(adminPage);
    test.skip(res.ok(), 'the harness answered the listing; this case is about a failed one');
    await expect(adminPage.getByRole('button', { name: 'Create User' })).toBeDisabled();
    expect(posts).toEqual([]);
  });

  test('BMC entry page links a profile to its users page', async ({ adminPage }) => {
    await adminPage.goto('/devices/bmc/');
    await adminPage.getByLabel('Profile ID').fill(PROFILE);
    await adminPage.getByRole('button', { name: 'Open Users' }).click();
    await expect(adminPage).toHaveURL(new RegExp(`/devices/bmc/${PROFILE}/users`));
  });
});
