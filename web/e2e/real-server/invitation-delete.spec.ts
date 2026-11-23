/**
 * Invitation delete against the real-server harness (#2056, epic #1665): a
 * non-pending row on /tenant/invitations offers Delete Invitation, gated on
 * DELETE /api/v1/invitations/{id:[0-9]+}; after the confirm dialog it deletes
 * the invitation record through the SDK. Each test uses its own unique
 * example.com address; what the UI did is checked through the SDK.
 */
import { test, expect } from './fixtures';
import type { PlatformClient } from 'trusted-platform-sdk';

const DELETE_OP = 'DELETE /api/v1/invitations/{id:[0-9]+}';

interface Created {
  id: string;
  email: string;
}

function uniqueEmail(tag: string): string {
  return `inv-${tag}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}@example.com`;
}

async function createInvitation(sdk: PlatformClient, tag: string, role = 'admin'): Promise<Created> {
  const email = uniqueEmail(tag);
  const res = await sdk.invitation.create({ email, role });
  const err: unknown = res.error;
  if (!res.success || !res.data) throw new Error(`[real-server] invitation.create: ${JSON.stringify(err)}`);
  return { id: res.data.invitation.id, email };
}

/** The status the server reports for an invitation, as a string. */
async function statusOf(sdk: PlatformClient, id: string): Promise<string> {
  const res = await sdk.invitation.get(id);
  return String(res.data?.invitation.status ?? '');
}

/** A revoked invitation, created and revoked through the SDK. */
async function revokedInvitation(sdk: PlatformClient, tag: string): Promise<Created> {
  const inv = await createInvitation(sdk, tag);
  await sdk.invitation.revoke(inv.id);
  await expect.poll(() => statusOf(sdk, inv.id)).toMatch(/revoked|cancelled/i);
  return inv;
}

/** Whether the server still finds the invitation; a lookup error counts as gone. */
async function exists(sdk: PlatformClient, id: string): Promise<boolean> {
  try {
    return (await sdk.invitation.get(id)).success;
  } catch {
    return false;
  }
}

test.describe('Invitation delete', () => {
  test('Delete Invitation removes a revoked invitation', async ({ adminPage, sdk }) => {
    const inv = await revokedInvitation(sdk, 'list-delete');
    await adminPage.goto('/tenant/invitations');
    const row = adminPage.getByRole('row').filter({ hasText: inv.email });
    await expect(row).toBeVisible();
    await row.getByRole('button', { name: 'Open menu' }).click();
    adminPage.once('dialog', (d) => void d.accept());
    await adminPage.getByRole('menuitem', { name: 'Delete Invitation' }).click();

    await expect.poll(() => exists(sdk, inv.id)).toBe(false);
  });

  test('Delete Invitation is gated on the DELETE route', async ({ adminPage, sdk }) => {
    const inv = await revokedInvitation(sdk, 'delete-gate');
    try {
      await adminPage.goto('/tenant/invitations');
      const row = adminPage.getByRole('row').filter({ hasText: inv.email });
      await expect(row).toBeVisible();
      await row.getByRole('button', { name: 'Open menu' }).click();
      const item = adminPage.getByRole('menuitem', { name: 'Delete Invitation' });
      await expect(item).toHaveAttribute('data-capability-op', DELETE_OP);
      await expect(item).toHaveAttribute('data-capability-enabled', 'true');
    } finally {
      await sdk.invitation.delete(inv.id);
    }
  });

  test('Delete Invitation on the detail page removes a revoked invitation', async ({ adminPage, sdk }) => {
    const inv = await revokedInvitation(sdk, 'detail-delete');
    await adminPage.goto(`/tenant/invitations/${encodeURIComponent(inv.id)}/`);
    await expect(adminPage.getByTestId('invitation-status')).toHaveText('Revoked');
    adminPage.once('dialog', (d) => void d.accept());
    await adminPage.getByRole('button', { name: 'Delete Invitation' }).click();

    await expect(adminPage).toHaveURL(/\/tenant\/invitations\/?$/);
    await expect.poll(() => exists(sdk, inv.id)).toBe(false);
  });
});
