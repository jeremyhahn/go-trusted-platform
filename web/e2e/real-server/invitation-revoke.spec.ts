/**
 * Invitation send and revoke against the real-server harness (#2056, epic
 * #1665): the list page's Send Invitation creates a pending invitation, the
 * row's Cancel Invitation revokes one, and the detail page's Revoke revokes
 * one. Each test uses its own unique example.com address; what the UI did is
 * checked through the SDK.
 */
import { test, expect } from './fixtures';
import type { PlatformClient } from 'trusted-platform-sdk';

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

test.describe('Invitation send and revoke', () => {
  test('Send Invitation creates a pending invitation', async ({ adminPage, sdk }) => {
    const email = uniqueEmail('send');
    let id: string | undefined;
    try {
      await adminPage.goto('/tenant/invitations');
      await adminPage.getByRole('button', { name: 'Send Invitation' }).first().click();
      const dialog = adminPage.getByRole('dialog');
      await expect(dialog).toBeVisible();
      await dialog.getByLabel('Email Address').fill(email);
      await dialog.getByRole('button', { name: 'Send Invitation' }).click();
      await expect(dialog).toBeHidden();

      await expect
        .poll(async () => {
          const res = await sdk.invitation.list({ email });
          const found = res.data?.invitations.find((inv) => inv.email === email);
          id = found?.id;
          return String(found?.status ?? '');
        })
        .toMatch(/pending/i);
    } finally {
      if (id) await sdk.invitation.revoke(id);
    }
  });

  test('Cancel Invitation revokes it from the list', async ({ adminPage, sdk }) => {
    const inv = await createInvitation(sdk, 'list-cancel');
    await adminPage.goto('/tenant/invitations');
    const row = adminPage.getByRole('row').filter({ hasText: inv.email });
    await expect(row).toBeVisible();
    await row.getByRole('button', { name: 'Open menu' }).click();
    adminPage.once('dialog', (d) => void d.accept());
    await adminPage.getByRole('menuitem', { name: 'Cancel Invitation' }).click();

    await expect.poll(() => statusOf(sdk, inv.id)).toMatch(/revoked|cancelled/i);
  });

  test('Revoke on the detail page revokes it', async ({ adminPage, sdk }) => {
    const inv = await createInvitation(sdk, 'detail-revoke');
    await adminPage.goto(`/tenant/invitations/${encodeURIComponent(inv.id)}/`);
    await expect(adminPage.getByTestId('invitation-status')).toHaveText('Pending');
    adminPage.once('dialog', (d) => void d.accept());
    await adminPage.getByRole('button', { name: 'Revoke' }).click();

    await expect(adminPage.getByTestId('invitation-status')).toHaveText('Revoked');
    await expect.poll(() => statusOf(sdk, inv.id)).toMatch(/revoked|cancelled/i);
  });
});
