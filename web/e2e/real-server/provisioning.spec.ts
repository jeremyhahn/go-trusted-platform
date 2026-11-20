/**
 * Provisioning sessions page against the real-server harness (#2036, epic #1665).
 *
 * Ported from web/e2e/provisioning.spec.ts. A provisioning session is opened
 * by a device enrolling, and the SDK has no call that creates one, so these
 * specs read the sessions the server holds and hold the page to them (#425:
 * the serial, MAC and timestamps the server sent, never "Invalid Date").
 * The mocked pending and expired sessions are listed as gaps in the PR body.
 */
import { test, expect } from './fixtures';

interface Result<T> {
  success: boolean;
  data?: T;
  error?: unknown;
}

interface ProvisioningSession {
  id: string;
  ek_serial?: string;
  mac_address?: string;
  expires_at?: string;
  fulfilled?: boolean;
}

/** The part of the SDK's DeviceService these specs drive. */
interface ProvisioningSdk {
  device: {
    listProvisioningSessions(): Promise<Result<ProvisioningSession[]>>;
  };
}

async function listSessions(sdk: unknown): Promise<ProvisioningSession[]> {
  const res = await (sdk as ProvisioningSdk).device.listProvisioningSessions();
  expect(res.success, JSON.stringify(res.error)).toBe(true);
  return res.data ?? [];
}

test.describe('Provisioning Sessions', () => {
  test('the page loads with no invalid timestamp', async ({ adminPage, sdk }) => {
    await listSessions(sdk);

    await adminPage.goto('/provisioning/sessions');

    await expect(adminPage.locator('h1').first()).toBeVisible();
    await expect(adminPage.getByText('Invalid Date')).toHaveCount(0);
  });

  test('the list shows the serial, MAC and status the server sent', async ({ adminPage, sdk }) => {
    const sessions = (await listSessions(sdk)).filter((s) => s.ek_serial);
    test.skip(sessions.length === 0, 'no device has opened a provisioning session on the harness server');

    await adminPage.goto('/provisioning/sessions');

    for (const session of sessions) {
      const row = adminPage.getByRole('row', { name: new RegExp(session.ek_serial!) });
      await expect(row).toBeVisible();
      if (session.mac_address) {
        await expect(row).toContainText(session.mac_address);
      }
      await expect(row).not.toContainText('Invalid Date');
      if (session.expires_at && !session.fulfilled && Date.parse(session.expires_at) < Date.now()) {
        await expect(row).toContainText(/expired/i);
      }
    }
  });
});
