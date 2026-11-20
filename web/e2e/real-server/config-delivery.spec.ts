/**
 * Real-server spec for ConfigDeliveryService.GetSession and FulfillSession
 * (#2046, epic #1665 coverage-matrix slice 9).
 *
 * The page is `(dashboard)/provisioning/sessions/[sessionId]`. A session is
 * opened by a device through the device-side pre-enrollment protocol
 * (not-UI), so the admin SDK cannot create one: the GetSession and
 * FulfillSession refusals run against any server, and the detail and
 * fulfil flow runs on the first pending session the server lists, and is
 * skipped when it lists none.
 */
import type { Page } from '@playwright/test';
import type { PlatformClient, ProvisioningSession } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';

/** The harness fixtures this spec uses (web/e2e/real-server/fixtures). */
interface Fixtures {
  adminPage: Page;
  sdk: PlatformClient;
}

const UNKNOWN_SESSION = 'no-such-session-2046';

function isPending(session: ProvisioningSession): boolean {
  return !session.fulfilled && new Date(session.expires_at) > new Date();
}

test.describe('config delivery: provisioning session detail', () => {
  test('GetSession: an unknown session is refused by the server and the page says so', async ({
    adminPage,
    sdk,
  }: Fixtures) => {
    const reply = await sdk.device.getProvisioningSession(UNKNOWN_SESSION);
    expect(reply.data).toBeUndefined();
    expect(reply.error).toBeDefined();

    await adminPage.goto(`/provisioning/sessions/${UNKNOWN_SESSION}`);
    await expect(adminPage.getByText('Session Not Found')).toBeVisible();
  });

  test('FulfillSession: the server refuses an unknown session', async ({ sdk }: Pick<Fixtures, 'sdk'>) => {
    const reply = await sdk.device.fulfillProvisioningSession({
      session_id: UNKNOWN_SESSION,
      profile_id: '1',
    });
    expect(reply.error).toBeDefined();
  });

  test('GetSession: the page shows what the server returns for a listed session', async ({
    adminPage,
    sdk,
  }: Fixtures) => {
    const listed = await sdk.device.listProvisioningSessions();
    const session = listed.data?.[0];
    test.skip(!session, 'the server lists no provisioning session');
    if (!session) return;

    const reply = await sdk.device.getProvisioningSession(session.id);
    expect(reply.error).toBeUndefined();
    expect(reply.data?.id).toBe(session.id);

    await adminPage.goto(`/provisioning/sessions/${session.id}`);
    await expect(adminPage.getByRole('heading', { name: 'Provisioning Session' })).toBeVisible();
    await expect(adminPage.getByText(session.id, { exact: true })).toBeVisible();
    if (reply.data?.ek_serial) {
      await expect(adminPage.getByText(reply.data.ek_serial, { exact: true })).toBeVisible();
    }
  });

  test('FulfillSession: a custom profile fulfils a pending session on the server', async ({
    adminPage,
    sdk,
  }: Fixtures) => {
    const listed = await sdk.device.listProvisioningSessions();
    const session = listed.data?.find(isPending);
    test.skip(!session, 'the server lists no pending provisioning session');
    if (!session) return;

    await adminPage.goto(`/provisioning/sessions/${session.id}`);
    await adminPage.getByRole('tab', { name: 'Custom Profile' }).click();
    await adminPage.getByLabel('Profile Name').fill(`e2e-2046-${Date.now()}`);
    await adminPage.getByRole('button', { name: 'Create Profile and Provision Device' }).click();
    await expect(adminPage.getByRole('heading', { name: 'Device Provisioned' })).toBeVisible();

    const after = await sdk.device.getProvisioningSession(session.id);
    expect(after.data?.fulfilled).toBe(true);
    expect(after.data?.profile_id).toBeTruthy();
  });

  test('FulfillSession: a fulfilled or expired session offers no fulfil control', async ({
    adminPage,
    sdk,
  }: Fixtures) => {
    const listed = await sdk.device.listProvisioningSessions();
    const session = listed.data?.find((s: ProvisioningSession) => !isPending(s));
    test.skip(!session, 'the server lists no fulfilled or expired session');
    if (!session) return;

    await adminPage.goto(`/provisioning/sessions/${session.id}`);
    // A fulfilled session shows the provisioned card; an expired one the
    // detail with its expiry alert. Neither offers the fulfil form.
    await expect(
      adminPage.getByRole('heading', { name: /Provisioning Session|Device Provisioned/ }).first()
    ).toBeVisible();
    await expect(
      adminPage.getByRole('button', { name: 'Create Profile and Provision Device' })
    ).toHaveCount(0);
  });
});
