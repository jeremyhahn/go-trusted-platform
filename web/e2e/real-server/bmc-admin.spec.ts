/**
 * Real-server spec for the BMC admin operations (#2040, epic #1665):
 * ReplaceWebCertificate, EnrollBMC, RestoreFactoryCert, ListUsers,
 * CreateUser, DeleteUser, SetUserPassword and SetUserPrivilege.
 *
 * The harness server has no BMC hardware behind it, so each operation is
 * driven through the SDK against a profile ID the server does not know and
 * the spec asserts on what the server answers (an error status, never a
 * success), then checks that the pages render the controls behind the
 * capability gate and surface the server's answer.
 */
import { test, expect } from './fixtures';

const UNKNOWN_PROFILE = 987654;

/** Runs an SDK call and returns the HTTP status the server answered with. */
async function statusOf(call: () => Promise<unknown>): Promise<number> {
  try {
    const res = (await call()) as { status?: number; success?: boolean } | undefined;
    if (res && typeof res.status === 'number') {
      return res.status;
    }
    return res && res.success === false ? 500 : 200;
  } catch (err) {
    const e = err as { status?: number; statusCode?: number; response?: { status?: number } };
    return e.status ?? e.statusCode ?? e.response?.status ?? 0;
  }
}

test.describe('BMC admin operations against the real server', () => {
  test('ListUsers on an unknown profile is refused by the server', async ({ sdk }) => {
    const status = await statusOf(() => sdk.bmc.listUsers(UNKNOWN_PROFILE));
    expect(status).toBeGreaterThanOrEqual(400);
  });

  test('CreateUser, SetUserPassword, SetUserPrivilege and DeleteUser are refused for an unknown profile', async ({
    sdk,
  }) => {
    const create = await statusOf(() =>
      sdk.bmc.createUser(UNKNOWN_PROFILE, {
        slot: 5,
        username: 'e2e-operator',
        password: 'E2e-operator-pass-1',
        privilege: 'operator',
        enabled: true,
        channel: 1,
      }),
    );
    expect(create).toBeGreaterThanOrEqual(400);

    const password = await statusOf(() =>
      sdk.bmc.setUserPassword(UNKNOWN_PROFILE, 5, 'E2e-operator-pass-2'),
    );
    expect(password).toBeGreaterThanOrEqual(400);

    const privilege = await statusOf(() =>
      sdk.bmc.setUserPrivilege(UNKNOWN_PROFILE, 5, 'user', 1),
    );
    expect(privilege).toBeGreaterThanOrEqual(400);

    const del = await statusOf(() => sdk.bmc.deleteUser(UNKNOWN_PROFILE, 5));
    expect(del).toBeGreaterThanOrEqual(400);
  });

  test('ReplaceWebCertificate rejects an unknown profile', async ({ sdk }) => {
    const status = await statusOf(() =>
      sdk.bmc.replaceWebCertificate(UNKNOWN_PROFILE, {
        certPem: 'not-a-certificate',
        keyPem: 'not-a-key',
      }),
    );
    expect(status).toBeGreaterThanOrEqual(400);
  });

  test('EnrollBMC and RestoreFactoryCert reach their REST routes and are refused for an unknown profile', async ({
    sdk,
  }) => {
    const enroll = await statusOf(() =>
      sdk.bmc.enrollBMC(UNKNOWN_PROFILE, { replaceCertificate: false }),
    );
    // 404: unknown profile; 503: the server runs without an enroller.
    // Never 405: the route exists.
    expect(enroll).toBeGreaterThanOrEqual(400);
    expect(enroll).not.toBe(405);

    const restore = await statusOf(() => sdk.bmc.restoreFactoryCert(UNKNOWN_PROFILE));
    expect(restore).toBeGreaterThanOrEqual(400);
    expect(restore).not.toBe(405);
  });

  test('the users page shows the server error for an unknown profile', async ({ adminPage }) => {
    await adminPage.goto(`/devices/bmc/${UNKNOWN_PROFILE}/users`);
    await expect(adminPage.getByRole('alert').first()).toBeVisible();
  });

  test('the profile page offers enrol and restore behind the gate and reports the refusal', async ({
    adminPage,
  }) => {
    await adminPage.goto(`/devices/bmc/${UNKNOWN_PROFILE}`);
    const enroll = adminPage.getByTestId('bmc-enroll-button');
    const restore = adminPage.getByTestId('bmc-restore-cert-button');
    await expect(enroll).toBeVisible();
    await expect(restore).toBeVisible();

    await enroll.click();
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    // The server refuses an unknown profile (404) or runs without an
    // enroller (503); either way the page shows the server's answer.
    await expect(adminPage.getByTestId('bmc-cert-ops-error')).toBeVisible();
    await expect(adminPage.getByTestId('bmc-action-error')).toBeVisible();
  });
});
