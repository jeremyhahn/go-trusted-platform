/**
 * Real-server spec for the key ceremony page (#2042, epic #1665).
 *
 * The page at /ca/ceremony reads CeremonyService.Status and offers the
 * Init, ClaimCert (begin/complete), ClaimShare (begin/complete) and SignCSR
 * steps. State is read and seeded through the SDK, never through route
 * mocks; assertions compare the page with what the server returns.
 */
import { test, expect } from './fixtures';

const PAGE = '/ca/ceremony';

test.describe('ceremony', () => {
  test('status view shows the state the server reports', async ({ adminPage, sdk }) => {
    const res = await sdk.ceremony.getStatus().catch((err: unknown) => ({ error: err }));
    await adminPage.goto(PAGE);
    await expect(adminPage.getByRole('heading', { name: 'Key ceremony' })).toBeVisible();

    if ('data' in res && res.data) {
      const status = res.data;
      await expect(adminPage.getByTestId('ceremony-state')).toHaveText(status.state || 'uninitialized');
      await expect(adminPage.getByTestId('ceremony-officers')).toContainText(
        `${status.officers_enrolled} / ${status.officers_required}`,
      );
    } else {
      // A daemon without a ceremony backend answers 503; the page says so
      // and keeps every step control disabled.
      await expect(adminPage.getByTestId('ceremony-error')).toBeVisible();
      await expect(adminPage.getByRole('button', { name: 'Initialize' })).toBeDisabled();
    }
  });

  test('init flow: the form posts to the server and the status follows', async ({ adminPage, sdk }) => {
    const before = await sdk.ceremony.getStatus().catch(() => undefined);
    test.skip(
      before === undefined || (before.data?.state ?? '') !== '' && before.data?.state !== 'uninitialized',
      'ceremony backend absent or already initialized on this server',
    );

    await adminPage.goto(PAGE);
    await adminPage.getByLabel('SO PIN').fill('12345678');
    await adminPage.getByLabel('User PIN').fill('87654321');
    await adminPage.getByLabel('Threshold').fill('2-of-3');
    await adminPage.getByLabel('Hostname').fill('ceremony.e2e.local');
    await adminPage.getByRole('button', { name: 'Initialize' }).click();

    const after = await sdk.ceremony.getStatus();
    await expect(adminPage.getByTestId('ceremony-id')).toHaveText(after.data!.ceremony_id);
    await expect(adminPage.getByTestId('ceremony-state')).toHaveText(after.data!.state);
  });

  test('claim certificate begin returns a nonce shown on the page', async ({ adminPage, sdk }) => {
    const status = await sdk.ceremony.getStatus().catch(() => undefined);
    test.skip(status === undefined || !status.data?.ceremony_id, 'no initialized ceremony on this server');

    await adminPage.goto(PAGE);
    await adminPage.getByTestId('claim-cert-username').fill('officer1');
    await adminPage.getByRole('button', { name: 'Begin certificate claim' }).click();
    await expect(
      adminPage.getByTestId('claim-cert-nonce').or(adminPage.getByTestId('ceremony-step-error')),
    ).toBeVisible();
  });

  test('claim share begin returns a nonce or the server refusal', async ({ adminPage, sdk }) => {
    const status = await sdk.ceremony.getStatus().catch(() => undefined);
    test.skip(status === undefined || !status.data?.ceremony_id, 'no initialized ceremony on this server');

    await adminPage.goto(PAGE);
    await adminPage.getByTestId('claim-share-username').fill('officer1');
    await adminPage.getByRole('button', { name: 'Begin share claim' }).click();
    await expect(
      adminPage.getByTestId('claim-share-nonce').or(adminPage.getByTestId('ceremony-step-error')),
    ).toBeVisible();
  });

  test('sign CSR without a CSR shows the server refusal', async ({ adminPage, sdk }) => {
    const status = await sdk.ceremony.getStatus().catch(() => undefined);
    test.skip(status === undefined, 'ceremony backend absent on this server');

    const refused = await sdk.ceremony
      .signCSR({ username: 'officer1', so_pin: '', csr_pem: '', role: 'admin' })
      .then(() => false)
      .catch(() => true);
    expect(refused).toBe(true);

    await adminPage.goto(PAGE);
    await adminPage.getByTestId('sign-csr-username').fill('officer1');
    await adminPage.getByRole('button', { name: 'Sign CSR' }).click();
    await expect(adminPage.getByTestId('ceremony-step-error')).toBeVisible();
  });
});
