/**
 * NTP page against the real server (#2058, epic #1665 slice 21).
 *
 * Each view is compared with what the server returns through the SDK
 * (`sdk.ntp`): GetStatus feeds the status card, ListSources the sources
 * table, and Step the "Step Clock" control. A node without an `ntp:`
 * configuration answers 503 on every route: the page then shows the read
 * error and gates the Step control off with the server's reason.
 */
import { test, expect } from './fixtures';

const NTP_PATH = '/networking/ntp';

test.describe('NTP (real server)', () => {
  test('the status card shows what GetStatus returns', async ({ adminPage, sdk }) => {
    const res = await sdk.ntp.getStatus();

    await adminPage.goto(NTP_PATH);
    await expect(adminPage.getByRole('heading', { name: 'NTP', exact: true })).toBeVisible();
    const card = adminPage.getByTestId('ntp-status-card');

    if (res.success && res.data?.status) {
      const s = res.data.status;
      await expect(card.getByText(s.synced ? 'Synced' : 'Not synced', { exact: true })).toBeVisible();
      await expect(card.getByText(`${s.sourcesReachable} / ${s.sourcesTotal}`)).toBeVisible();
    } else {
      await expect(card.getByText('No status available')).toBeVisible();
    }
  });

  test('the sources table lists what ListSources returns', async ({ adminPage, sdk }) => {
    const res = await sdk.ntp.listSources();

    await adminPage.goto(NTP_PATH);
    const table = adminPage.getByTestId('ntp-sources-table');

    if (!res.success) {
      await expect(adminPage.getByTestId('ntp-sources-error')).toBeVisible();
      if (res.error?.message) {
        await expect(adminPage.getByTestId('ntp-sources-error')).toContainText(res.error.message);
      }
      return;
    }
    const sources = res.data?.sources ?? [];
    if (sources.length === 0) {
      await expect(table.getByText('No sources configured')).toBeVisible();
      return;
    }
    for (const s of sources) {
      await expect(table.getByRole('cell', { name: s.address, exact: true })).toBeVisible();
    }
  });

  test('the Step control is gated by what GetStatus returns', async ({ adminPage, sdk }) => {
    const res = await sdk.ntp.getStatus();

    await adminPage.goto(NTP_PATH);
    const step = adminPage.getByRole('button', { name: 'Step Clock' });

    if (res.success && res.data?.status) {
      await expect(step).toBeEnabled();
      await expect(adminPage.getByTestId('ntp-step-reason')).toHaveCount(0);
    } else {
      await expect(step).toBeDisabled();
      await expect(adminPage.getByTestId('ntp-step-reason')).toBeVisible();
    }
  });

  test('Cancel closes the Step dialog without stepping', async ({ adminPage, sdk }) => {
    const res = await sdk.ntp.getStatus();
    test.skip(!res.success, 'NTP is not configured on the harness node: Step is gated off');

    await adminPage.goto(NTP_PATH);
    await adminPage.getByRole('button', { name: 'Step Clock' }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByText('Step the clock?')).toBeVisible();
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toHaveCount(0);
    await expect(adminPage.getByText('Clock stepped', { exact: true })).toHaveCount(0);
  });

  test('Confirm Step reports what Step returns', async ({ adminPage, sdk }) => {
    const res = await sdk.ntp.getStatus();
    test.skip(!res.success, 'NTP is not configured on the harness node: Step is gated off');

    await adminPage.goto(NTP_PATH);
    await adminPage.getByRole('button', { name: 'Step Clock' }).click();
    const dialog = adminPage.getByRole('dialog');
    await dialog.getByRole('button', { name: 'Confirm Step' }).click();

    const stepped = adminPage.getByText('Clock stepped', { exact: true });
    const failed = adminPage.getByText(/Failed to step the clock/);
    await expect(stepped.or(failed).first()).toBeVisible();
    if (await stepped.isVisible()) {
      await expect(dialog).toHaveCount(0);
      const after = await sdk.ntp.getStatus();
      expect(after.success).toBe(true);
    }
  });
});
