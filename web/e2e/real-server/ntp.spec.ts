/**
 * NTP page against the real-server harness (#2036, epic #1665).
 *
 * Ported from web/e2e/ntp.spec.ts. The status and sources are read from the
 * server through the SDK first, and the page is held to that answer, whether
 * the harness node runs chronyd or not. Mocked cases with no server behaviour
 * behind them (a status read held open, a refresh made to fail on cue, a 409
 * from Step) are listed as gaps in the PR body; a confirmed Step is not run
 * because it steps the runner's clock.
 */
import { test, expect } from './fixtures';

interface Result<T> {
  success: boolean;
  data?: T;
  error?: unknown;
}

interface NTPStatus {
  synced: boolean;
  stratum: number;
  mode: string;
}

interface NTPSource {
  address: string;
  state: string;
  reachable: boolean;
}

/** The part of the SDK's NTPService these specs drive. */
interface NtpSdk {
  ntp: {
    getStatus(): Promise<Result<{ status: NTPStatus }>>;
    listSources(): Promise<Result<{ sources: NTPSource[] }>>;
  };
}

test.describe('NTP', () => {
  test('shows the NTP status the server reports (GetStatus)', async ({ adminPage, sdk }) => {
    const res = await (sdk as NtpSdk).ntp.getStatus();

    await adminPage.goto('/networking/ntp');

    await expect(adminPage.getByRole('heading', { name: /^ntp$/i })).toBeVisible();
    const card = adminPage.getByTestId('ntp-status-card');
    await expect(card).toBeVisible();
    if (res.success && res.data) {
      if (res.data.status.synced) {
        await expect(card.getByText('Synced', { exact: true })).toBeVisible();
      } else {
        await expect(card.getByText('Synced', { exact: true })).toHaveCount(0);
      }
    } else {
      await expect(card.getByText(/fail|error|unavailable/i).first()).toBeVisible();
    }
  });

  test('lists the NTP sources the server reports (ListSources)', async ({ adminPage, sdk }) => {
    const res = await (sdk as NtpSdk).ntp.listSources();

    await adminPage.goto('/networking/ntp');

    const table = adminPage.getByTestId('ntp-sources-table');
    await expect(table).toBeVisible();
    if (!res.success) {
      // A failed read is an error, never an empty configuration.
      await expect(table.getByTestId('ntp-sources-error')).toBeVisible();
      await expect(table.getByText('No sources configured')).toHaveCount(0);
      return;
    }
    const sources = res.data?.sources ?? [];
    if (sources.length === 0) {
      await expect(table.getByText('No sources configured')).toBeVisible();
    }
    for (const source of sources) {
      await expect(table.getByText(source.address).first()).toBeVisible();
    }
  });

  test('sends no Step when the confirmation is cancelled', async ({ adminPage }) => {
    const steps: string[] = [];
    adminPage.on('request', (req) => {
      if (req.method() === 'POST' && /\/ntp\/step\b/.test(req.url())) {
        steps.push(req.url());
      }
    });

    await adminPage.goto('/networking/ntp');
    await adminPage.getByRole('button', { name: /step clock/i }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByText(/step the clock\?/i)).toBeVisible();

    await dialog.getByRole('button', { name: /cancel/i }).click();

    await expect(adminPage.getByRole('dialog')).toBeHidden();
    expect(steps).toHaveLength(0);
  });

  test('starts no overlapping refresh while a status read is pending', async ({ adminPage }) => {
    let statusReads = 0;
    adminPage.on('request', (req) => {
      if (req.method() === 'GET' && /\/ntp\/status\b/.test(req.url())) {
        statusReads++;
      }
    });

    await adminPage.goto('/networking/ntp');
    const refresh = adminPage.getByRole('button', { name: 'Refresh' });
    await expect(refresh).toBeEnabled();

    const before = statusReads;
    await refresh.click();
    await refresh.click({ force: true });

    await expect(refresh).toBeEnabled();
    expect(statusReads - before).toBeLessThanOrEqual(1);
  });
});
