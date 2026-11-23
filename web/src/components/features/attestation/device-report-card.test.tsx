import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DeviceReport } from 'trusted-platform-sdk';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import type { Answer } from '@/test/control-plane-fetch';
import { DeviceReportCard } from './device-report-card';

// #2035 (Codex round 3 on #2341): the real-server harness has no collector
// that can be made to produce a report, so the collected-report states the
// mocked Playwright spec covered are pinned here against the real SDK client:
// fresh and stale verdicts with their age, a cryptographic failure versus a
// check that could not run, the three clock states, the signed and TOFU
// baselines, never collected (404), not configured (503), and the re-read
// after Refresh attestation.

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const REPORT = 'GET /api/v1/attestation/reports/7';
const REFRESH = 'POST /api/v1/attestation/reports/7/refresh';

/** A full DeviceReport wire object for device 7: a fresh, signed-baseline pass unless overridden. */
function report(overrides: Partial<DeviceReport> = {}): DeviceReport {
  return {
    device_id: '7',
    serial: 'SN-0007',
    model: 'example-board',
    verified: true,
    ak_certificate_verified: true,
    signature_valid: true,
    nonce_valid: true,
    pcrs_valid: true,
    cryptographic_failure: false,
    pcr_baseline_source: 'signed',
    pcr_baseline_recorded_at: '2026-10-01T00:00:00Z',
    pcr_baseline_captured: false,
    status: 'attested',
    attested_at: '2026-11-01T11:58:00Z',
    collected_at: '2026-11-01T11:58:00Z',
    fresh: true,
    age_seconds: 120,
    as_of: '2026-11-01T12:00:00Z',
    ...overrides,
  };
}

const accepted: Answer = { status: 202, body: { code: 202, success: true, payload: { enqueued: true } } };

function renderCard() {
  render(withControlPlane(<DeviceReportCard deviceId="7" />));
}

describe('DeviceReportCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('a fresh pass shows Verified beside its age, every check passed and the signed baseline', async () => {
    stubControlPlane({ [REPORT]: ok(report()) });
    renderCard();

    expect((await screen.findByTestId('report-verdict')).textContent).toBe('Verified');
    expect(screen.getByTestId('report-age').textContent).not.toContain('stale');
    expect(screen.getByTestId('report-age').textContent).toContain('2 minutes old');
    expect(screen.getByTestId('report-state-report').getAttribute('data-fresh')).toBe('true');
    expect(screen.getByTestId('report-baseline-source').textContent).toContain('Signed baseline');
    for (const key of ['ak_certificate_verified', 'signature_valid', 'nonce_valid', 'pcrs_valid']) {
      expect(screen.getByTestId(`check-${key}`).textContent).toContain('passed');
    }
    expect(screen.queryByTestId('report-failure-class')).toBeNull();
  });

  it('a stale pass is still shown, visibly stale, with its age', async () => {
    stubControlPlane({ [REPORT]: ok(report({ fresh: false, age_seconds: 10800 })) });
    renderCard();

    const age = await screen.findByTestId('report-age');
    expect(age.textContent).toContain('stale');
    expect(age.textContent).toContain('3 hours');
    expect(screen.getByTestId('report-state-report').getAttribute('data-fresh')).toBe('false');
    expect(screen.getByTestId('report-verdict').textContent).toBe('Verified');
  });

  it('a cryptographic failure names the failed check and that it ran and failed', async () => {
    stubControlPlane({
      [REPORT]: ok(
        report({
          verified: false,
          pcrs_valid: false,
          cryptographic_failure: true,
          message: 'PCR 7 does not match the profile baseline',
          pcr_baseline_source: 'tofu',
          status: 'quarantined',
        })
      ),
    });
    renderCard();

    expect((await screen.findByTestId('report-verdict')).textContent).toBe('Failed');
    expect(screen.getByTestId('check-pcrs_valid').textContent).toContain('failed');
    expect(screen.getByTestId('check-signature_valid').textContent).toContain('passed');
    expect(screen.getByTestId('report-failure-class').textContent).toContain('ran and failed');
    expect(screen.getByText('PCR 7 does not match the profile baseline')).toBeDefined();
    expect(screen.getByTestId('report-baseline-source').textContent).toContain('TOFU baseline');
  });

  it('a check that could not run is Not verified, not Failed', async () => {
    stubControlPlane({
      [REPORT]: ok(
        report({
          verified: false,
          ak_certificate_verified: false,
          cryptographic_failure: false,
          message: 'no attestation certificate enrolled',
          status: 'denied',
        })
      ),
    });
    renderCard();

    expect((await screen.findByTestId('report-verdict')).textContent).toBe('Not verified');
    expect(screen.getByTestId('check-ak_certificate_verified').textContent).toContain('failed');
    expect(screen.getByTestId('report-failure-class').textContent).toContain('could not run');
  });

  it('never collected (404) is distinct from a failed verdict', async () => {
    stubControlPlane({ [REPORT]: refused(404, 'no report') });
    renderCard();

    expect((await screen.findByTestId('report-state-never-collected')).textContent).toContain('Never collected');
    expect(screen.queryByTestId('report-verdict')).toBeNull();
    expect(screen.queryByText('Failed', { exact: true })).toBeNull();
  });

  it('reporting not configured (503) is named and disables Refresh', async () => {
    // The SDK client retries a 503 with backoff (1 s, 2 s, 4 s) before it
    // answers the card, so the clock is run past the retries.
    vi.useFakeTimers({ shouldAdvanceTime: true });
    stubControlPlane({ [REPORT]: refused(503, 'not configured') });
    renderCard();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000);
    });
    vi.useRealTimers();

    expect((await screen.findByTestId('report-state-not-configured')).textContent).toContain(
      'Reporting not configured'
    );
    expect(screen.getByRole('button', { name: /Refresh attestation/ }).hasAttribute('disabled')).toBe(true);
  });

  it('the clock renders in three states', async () => {
    const cases: Array<[boolean | undefined, string]> = [
      [true, 'Clock synced'],
      [false, 'Clock unsynced'],
      [undefined, 'Clock unknown'],
    ];
    for (const [synced, label] of cases) {
      const r = report();
      if (synced !== undefined) r.time_synced = synced;
      stubControlPlane({ [REPORT]: ok(r) });
      renderCard();
      expect((await screen.findByTestId('report-clock')).textContent).toBe(label);
      cleanup();
      vi.unstubAllGlobals();
    }
  });

  it('Refresh attestation enqueues (202) and re-reads the report with its new age', async () => {
    const routes: Record<string, Answer> = {
      [REPORT]: ok(report({ fresh: false, age_seconds: 10800 })),
      [REFRESH]: accepted,
    };
    const sent = stubControlPlane(routes);
    renderCard();

    expect((await screen.findByTestId('report-age')).textContent).toContain('stale');
    // stubControlPlane looks each request up in this object, so the next read
    // answers the report the collector wrote after the enqueued collection.
    routes[REPORT] = ok(report({ fresh: true, age_seconds: 5 }));

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Refresh attestation/ }));
    });

    await waitFor(() => expect(screen.getByTestId('report-age').textContent).toContain('5 seconds old'));
    expect(screen.getByTestId('report-age').textContent).not.toContain('stale');
    expect(sent.some((r) => r.method === 'POST' && r.path === '/api/v1/attestation/reports/7/refresh')).toBe(true);
    expect(await screen.findByText(/^Collection enqueued/)).toBeDefined();
    expect(sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/attestation/reports/7')).toHaveLength(2);
  });

  it('a refused refresh is a destructive toast', async () => {
    stubControlPlane({
      [REPORT]: ok(report()),
      [REFRESH]: refused(409, 'collector busy'),
    });
    renderCard();
    await screen.findByTestId('report-verdict');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Refresh attestation/ }));
    });

    const toast = await screen.findByText(/collector busy/);
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });
});
