import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import ZonesPage from './page';
import { ZONE_RESTART_NOTICE, zoneChangeToast } from './zone-change';

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/networking/zones',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

// #2065: the page gates its controls on the server's capabilities; these cases have every op offered.
vi.mock('@/hooks/use-capabilities', () => ({ useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }) }));

const LIST_PATH = 'GET /api/v1/sdn/zones';
const CREATE_PATH = 'POST /api/v1/sdn/zones';

function createdZone(restartRequired: boolean): Answer {
  return ok({
    name: 'lab',
    offset: 9,
    port_classes: ['gateway'],
    internet_ingress: false,
    isolate_from: [],
    allow_to: [],
    services: [],
    isolate: false,
    oob: false,
    lifecycle_role: '',
    restart_required: restartRequired,
    created_at: '2026-11-21T00:00:00Z',
    updated_at: '2026-11-21T00:00:00Z',
  });
}

async function createLab(restartRequired: boolean) {
  const sent = stubControlPlane({
    [LIST_PATH]: ok({ zones: [], count: 0, timestamp: '2026-11-21T00:00:00Z' }),
    [CREATE_PATH]: createdZone(restartRequired),
  });
  render(withControlPlane(<ZonesPage />));
  await waitFor(() => expect(sent.some((r) => r.method === 'GET')).toBe(true));
  // The toast store is module-wide, so an earlier test's toasts can still be listed.
  const noticesBefore = noticeToasts().length;

  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Create Zone' }));
  });
  fireEvent.change(screen.getByLabelText('Name *'), { target: { value: 'lab' } });
  await act(async () => {
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Create Zone' }));
  });

  await waitFor(() =>
    expect(
      sent.some(
        (r) =>
          r.method === 'POST' &&
          r.path === '/api/v1/sdn/zones' &&
          (r.body as { name?: string } | undefined)?.name === 'lab'
      )
    ).toBe(true)
  );
  return { sent, noticesBefore };
}

function noticeToasts() {
  return screen.queryAllByTestId('toast').filter((t) => t.textContent?.includes(ZONE_RESTART_NOTICE));
}

describe('zoneChangeToast', () => {
  it('adds the restart notice only when the server asks for it', () => {
    expect(zoneChangeToast('created', true)).toEqual({
      title: 'Zone created',
      description: ZONE_RESTART_NOTICE,
      variant: 'success',
    });
    expect(zoneChangeToast('updated', false)).toEqual({ title: 'Zone updated', variant: 'success' });
    expect(zoneChangeToast('updated')).toEqual({ title: 'Zone updated', variant: 'success' });
  });

  it('titles each verb', () => {
    expect(zoneChangeToast('deleted', true).title).toBe('Zone deleted');
  });

  it('the notice names the daemon restart', () => {
    expect(ZONE_RESTART_NOTICE).toContain('next daemon restart');
  });
});

describe('ZonesPage create dialog', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('a created zone that needs a restart says so', async () => {
    await createLab(true);

    const toast = await screen.findByText('Zone created: ' + ZONE_RESTART_NOTICE);
    expect(toast.getAttribute('data-variant')).toBe('success');
  });

  it('a created zone with no restart pending shows the plain toast', async () => {
    const { noticesBefore } = await createLab(false);

    const toasts = await screen.findAllByTestId('toast');
    await waitFor(() =>
      expect(screen.getAllByTestId('toast').some((t) => t.textContent?.trim() === 'Zone created:')).toBe(true)
    );
    const created = screen.getAllByTestId('toast').find((t) => t.textContent?.trim() === 'Zone created:');
    expect(created?.getAttribute('data-variant')).toBe('success');
    expect(toasts.length).toBeGreaterThan(0);
    // No new toast carries the restart notice.
    expect(noticeToasts().length).toBeLessThanOrEqual(noticesBefore);
  });
});
