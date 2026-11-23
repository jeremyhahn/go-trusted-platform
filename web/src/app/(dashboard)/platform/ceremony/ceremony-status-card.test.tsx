import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { CeremonyStatusCard, ceremonyStateLabel, officerProgress } from './ceremony-status-card';
import CeremonyPage from './page';

// #2042: the ceremony page reads CeremonyService.Status through the SDK
// client (useCeremony().status()) and shows it read-only, with no control.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/platform/ceremony',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const STATUS_PATH = 'GET /api/v1/ceremony/status';

function inProgress(): Answer {
  return ok({
    ceremonyId: 'c-1',
    state: 'CEREMONY_STATE_IN_PROGRESS',
    threshold: '3-of-5',
    officersEnrolled: 2,
    officersRequired: 3,
    initializedAt: '2026-11-20T10:00:00Z',
  });
}

describe('ceremony status helpers', () => {
  it('labels each ceremony state', () => {
    expect(ceremonyStateLabel('CEREMONY_STATE_IN_PROGRESS')).toBe('In progress');
    expect(ceremonyStateLabel('CEREMONY_STATE_UNINITIALIZED')).toBe('Not initialized');
    expect(ceremonyStateLabel('COMPLETE')).toBe('Complete');
    expect(ceremonyStateLabel('CEREMONY_STATE_UNSPECIFIED')).toBe('Unknown');
    expect(ceremonyStateLabel(undefined)).toBe('Unknown');
  });

  it('counts the officers', () => {
    expect(officerProgress({ officersEnrolled: 2, officersRequired: 3 })).toBe('2 of 3');
    expect(officerProgress(undefined)).toBe('Unavailable');
    expect(officerProgress({ officersEnrolled: 0, officersRequired: 0 })).toBe('Unavailable');
    expect(officerProgress({ officersEnrolled: 0, officersRequired: 3 })).toBe('0 of 3');
  });
});

describe('CeremonyStatusCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows an in-progress ceremony', async () => {
    const sent = stubControlPlane({ [STATUS_PATH]: inProgress() });
    render(withControlPlane(<CeremonyStatusCard />));

    expect(await screen.findByText('In progress')).toBeDefined();
    expect(screen.getByText('2 of 3')).toBeDefined();
    expect(screen.getByText('3-of-5')).toBeDefined();
    expect(screen.getByText('c-1')).toBeDefined();
    expect(screen.getByText('2026-11-20T10:00:00Z')).toBeDefined();
    expect(sent).toEqual([{ method: 'GET', path: '/api/v1/ceremony/status', body: undefined }]);
  });

  it('shows a ceremony not yet initialised', async () => {
    stubControlPlane({
      [STATUS_PATH]: ok({
        ceremonyId: '',
        state: 'CEREMONY_STATE_UNINITIALIZED',
        threshold: '',
        officersEnrolled: 0,
        officersRequired: 0,
      }),
    });
    render(withControlPlane(<CeremonyStatusCard />));

    expect(await screen.findAllByText('Not initialized')).toHaveLength(2);
    expect(screen.getAllByText('Unavailable')).toHaveLength(2);
  });

  it('shows what the server does not report as unavailable', async () => {
    // The real backend reports only the ceremony ID and state today.
    stubControlPlane({ [STATUS_PATH]: ok({ ceremonyId: 'c-1', state: 'CEREMONY_STATE_IN_PROGRESS' }) });
    render(withControlPlane(<CeremonyStatusCard />));

    expect(await screen.findByText('In progress')).toBeDefined();
    expect(screen.getAllByText('Unavailable')).toHaveLength(3);
    expect(screen.queryByText('Not initialized')).toBeNull();
    expect(screen.queryByText('0 of 0')).toBeNull();
  });

  it('shows a refusal', async () => {
    stubControlPlane({ [STATUS_PATH]: refused(403, 'ceremony: scope ceremony:status required') });
    render(withControlPlane(<CeremonyStatusCard />));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toBe('Ceremony status unavailable: ceremony: scope ceremony:status required');
  });

  it('the page has its header, the Initialize and Sign CSR controls and the claim cards', async () => {
    stubControlPlane({ [STATUS_PATH]: inProgress() });
    render(withControlPlane(<CeremonyPage />));

    expect(await screen.findByRole('heading', { name: 'Bootstrap ceremony' })).toBeDefined();
    expect(await screen.findByText('In progress')).toBeDefined();
    expect(screen.getAllByRole('button').map((b) => b.textContent)).toEqual([
      'Initialize',
      'Sign CSR',
      'Request challenge',
      'Start over',
      'Request challenge',
      'Start over',
    ]);
  });
});
