import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import FindDeviceConfigPage from './page';

vi.mock('next/navigation', () => ({
  usePathname: () => '/devices/profiles/find-config',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

// The page's gated controls read the capabilities through this hook; mocked
// so the page sends no GET /api/v1/capabilities and stubAnswers' call order
// holds. Every op is enabled.
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: () => ({ enabled: true }),
  }),
}));

const UNASSIGN = 'POST /api/v1/device/profiles/12/unassign';

const ROUTE = 'GET /api/v1/device/profiles/find-config';

const PROFILE = ok({
  id: '12',
  name: 'edge-gw',
  role: 'gateway',
  ek_serial: 'EK-1',
  mac_address: 'aa:bb:cc:dd:ee:ff',
  assigned: true,
  created_at: '2026-11-20T00:00:00Z',
  updated_at: '2026-11-20T00:00:00Z',
});

const PROFILE_B = ok({
  id: '13',
  name: 'core-gw',
  role: 'gateway',
  ek_serial: 'EK-2',
  mac_address: null,
  assigned: false,
  created_at: '2026-11-20T00:00:00Z',
  updated_at: '2026-11-20T00:00:00Z',
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

/** lookupField is the lookup form's field; the Assign card below it reuses the labels. */
function lookupField(label: string): HTMLElement {
  return screen.getAllByLabelText(label)[0];
}

async function findByEKSerial(ekSerial: string) {
  render(withControlPlane(<FindDeviceConfigPage />));
  fireEvent.change(lookupField('EK serial'), { target: { value: ekSerial } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Find config' }));
  });
}

/** deferred holds an answer back until the test resolves it. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

function answer(a: Answer): Response {
  return new Response(JSON.stringify(a.body), {
    status: a.status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** stubAnswers replaces fetch with one that hands out answers in call order. */
function stubAnswers(...answers: Array<Answer | Promise<Answer>>) {
  const fetch = vi.fn(async () => answer(await answers.shift()!));
  vi.stubGlobal('fetch', fetch);
  return fetch;
}

async function submit(ekSerial: string) {
  fireEvent.change(lookupField('EK serial'), { target: { value: ekSerial } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Find config' }));
  });
}

describe('FindDeviceConfigPage', () => {
  it('offers Unassign on an assigned profile only', async () => {
    stubControlPlane({ [ROUTE]: PROFILE });
    await findByEKSerial('EK-1');
    await screen.findByText('edge-gw');
    expect(screen.getByRole('button', { name: 'Unassign' })).toBeTruthy();
    cleanup();

    stubControlPlane({ [ROUTE]: PROFILE_B });
    await findByEKSerial('EK-2');
    await screen.findByText('core-gw');
    expect(screen.getByText('Not assigned')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Unassign' })).toBeNull();
  });

  it('unassigns the shown profile through the confirm dialog', async () => {
    const sent = stubControlPlane({
      [ROUTE]: PROFILE,
      [UNASSIGN]: ok({ ...(PROFILE.body as object), ek_serial: null, mac_address: null, assigned: false }),
    });
    await findByEKSerial('EK-1');
    await screen.findByText('edge-gw');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Unassign' }));
    });
    const dialog = await screen.findByRole('dialog');
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Unassign' }));
    });

    expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/device/profiles/12/unassign', body: {} });
    await screen.findByText('Not assigned');
    expect(screen.getByText('edge-gw')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Unassign' })).toBeNull();
  });

  it('shows the Assign a profile card', () => {
    stubControlPlane({});
    render(withControlPlane(<FindDeviceConfigPage />));

    expect(screen.getByText('Assign a profile')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Assign profile' })).toBeTruthy();
  });

  it('keeps Find config disabled until an identity is typed', () => {
    stubControlPlane({ [ROUTE]: PROFILE });
    render(withControlPlane(<FindDeviceConfigPage />));

    const button = screen.getByRole('button', { name: 'Find config' });
    expect((button as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(lookupField('MAC address'), { target: { value: 'aa:bb:cc:dd:ee:ff' } });
    expect((button as HTMLButtonElement).disabled).toBe(false);
  });

  it('shows the matched profile', async () => {
    stubControlPlane({ [ROUTE]: PROFILE });
    await findByEKSerial('EK-1');

    await screen.findByText('edge-gw');
    expect(screen.getByText('Assigned')).toBeTruthy();
    expect(screen.getByText('Profile ID 12')).toBeTruthy();
  });

  it('says no profile matches on a 404', async () => {
    stubControlPlane({ [ROUTE]: refused(404, 'no matching config') });
    await findByEKSerial('EK-9');

    await screen.findByText('No profile matches this device.');
  });

  it('shows a refusal on a 403', async () => {
    stubControlPlane({ [ROUTE]: refused(403, 'forbidden') });
    await findByEKSerial('EK-1');

    expect((await screen.findByRole('alert')).textContent).toBe('Lookup refused: forbidden');
  });

  it('hides the previous profile while a new lookup is pending', async () => {
    const second = deferred<Answer>();
    stubAnswers(PROFILE, second.promise);
    render(withControlPlane(<FindDeviceConfigPage />));

    await submit('EK-1');
    await screen.findByText('edge-gw');

    await submit('EK-2');
    expect(screen.queryByText('edge-gw')).toBeNull();
    expect(screen.getByRole('status').textContent).toContain('Looking up the profile');

    await act(async () => second.resolve(PROFILE_B));
    await screen.findByText('core-gw');
    expect(screen.queryByText('edge-gw')).toBeNull();
    expect(screen.getByText('For EK serial EK-2, MAC address -')).toBeTruthy();
  });

  it('a 404 between two lookups does not bring the earlier profile back', async () => {
    const third = deferred<Answer>();
    const fetch = stubAnswers(PROFILE, refused(404, 'no matching config'), third.promise);
    render(withControlPlane(<FindDeviceConfigPage />));

    await submit('EK-1');
    await screen.findByText('edge-gw');

    await submit('EK-9');
    await screen.findByText('No profile matches this device.');
    expect(screen.queryByText('edge-gw')).toBeNull();

    await submit('EK-9');
    expect(screen.queryByText('edge-gw')).toBeNull();
    expect(screen.queryByText('No profile matches this device.')).toBeNull();

    await act(async () => third.resolve(refused(404, 'no matching config')));
    await screen.findByText('No profile matches this device.');
    expect(screen.queryByText('edge-gw')).toBeNull();
    expect(fetch).toHaveBeenCalledTimes(3);
  });
});
