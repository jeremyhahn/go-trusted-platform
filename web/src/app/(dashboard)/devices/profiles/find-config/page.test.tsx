import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import FindDeviceConfigPage from './page';

vi.mock('next/navigation', () => ({
  usePathname: () => '/devices/profiles/find-config',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

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

async function findByEKSerial(ekSerial: string) {
  render(withControlPlane(<FindDeviceConfigPage />));
  fireEvent.change(screen.getByLabelText('EK serial'), { target: { value: ekSerial } });
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
  fireEvent.change(screen.getByLabelText('EK serial'), { target: { value: ekSerial } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Find config' }));
  });
}

describe('FindDeviceConfigPage', () => {
  it('keeps Find config disabled until an identity is typed', () => {
    stubControlPlane({ [ROUTE]: PROFILE });
    render(withControlPlane(<FindDeviceConfigPage />));

    const button = screen.getByRole('button', { name: 'Find config' });
    expect((button as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(screen.getByLabelText('MAC address'), { target: { value: 'aa:bb:cc:dd:ee:ff' } });
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
