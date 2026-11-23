import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }), usePathname: () => '/devices/profiles' }));

import { DeviceProfileLookup } from './device-profile-lookup';

// #2048: the profiles page counts profiles and finds one by MAC, by serial or
// by match through the SDK DeviceService, each control capability-gated.

const COUNT_OP = 'GET /api/v1/device/profiles/count';
const MAC_OP = 'GET /api/v1/device/profiles/mac/{mac}';
const SERIAL_OP = 'GET /api/v1/device/profiles/serial/{serial}';
const MATCH_OP = 'POST /api/v1/device/profiles/match';
const ALL_OPS = [COUNT_OP, MAC_OP, SERIAL_OP, MATCH_OP];

const MAC = '02:00:00:00:00:01';
const PROFILE = { id: '5', name: 'edge-node', role: 'server' };

// The server's capabilities listing for the four ops; an op in off is listed
// but disabled.
function caps(off: string[] = []): Answer {
  const capabilities = ALL_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: device' }
      : { op, kind: 'route', enabled: true }
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function routes(overrides: Record<string, Answer> = {}): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
    'GET /api/v1/device/profiles/count': ok({ count: 4 }),
    ...overrides,
  };
}

const button = (name: string) => screen.getByRole('button', { name });

async function fill(label: string, value: string) {
  fireEvent.change(await screen.findByLabelText(label), { target: { value } });
}

async function press(name: string) {
  await waitFor(() => expect(button(name).hasAttribute('disabled')).toBe(false));
  await act(async () => {
    fireEvent.click(button(name));
  });
}

describe('DeviceProfileLookup', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the profile count', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<DeviceProfileLookup />));

    await screen.findByText('4 profiles');
  });

  it('finds a profile by MAC', async () => {
    const sent = stubControlPlane(
      routes({
        [`GET /api/v1/device/profiles/mac/${encodeURIComponent(MAC)}`]: ok(PROFILE),
        [`GET /api/v1/device/profiles/mac/${MAC}`]: ok(PROFILE),
      })
    );
    render(withControlPlane(<DeviceProfileLookup />));

    await fill('Profile MAC address', MAC);
    await press('Find by MAC');

    const result = await screen.findByTestId('device-profile-lookup-result');
    expect(result.textContent).toContain('edge-node');
    expect(result.textContent).toContain('5');
    expect(
      sent.some((r) => r.method === 'GET' && r.path.startsWith('/api/v1/device/profiles/mac/02'))
    ).toBe(true);
  });

  it('finds a profile by serial', async () => {
    const sent = stubControlPlane(routes({ 'GET /api/v1/device/profiles/serial/SN-0001': ok(PROFILE) }));
    render(withControlPlane(<DeviceProfileLookup />));

    await fill('Profile serial', 'SN-0001');
    await press('Find by serial');

    const result = await screen.findByTestId('device-profile-lookup-result');
    expect(result.textContent).toContain('edge-node');
    expect(sent.some((r) => r.method === 'GET' && r.path === '/api/v1/device/profiles/serial/SN-0001')).toBe(true);
  });

  it('matches a profile from MAC, serial and model', async () => {
    const sent = stubControlPlane(routes({ 'POST /api/v1/device/profiles/match': ok(PROFILE) }));
    render(withControlPlane(<DeviceProfileLookup />));

    await fill('Profile MAC address', MAC);
    await fill('Profile model', 'X10');
    await press('Match');

    const result = await screen.findByTestId('device-profile-lookup-result');
    expect(result.textContent).toContain('edge-node');
    const post = sent.find((r) => r.method === 'POST' && r.path === '/api/v1/device/profiles/match');
    expect(post).toBeDefined();
    const body = post?.body as Record<string, unknown>;
    expect(body.mac_address).toBe(MAC);
    expect(body.model).toBe('X10');
    expect('macAddress' in body).toBe(false);
  });

  it('shows a refused lookup as a destructive toast', async () => {
    stubControlPlane(routes({ 'GET /api/v1/device/profiles/serial/SN-0001': refused(404, 'profile not found') }));
    render(withControlPlane(<DeviceProfileLookup />));

    await fill('Profile serial', 'SN-0001');
    await press('Find by serial');

    const toast = await screen.findByTestId('toast');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(toast.textContent).toContain('not found');
    expect(screen.queryByTestId('device-profile-lookup-result')).toBeNull();
  });

  it('withholds the lookups the server does not offer', async () => {
    const sent = stubControlPlane(routes({ 'GET /api/v1/capabilities': caps(ALL_OPS) }));
    render(withControlPlane(<DeviceProfileLookup />));

    await fill('Profile MAC address', MAC);
    await fill('Profile serial', 'SN-0001');
    for (const name of ['Find by MAC', 'Find by serial', 'Match']) {
      await waitFor(() => expect(button(name).getAttribute('title')).toBe('not-configured: device'));
      expect(button(name).hasAttribute('disabled')).toBe(true);
      expect(button(name).getAttribute('data-capability-enabled')).toBe('false');
    }
    expect(sent.some((r) => r.path === '/api/v1/device/profiles/count')).toBe(false);
    expect(screen.queryByTestId('device-profile-count')).toBeNull();
  });
});
