import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import VPNPage from './page';

// #2070: every VPN page control that reaches a server route is wrapped in
// the capability gate on that route; an op the server does not offer
// disables its control with the server's reason as the title.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/networking/vpn',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const VPN_OPS = [
  'GET /api/v1/vpn/status',
  'GET /api/v1/vpn/peers',
  'POST /api/v1/vpn/peers',
  'DELETE /api/v1/vpn/peers/{device_id}',
  'GET /api/v1/vpn/posture-policies',
  'GET /api/v1/vpn/posture-policies/{name}',
  'PUT /api/v1/vpn/posture-policies/{name}',
  'DELETE /api/v1/vpn/posture-policies/{name}',
] as const;

// The server's capabilities listing: every VPN op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = VPN_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: vpn' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function routes(off: string[] = []): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(off),
    'GET /api/v1/vpn/status': ok({ gateways: [] }),
    'GET /api/v1/vpn/peers': ok({
      peers: [{ tenantId: 'acme', deviceId: 'laptop-1', zones: ['management'], enrolledAtUnix: '1760300000' }],
    }),
    'GET /api/v1/vpn/posture-policies': ok({
      policies: [{ tenantId: 'acme', name: 'corp', module: 'package vpn.posture\n', updatedAtUnix: '1760300000' }],
    }),
  };
}

async function button(name: string): Promise<HTMLButtonElement> {
  return (await screen.findByRole('button', { name })) as HTMLButtonElement;
}

async function waitEnabled(name: string, enabled: 'true' | 'false'): Promise<HTMLButtonElement> {
  const b = await button(name);
  await waitFor(() => expect(b.getAttribute('data-capability-enabled')).toBe(enabled));
  return b;
}

async function closeDialog() {
  fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
}

describe('VPNPage capability gate', () => {
  it('marks every write control with its server op', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<VPNPage />));
    await button('Revoke laptop-1');

    const expected: Array<[string, string]> = [
      ['Enrol Peer', 'POST /api/v1/vpn/peers'],
      ['Revoke laptop-1', 'DELETE /api/v1/vpn/peers/{device_id}'],
      ['New Policy', 'PUT /api/v1/vpn/posture-policies/{name}'],
      ['Edit corp', 'GET /api/v1/vpn/posture-policies/{name}'],
      ['Delete corp', 'DELETE /api/v1/vpn/posture-policies/{name}'],
    ];
    for (const [name, op] of expected) {
      const b = await waitEnabled(name, 'true');
      expect(b.getAttribute('data-capability-op')).toBe(op);
    }
  });

  it('disables the controls the server does not offer, with the reason as the title', async () => {
    const sent = stubControlPlane(routes(['POST /api/v1/vpn/peers', 'DELETE /api/v1/vpn/posture-policies/{name}']));
    render(withControlPlane(<VPNPage />));

    for (const name of ['Enrol Peer', 'Delete corp']) {
      const b = await waitEnabled(name, 'false');
      expect(b.disabled).toBe(true);
      expect(b.getAttribute('title')).toBe('not-configured: vpn');
    }
    for (const name of ['Revoke laptop-1', 'New Policy']) {
      const b = await waitEnabled(name, 'true');
      expect(b.disabled).toBe(false);
    }

    fireEvent.click(await button('Enrol Peer'));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(sent.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  it('gates the dialog confirms on the same ops', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<VPNPage />));

    fireEvent.click(await waitEnabled('Revoke laptop-1', 'true'));
    expect((await button('Confirm Revoke')).getAttribute('data-capability-op')).toBe(
      'DELETE /api/v1/vpn/peers/{device_id}',
    );
    await closeDialog();

    fireEvent.click(await waitEnabled('Delete corp', 'true'));
    expect((await button('Confirm Delete')).getAttribute('data-capability-op')).toBe(
      'DELETE /api/v1/vpn/posture-policies/{name}',
    );
    await closeDialog();

    fireEvent.click(await waitEnabled('Enrol Peer', 'true'));
    expect((await button('Enrol')).getAttribute('data-capability-op')).toBe('POST /api/v1/vpn/peers');
    await closeDialog();

    fireEvent.click(await waitEnabled('New Policy', 'true'));
    expect((await button('Save')).getAttribute('data-capability-op')).toBe('PUT /api/v1/vpn/posture-policies/{name}');
    await closeDialog();
  });
});
