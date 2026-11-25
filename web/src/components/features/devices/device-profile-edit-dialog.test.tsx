import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }), usePathname: () => '/devices/profiles' }));

import { DeviceProfileEditDialog } from './device-profile-edit-dialog';

// #2048: Edit Profile on the profiles page saves name and model through the
// SDK DeviceService updateProfile, gated on the server's update route.

const OP = 'PUT /api/v1/device/profiles/{id:[0-9]+}';

const PROFILE = { id: '5', name: 'edge-node', model: 'r650', role: 'server' };

// The server's capabilities listing for the one op; an op in off is listed
// but disabled.
function caps(off: string[] = []): Answer {
  const capabilities = [OP].map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: device' }
      : { op, kind: 'route', enabled: true }
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function routes(overrides: Record<string, Answer> = {}): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
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

describe('DeviceProfileEditDialog', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('saves the edited name and model through PUT /api/v1/device/profiles/5', async () => {
    const onSaved = vi.fn();
    const onOpenChange = vi.fn();
    const sent = stubControlPlane(
      routes({ 'PUT /api/v1/device/profiles/5': ok({ profile: { ...PROFILE, name: 'edge-2' } }) })
    );
    render(
      withControlPlane(
        <DeviceProfileEditDialog profile={PROFILE as never} open onOpenChange={onOpenChange} onSaved={onSaved} />
      )
    );

    expect((await screen.findByLabelText('Profile name')).getAttribute('value')).toBe('edge-node');
    await fill('Profile name', 'edge-2');
    await press('Save');

    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(onOpenChange).toHaveBeenCalledWith(false);
    const put = sent.find((r) => r.method === 'PUT' && r.path === '/api/v1/device/profiles/5');
    expect(put).toBeDefined();
    const body = put?.body as Record<string, unknown>;
    expect(body.name).toBe('edge-2');
    expect(body.model).toBe('r650');
    expect(body.role).toBe('server');
  });

  it('withholds Save when the server does not offer the update', async () => {
    const sent = stubControlPlane(routes({ 'GET /api/v1/capabilities': caps([OP]) }));
    render(withControlPlane(<DeviceProfileEditDialog profile={PROFILE as never} open onOpenChange={vi.fn()} />));

    await fill('Profile name', 'edge-2');
    await waitFor(() => expect(button('Save').getAttribute('title')).toBe('not-configured: device'));
    expect(button('Save').hasAttribute('disabled')).toBe(true);
    expect(button('Save').getAttribute('data-capability-enabled')).toBe('false');
    expect(sent.some((r) => r.method === 'PUT')).toBe(false);
  });

  it('shows a refused update as a destructive toast and does not call onSaved', async () => {
    const onSaved = vi.fn();
    stubControlPlane(routes({ 'PUT /api/v1/device/profiles/5': refused(409, 'profile name taken') }));
    render(
      withControlPlane(
        <DeviceProfileEditDialog profile={PROFILE as never} open onOpenChange={vi.fn()} onSaved={onSaved} />
      )
    );

    await fill('Profile name', 'edge-2');
    await press('Save');

    const toast = await screen.findByTestId('toast');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(toast.textContent).toContain('name taken');
    expect(onSaved).not.toHaveBeenCalled();
  });
});
