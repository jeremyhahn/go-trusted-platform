import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';

const { off } = vi.hoisted(() => ({ off: new Set<string>() }));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: 'not-configured: device' } : { enabled: true },
  }),
}));

import { ProfileAssignmentCard, ProfileUnassignButton } from './profile-assignment-card';

const ASSIGN_OP = 'POST /api/v1/device/profiles/{id:[0-9]+}/assign';
const UNASSIGN_OP = 'POST /api/v1/device/profiles/{id:[0-9]+}/unassign';
const ASSIGN = 'POST /api/v1/device/profiles/12/assign';
const UNASSIGN = 'POST /api/v1/device/profiles/12/unassign';

const PROFILE = {
  id: '12',
  name: 'edge-gw',
  role: 'gateway',
  ek_serial: null,
  mac_address: '02:00:00:00:00:01',
  assigned: true,
  created_at: '2026-11-20T00:00:00Z',
  updated_at: '2026-11-20T00:00:00Z',
};

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  off.clear();
});

const assignButton = () => screen.getByRole('button', { name: 'Assign profile' }) as HTMLButtonElement;

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe('ProfileAssignmentCard', () => {
  it('assigns a profile to a MAC address through the SDK', async () => {
    const sent = stubControlPlane({ [ASSIGN]: ok(PROFILE) });
    const onAssigned = vi.fn();
    render(withControlPlane(<ProfileAssignmentCard onAssigned={onAssigned} />));

    expect(screen.getByText('Assign a profile')).toBeTruthy();
    type('Profile ID', '12');
    type('MAC address', '02:00:00:00:00:01');
    await act(async () => {
      fireEvent.click(assignButton());
    });

    await screen.findByText('Profile edge-gw assigned');
    expect(sent).toEqual([
      {
        method: 'POST',
        path: '/api/v1/device/profiles/12/assign',
        body: { profile_id: 12, mac_address: '02:00:00:00:00:01' },
      },
    ]);
    expect(onAssigned).toHaveBeenCalledTimes(1);
    expect(onAssigned.mock.calls[0][0]).toMatchObject({ id: '12', name: 'edge-gw' });
    expect(screen.getAllByTestId('toast').some((t) => t.textContent?.includes('Profile assigned'))).toBe(true);
  });

  it('keeps Assign profile disabled until a profile id and a device identity are typed', () => {
    stubControlPlane({});
    render(withControlPlane(<ProfileAssignmentCard />));

    expect(assignButton().disabled).toBe(true);
    type('Profile ID', '12');
    expect(assignButton().disabled).toBe(true);
    type('EK serial', 'EK-1');
    expect(assignButton().disabled).toBe(false);
    type('EK serial', '  ');
    expect(assignButton().disabled).toBe(true);
    type('Device ID', '42');
    expect(assignButton().disabled).toBe(false);
  });

  it('shows the server refusal', async () => {
    stubControlPlane({ [ASSIGN]: refused(400, 'device identity required') });
    render(withControlPlane(<ProfileAssignmentCard />));

    type('Profile ID', '12');
    type('Device ID', '42');
    await act(async () => {
      fireEvent.click(assignButton());
    });

    expect((await screen.findByRole('alert')).textContent).toBe('Assignment refused: device identity required');
  });

  it('disables Assign profile when the server does not offer the assign op', async () => {
    off.add(ASSIGN_OP);
    const sent = stubControlPlane({ [ASSIGN]: ok(PROFILE) });
    render(withControlPlane(<ProfileAssignmentCard />));

    type('Profile ID', '12');
    type('Device ID', '42');
    const button = assignButton();
    expect(button.disabled).toBe(true);
    expect(button.title).toBe('not-configured: device');
    expect(button.getAttribute('data-capability-op')).toBe(ASSIGN_OP);
    await act(async () => {
      fireEvent.click(button);
    });
    expect(sent).toHaveLength(0);
  });
});

describe('ProfileUnassignButton', () => {
  it('unassigns only after the confirm', async () => {
    const sent = stubControlPlane({ [UNASSIGN]: ok({ ...PROFILE, mac_address: null, assigned: false }) });
    const onUnassigned = vi.fn();
    render(withControlPlane(<ProfileUnassignButton profileId="12" onUnassigned={onUnassigned} />));

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Unassign' }));
    });
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Unassign profile?')).toBeTruthy();
    expect(sent).toHaveLength(0);

    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Unassign' }));
    });

    expect(sent).toEqual([{ method: 'POST', path: '/api/v1/device/profiles/12/unassign', body: {} }]);
    expect(onUnassigned).toHaveBeenCalledTimes(1);
    expect(onUnassigned.mock.calls[0][0]).toMatchObject({ id: '12', assigned: false });
    expect(screen.getAllByTestId('toast').some((t) => t.textContent?.includes('Profile unassigned'))).toBe(true);
  });

  it('sends nothing on Cancel', async () => {
    const sent = stubControlPlane({});
    const onUnassigned = vi.fn();
    render(withControlPlane(<ProfileUnassignButton profileId="12" onUnassigned={onUnassigned} />));

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Unassign' }));
    });
    const dialog = await screen.findByRole('dialog');
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    });

    expect(sent).toHaveLength(0);
    expect(onUnassigned).not.toHaveBeenCalled();
  });

  it('disables Unassign when the server does not offer the unassign op', () => {
    off.add(UNASSIGN_OP);
    stubControlPlane({});
    render(withControlPlane(<ProfileUnassignButton profileId="12" onUnassigned={vi.fn()} />));

    const button = screen.getByRole('button', { name: 'Unassign' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.title).toBe('not-configured: device');
    expect(button.getAttribute('data-capability-op')).toBe(UNASSIGN_OP);
  });
});
