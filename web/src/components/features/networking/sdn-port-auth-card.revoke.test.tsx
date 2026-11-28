import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { SDNPortAuthCard } from './sdn-port-auth-card';

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }),
}));

const AUTH = '/api/v1/sdn/bridges/br0/ports/p1/auth';
// Made-up bytes, no real certificate.
const PEM = '-----BEGIN CERTIFICATE-----\nTUlJQg==\n-----END CERTIFICATE-----';
const REVOKE_REFUSED = 'sdn/policy: RevokePortAuth is refused: port authentication is not enforced on the switch';

const authenticated = ok({
  status: { success: true, message: 'ok' },
  auth: { authenticated: true, certificateCn: 'port-p1.example.com' },
});
const revoked = ok({ status: { success: true, message: 'revoked' } });

function renderCard() {
  render(withControlPlane(<SDNPortAuthCard bridgeId="br0" portId="p1" />));
}

async function openRevoke() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
  });
  return screen.findByRole('dialog');
}

async function confirmRevoke() {
  const dialog = await openRevoke();
  await act(async () => {
    fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke' }));
  });
}

function deletes(sent: { method: string; path: string }[]) {
  return sent.filter((r) => r.method === 'DELETE' && r.path === AUTH);
}

describe('SDNPortAuthCard revoke', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('asks before revoking and sends nothing on Cancel', async () => {
    const sent = stubControlPlane({ [`DELETE ${AUTH}`]: revoked });
    renderCard();

    const dialog = await openRevoke();
    expect(dialog.textContent).toContain('Revoke port authentication?');
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(deletes(sent)).toHaveLength(0);
  });

  it('revokes after the confirm', async () => {
    const sent = stubControlPlane({ [`DELETE ${AUTH}`]: revoked });
    renderCard();

    await confirmRevoke();

    const toast = await screen.findByText('Port authentication revoked: Port p1');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(deletes(sent)).toHaveLength(1);
    expect(screen.getByTestId('sdn-port-auth-state').textContent).toBe('Not authenticated');
  });

  it('shows the revoke refusal verbatim', async () => {
    stubControlPlane({ [`DELETE ${AUTH}`]: refused(409, REVOKE_REFUSED) });
    renderCard();

    await confirmRevoke();

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toBe(REVOKE_REFUSED);
    const toast = await screen.findByText((text) => text.startsWith('Revoke failed: sdn/policy: RevokePortAuth is refused'));
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });

  it('revokes after an authenticate', async () => {
    const sent = stubControlPlane({ [`POST ${AUTH}`]: authenticated, [`DELETE ${AUTH}`]: revoked });
    renderCard();

    fireEvent.change(screen.getByLabelText('Certificate'), { target: { value: PEM } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Authenticate' }));
    });
    await waitFor(() => expect(screen.getByTestId('sdn-port-auth-state').textContent).toBe('Authenticated'));

    await confirmRevoke();

    await waitFor(() => expect(screen.getByTestId('sdn-port-auth-state').textContent).toBe('Not authenticated'));
    expect(sent.map((r) => `${r.method} ${r.path}`)).toEqual([`POST ${AUTH}`, `DELETE ${AUTH}`]);
  });
});
