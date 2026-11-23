import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { certificateToBase64 } from '@/hooks/use-sdn-port-auth';
import { SDNPortAuthCard, guessCertificateFormat } from './sdn-port-auth-card';

const { off } = vi.hoisted(() => ({ off: new Set<string>() }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) => (off.has(op) ? { enabled: false, reason: 'not-configured: sdn' } : { enabled: true }),
  }),
}));

const AUTH_OP = 'POST /api/v1/sdn/bridges/{name}/ports/{port}/auth';
const REVOKE_OP = 'DELETE /api/v1/sdn/bridges/{name}/ports/{port}/auth';

const AUTH = '/api/v1/sdn/bridges/br0/ports/p1/auth';
// Made-up bytes, no real certificate.
const PEM = '-----BEGIN CERTIFICATE-----\nTUlJQg==\n-----END CERTIFICATE-----';
const DER = 'MIIBCgKCAQEA';
const NOT_ENFORCED = 'sdn/policy: AuthenticatePort is refused: port authentication is not enforced on the switch';

const authenticated = ok({
  status: { success: true, message: 'ok' },
  auth: { authenticated: true, certificateCn: 'port-p1.example.com' },
});

function renderCard() {
  render(withControlPlane(<SDNPortAuthCard bridgeId="br0" portId="p1" />));
}

async function clickAuthenticate() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Authenticate' }));
  });
}

describe('SDNPortAuthCard authenticate', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    off.clear();
  });

  it('sends a PEM as base64 and shows the authenticated port', async () => {
    const sent = stubControlPlane({ [`POST ${AUTH}`]: authenticated });
    renderCard();

    fireEvent.change(screen.getByLabelText('Certificate'), { target: { value: PEM } });
    await clickAuthenticate();

    const toast = await screen.findByText('Port authenticated: Port p1 accepted port-p1.example.com');
    expect(toast.getAttribute('data-variant')).toBe('success');
    const posts = sent.filter((r) => r.method === 'POST' && r.path === AUTH);
    expect(posts).toHaveLength(1);
    expect(posts[0].body).toEqual({ certificate: certificateToBase64(PEM), format: 'PEM' });
    expect(screen.getByTestId('sdn-port-auth-state').textContent).toBe('Authenticated');
    expect(screen.getByTestId('sdn-port-auth-cn').textContent).toBe('port-p1.example.com');
  });

  it('sends a DER as given', async () => {
    const sent = stubControlPlane({ [`POST ${AUTH}`]: authenticated });
    renderCard();

    fireEvent.change(screen.getByLabelText('Certificate format'), { target: { value: 'DER' } });
    fireEvent.change(screen.getByLabelText('Certificate'), { target: { value: DER } });
    await clickAuthenticate();

    await screen.findByTestId('sdn-port-auth-state');
    const posts = sent.filter((r) => r.method === 'POST' && r.path === AUTH);
    expect(posts).toHaveLength(1);
    expect(posts[0].body).toEqual({ certificate: DER, format: 'DER' });
  });

  it('shows the not-enforced refusal verbatim', async () => {
    stubControlPlane({ [`POST ${AUTH}`]: refused(409, NOT_ENFORCED) });
    renderCard();

    fireEvent.change(screen.getByLabelText('Certificate'), { target: { value: PEM } });
    await clickAuthenticate();

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toBe(NOT_ENFORCED);
    const toast = await screen.findByText((text) => text.startsWith('Authenticate failed: sdn/policy: AuthenticatePort is refused'));
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByTestId('sdn-port-auth-state')).toBeNull();
    expect((screen.getByLabelText('Certificate') as HTMLTextAreaElement).value).toBe(PEM);
  });

  it('does not send an empty certificate', async () => {
    const sent = stubControlPlane({ [`POST ${AUTH}`]: authenticated });
    renderCard();

    const button = screen.getByRole('button', { name: 'Authenticate' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('Certificate'), { target: { value: '   \n ' } });
    expect(button.disabled).toBe(true);
    await act(async () => {
      fireEvent.click(button);
    });
    expect(sent).toHaveLength(0);
  });

  it('guesses the format', () => {
    expect(guessCertificateFormat(PEM)).toBe('PEM');
    expect(guessCertificateFormat(DER)).toBe('DER');
    expect(guessCertificateFormat('')).toBe('DER');
  });
});

describe('SDNPortAuthCard capability gate (#2064)', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    off.clear();
  });

  it("withholds Authenticate with the server's reason when POST .../auth is not offered", async () => {
    off.add(AUTH_OP);
    const sent = stubControlPlane({ [`POST ${AUTH}`]: authenticated });
    renderCard();

    fireEvent.change(screen.getByLabelText('Certificate'), { target: { value: PEM } });
    const button = screen.getByRole('button', { name: 'Authenticate' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.getAttribute('title')).toBe('not-configured: sdn');
    expect(button.getAttribute('data-capability-op')).toBe(AUTH_OP);
    expect(button.getAttribute('data-capability-enabled')).toBe('false');
    await clickAuthenticate();
    expect(sent).toHaveLength(0);
  });

  it("withholds Revoke with the server's reason when DELETE .../auth is not offered", async () => {
    off.add(REVOKE_OP);
    stubControlPlane({});
    renderCard();

    const button = screen.getByRole('button', { name: 'Revoke' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.getAttribute('title')).toBe('not-configured: sdn');
    expect(button.getAttribute('data-capability-op')).toBe(REVOKE_OP);
    expect(button.getAttribute('data-capability-enabled')).toBe('false');
    await act(async () => {
      fireEvent.click(button);
    });
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('leaves Authenticate and Revoke enabled when the server offers them', () => {
    stubControlPlane({});
    renderCard();

    fireEvent.change(screen.getByLabelText('Certificate'), { target: { value: PEM } });
    const authenticate = screen.getByRole('button', { name: 'Authenticate' }) as HTMLButtonElement;
    const revoke = screen.getByRole('button', { name: 'Revoke' }) as HTMLButtonElement;
    expect(authenticate.getAttribute('data-capability-enabled')).toBe('true');
    expect(authenticate.disabled).toBe(false);
    expect(revoke.getAttribute('data-capability-enabled')).toBe('true');
    expect(revoke.disabled).toBe(false);
  });
});
