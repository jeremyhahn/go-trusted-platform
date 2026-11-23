import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { TenantBarrierCard } from './tenant-barrier-card';

// #2067: the tenant barrier card reads the barrier status and offers Initialize, Unseal and Seal, each in the capability gate.

const STATUS = 'GET /api/v1/tenants/{id}/barrier';
const INIT = 'POST /api/v1/tenants/{id}/barrier/init';
const UNSEAL = 'POST /api/v1/tenants/{id}/barrier/unseal';
const SEAL = 'POST /api/v1/tenants/{id}/barrier/seal';
const REASON = 'not-configured: tenant';

function caps(off: string[] = []): Answer {
  const capabilities = [STATUS, INIT, UNSEAL, SEAL].map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: REASON }
      : { op, kind: 'route', enabled: true }
  );
  return ok({
    capabilities,
    total: capabilities.length,
    enabled: capabilities.filter((c) => c.enabled).length,
  });
}

const barrier = (b: object) =>
  ok({ barrierStatus: { tenantId: 't1', strategy: 'shamir', hardwareBacked: false, ...b } });

function renderCard() {
  return render(withControlPlane(<TenantBarrierCard tenantId="t1" />));
}

function statusReads(sent: { method: string; path: string }[]) {
  return sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/tenants/t1/barrier').length;
}

async function enabledButton(name: string) {
  const button = screen.getByRole('button', { name });
  await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
  return button;
}

describe('TenantBarrierCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the barrier status the server reports', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'GET /api/v1/tenants/t1/barrier': barrier({ sealed: true, initialized: true }),
    });
    renderCard();

    const status = await screen.findByTestId('tenant-barrier-status');
    await waitFor(() => expect(status.textContent).toMatch(/sealed/i));
    expect(status.textContent).toMatch(/initialized/i);
    expect(status.textContent).toContain('shamir');
  });

  it('initializes with the threshold and share count and re-reads the status', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'GET /api/v1/tenants/t1/barrier': barrier({ sealed: true, initialized: false }),
      'POST /api/v1/tenants/t1/barrier/init': ok({ status: { code: 0 } }),
    });
    renderCard();

    await waitFor(() => expect(statusReads(sent)).toBe(1));
    fireEvent.change(screen.getByLabelText('Threshold'), { target: { value: '2' } });
    fireEvent.change(screen.getByLabelText('Shares'), { target: { value: '3' } });
    fireEvent.click(await enabledButton('Initialize'));

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'POST',
        path: '/api/v1/tenants/t1/barrier/init',
        body: { threshold: 2, shares: 3 },
      })
    );
    await waitFor(() => expect(statusReads(sent)).toBe(2));
  });

  it('unseals with the key the operator gives', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'GET /api/v1/tenants/t1/barrier': barrier({ sealed: true, initialized: true }),
      'POST /api/v1/tenants/t1/barrier/unseal': ok({ status: { code: 0 } }),
    });
    renderCard();

    fireEvent.change(screen.getByLabelText('Unseal key'), { target: { value: 'a2V5' } });
    fireEvent.click(await enabledButton('Unseal'));

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'POST',
        path: '/api/v1/tenants/t1/barrier/unseal',
        body: { key: 'a2V5' },
      })
    );
  });

  it('seals and shows a refusal in an alert', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'GET /api/v1/tenants/t1/barrier': barrier({ sealed: true, initialized: true }),
      'POST /api/v1/tenants/t1/barrier/seal': refused(409, 'barrier already sealed'),
    });
    renderCard();

    fireEvent.click(await enabledButton('Seal'));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('barrier already sealed');
  });

  it('withholds Initialize, Unseal and Seal with the server reason when their ops are not offered', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps([INIT, UNSEAL, SEAL]),
      'GET /api/v1/tenants/t1/barrier': barrier({ sealed: true, initialized: true }),
    });
    renderCard();

    for (const [name, op] of [
      ['Initialize', INIT],
      ['Unseal', UNSEAL],
      ['Seal', SEAL],
    ] as const) {
      const button = screen.getByRole('button', { name });
      await waitFor(() => expect(button.getAttribute('title')).toBe(REASON));
      expect((button as HTMLButtonElement).disabled).toBe(true);
      expect(button.getAttribute('data-capability-enabled')).toBe('false');
      expect(button.getAttribute('data-capability-op')).toBe(op);
    }

    fireEvent.click(screen.getByRole('button', { name: 'Seal' }));
    expect(sent.some((r) => r.method === 'POST')).toBe(false);
  });

  it('does not read the status when the server does not offer it', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps([STATUS]),
      'GET /api/v1/tenants/t1/barrier': barrier({ sealed: true, initialized: true }),
    });
    renderCard();

    await screen.findByText(REASON);
    expect(statusReads(sent)).toBe(0);
  });
});
