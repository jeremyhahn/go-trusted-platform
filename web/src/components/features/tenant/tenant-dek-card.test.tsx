import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { TenantDEKCard } from './tenant-dek-card';

// #2067: the barrier page reads the tenant's data encryption key status and
// rotates it through the SDK's TenantService (GET /tenants/{id}/dek,
// POST /tenants/{id}/dek/rotate), each in the capability gate on its op.

const STATUS = 'GET /api/v1/tenants/{id}/dek';
const ROTATE = 'POST /api/v1/tenants/{id}/dek/rotate';
const REASON = 'not-configured: tenant-dek';

function caps(off: string[] = []): Answer {
  const capabilities = [STATUS, ROTATE].map((op) =>
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

const dekStatus = ok({
  dekStatus: {
    tenantId: 't1',
    path: 'tenants/t1/dek',
    version: 3,
    algorithm: 'AES-256-GCM',
    status: 'active',
    isDefault: true,
    createdAt: '2026-01-01T00:00:00Z',
  },
});

function renderCard() {
  return render(withControlPlane(<TenantDEKCard tenantId="t1" />));
}

async function enabledButton(name: string) {
  const button = screen.getByRole('button', { name });
  await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
  return button;
}

function statusReads(sent: { method: string; path: string }[]) {
  return sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/tenants/t1/dek').length;
}

describe('TenantDEKCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the DEK status the server reports', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'GET /api/v1/tenants/t1/dek': dekStatus,
    });
    renderCard();

    const status = await screen.findByTestId('tenant-dek-status');
    await waitFor(() => expect(status.textContent).toContain('version 3'));
    expect(status.textContent).toContain('AES-256-GCM');
  });

  it('rotates only after the confirm and re-reads the status', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'GET /api/v1/tenants/t1/dek': dekStatus,
      'POST /api/v1/tenants/t1/dek/rotate': ok({
        tenantId: 't1',
        oldVersion: 3,
        newVersion: 4,
        timestamp: '2026-01-02T00:00:00Z',
      }),
    });
    renderCard();

    await waitFor(() => expect(statusReads(sent)).toBe(1));
    fireEvent.click(await enabledButton('Rotate DEK'));
    expect(sent.some((r) => r.method === 'POST')).toBe(false);

    await screen.findByText('Rotate the tenant DEK?');
    fireEvent.click(await enabledButton('Rotate'));

    await waitFor(() =>
      expect(sent).toContainEqual(expect.objectContaining({ method: 'POST', path: '/api/v1/tenants/t1/dek/rotate' }))
    );
    const rotated = await screen.findByTestId('tenant-dek-rotated');
    await waitFor(() => expect(rotated.textContent).toContain('version 4'));
    await waitFor(() => expect(statusReads(sent)).toBe(2));
  });

  it('withholds the status read and rotate the server does not offer', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps([STATUS, ROTATE]),
    });
    renderCard();

    const button = screen.getByRole('button', { name: 'Rotate DEK' });
    await waitFor(() => expect(button.getAttribute('title')).toBe(REASON));
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(button.getAttribute('data-capability-enabled')).toBe('false');
    expect(button.getAttribute('data-capability-op')).toBe(ROTATE);
    expect(await screen.findByText(REASON)).toBeTruthy();
    expect(statusReads(sent)).toBe(0);

    fireEvent.click(button);
    expect(sent.some((r) => r.method === 'POST')).toBe(false);
  });

  it('shows a refused rotate with the server message', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'GET /api/v1/tenants/t1/dek': dekStatus,
      'POST /api/v1/tenants/t1/dek/rotate': refused(503, 'dek backend not configured'),
    });
    renderCard();

    await waitFor(() => expect(statusReads(sent)).toBe(1));
    fireEvent.click(await enabledButton('Rotate DEK'));
    await screen.findByText('Rotate the tenant DEK?');
    fireEvent.click(await enabledButton('Rotate'));

    const alert = await screen.findByRole('alert');
    await waitFor(() => expect(alert.textContent).toContain('dek backend not configured'));
    expect(statusReads(sent)).toBe(1);
  });
});
