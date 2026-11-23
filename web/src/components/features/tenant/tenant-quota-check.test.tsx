import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { TenantQuotaCheck } from './tenant-quota-check';

// #2067: the quotas page checks a resource amount against the tenant's quota
// through the SDK's TenantService.checkQuota (POST /tenants/{id}/quota-check),
// in the capability gate on that op.

const CHECK = 'POST /api/v1/tenants/{id}/quota-check';
const REASON = 'not-configured: tenant';

function caps(off: string[] = []): Answer {
  const capabilities = [CHECK].map((op) =>
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

function renderCard() {
  return render(withControlPlane(<TenantQuotaCheck tenantId="t1" />));
}

async function enabledButton(name: string) {
  const button = screen.getByRole('button', { name });
  await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
  return button;
}

function fill(resource: string, amount: string) {
  fireEvent.change(screen.getByLabelText('Resource'), { target: { value: resource } });
  fireEvent.change(screen.getByLabelText('Amount'), { target: { value: amount } });
}

describe('TenantQuotaCheck', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('checks a resource amount and shows the answer', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'POST /api/v1/tenants/t1/quota-check': ok({ tenantId: 't1', resource: 'vms', amount: 2, available: true }),
    });
    renderCard();

    fill('vms', '2');
    fireEvent.click(await enabledButton('Check quota'));

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'POST',
        path: '/api/v1/tenants/t1/quota-check',
        body: { resource: 'vms', amount: 2 },
      })
    );
    const result = await screen.findByTestId('tenant-quota-check-result');
    await waitFor(() => expect(result.textContent).toContain('Available'));
  });

  it('shows an exceeded quota as the server worded it', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'POST /api/v1/tenants/t1/quota-check': refused(429, 'quota exceeded for vms'),
    });
    renderCard();

    fill('vms', '500');
    fireEvent.click(await enabledButton('Check quota'));

    const result = await screen.findByTestId('tenant-quota-check-result');
    await waitFor(() => expect(result.textContent).toContain('quota exceeded for vms'));
  });

  it('shows an unavailable answer with the server message', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'POST /api/v1/tenants/t1/quota-check': ok({
        tenantId: 't1',
        resource: 'vcpus',
        amount: 64,
        available: false,
        message: 'quota exceeded',
      }),
    });
    renderCard();

    fill('vcpus', '64');
    fireEvent.click(await enabledButton('Check quota'));

    const result = await screen.findByTestId('tenant-quota-check-result');
    await waitFor(() => expect(result.textContent).toContain('quota exceeded'));
    expect(result.textContent).not.toContain('Available');
  });

  it('withholds the check the server does not offer', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps([CHECK]),
    });
    renderCard();

    const button = screen.getByRole('button', { name: 'Check quota' });
    await waitFor(() => expect(button.getAttribute('title')).toBe(REASON));
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(button.getAttribute('data-capability-enabled')).toBe('false');
    expect(button.getAttribute('data-capability-op')).toBe(CHECK);

    fireEvent.click(button);
    expect(sent.some((r) => r.method === 'POST')).toBe(false);
  });
});
