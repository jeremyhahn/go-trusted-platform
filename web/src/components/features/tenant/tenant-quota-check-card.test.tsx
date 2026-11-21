import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { TenantQuotaCheckCard } from './tenant-quota-check-card';

// #2067: the quota check card asks the control plane's CheckQuota
// (POST /api/v1/tenants/{id}/quota-check) whether an amount of a resource
// fits the tenant's quota; a quota refusal is an answer, a 4xx is shown
// verbatim.

const CHECK_PATH = 'POST /api/v1/tenants/t-1/quota-check';

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function setAmount(value: string) {
  fireEvent.change(screen.getByLabelText('Amount'), { target: { value } });
}

describe('TenantQuotaCheckCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('says an amount fits', async () => {
    const sent = stubControlPlane({
      [CHECK_PATH]: ok({ tenantId: 't-1', resource: 'vcpus', amount: '4', available: true, message: 'quota available' }),
    });
    render(withControlPlane(<TenantQuotaCheckCard tenantId="t-1" />));

    fireEvent.change(screen.getByLabelText('Resource'), { target: { value: 'vcpus' } });
    setAmount('4');
    await click('Check');

    expect(await screen.findByTestId('quota-check-verdict')).toHaveProperty('textContent', 'Fits');
    expect(screen.getByTestId('quota-check-message').textContent).toBe('quota available');
    const posts = sent.filter((r) => r.method === 'POST');
    expect(posts).toEqual([{ method: 'POST', path: '/api/v1/tenants/t-1/quota-check', body: { resource: 'vcpus', amount: 4 } }]);
  });

  it('says an amount is over quota', async () => {
    stubControlPlane({
      [CHECK_PATH]: ok({ available: false, message: 'quota exceeded for vms: 10 + 5 > 12' }),
    });
    render(withControlPlane(<TenantQuotaCheckCard tenantId="t-1" />));

    setAmount('5');
    await click('Check');

    expect((await screen.findByTestId('quota-check-verdict')).textContent).toBe('Over quota');
    expect(screen.getByTestId('quota-check-message').textContent).toContain('quota exceeded for vms');
  });

  it('shows a refusal verbatim', async () => {
    stubControlPlane({ [CHECK_PATH]: refused(400, 'invalid resource type: gpus') });
    render(withControlPlane(<TenantQuotaCheckCard tenantId="t-1" />));

    await click('Check');

    expect((await screen.findByRole('alert')).textContent).toContain('invalid resource type: gpus');
    expect(screen.queryByTestId('quota-check-verdict')).toBeNull();
  });

  it('refuses a bad amount without a request', async () => {
    const sent = stubControlPlane({ [CHECK_PATH]: ok({ available: true, message: 'quota available' }) });
    render(withControlPlane(<TenantQuotaCheckCard tenantId="t-1" />));

    setAmount('0');
    await click('Check');
    const toast = await screen.findByText('Invalid amount: the amount is a whole number above 0');
    expect(toast.getAttribute('data-variant')).toBe('destructive');

    setAmount('2.5');
    await click('Check');
    await waitFor(() =>
      expect(screen.getAllByText('Invalid amount: the amount is a whole number above 0').length).toBeGreaterThan(0)
    );
    for (const t of screen.getAllByText('Invalid amount: the amount is a whole number above 0')) {
      expect(t.getAttribute('data-variant')).toBe('destructive');
    }

    expect(sent.some((r) => r.method === 'POST')).toBe(false);
  });

  it('offers every quota resource', () => {
    stubControlPlane({});
    render(withControlPlane(<TenantQuotaCheckCard tenantId="t-1" />));

    const options = Array.from((screen.getByLabelText('Resource') as HTMLSelectElement).options);
    expect(options).toHaveLength(10);
    expect(options[0].value).toBe('vms');
    expect(options[9].value).toBe('snapshots');
  });
});
