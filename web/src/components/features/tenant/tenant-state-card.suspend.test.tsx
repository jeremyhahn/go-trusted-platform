import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer, type SentRequest } from '@/test/control-plane-fetch';
import { TenantStateCard } from './tenant-state-card';

// #2067: the tenant state card suspends a tenant only after a confirm
// (POST /api/v1/tenants/{id}/suspend), resumes a suspended one at once
// (POST /api/v1/tenants/{id}/resume), and re-reads the tenant after each;
// a refusal is shown verbatim and the shown tenant is kept.

const BY_NAME = 'GET /api/v1/tenants/by-name/acme';
const SUSPEND = 'POST /api/v1/tenants/t-1/suspend';
const RESUME = 'POST /api/v1/tenants/t-1/resume';

function storedTenant(state: string): Answer {
  return ok({ tenant: { id: 't-1', name: 'acme', displayName: 'ACME', state } });
}

function count(sent: SentRequest[], key: string): number {
  return sent.filter((r) => `${r.method} ${r.path}` === key).length;
}

async function clickButton(button: HTMLElement) {
  await act(async () => {
    fireEvent.click(button);
  });
}

async function findAcme() {
  render(withControlPlane(<TenantStateCard />));
  fireEvent.change(screen.getByLabelText('Tenant name'), { target: { value: 'acme' } });
  await clickButton(screen.getByRole('button', { name: 'Find' }));
  await screen.findByTestId('tenant-state-id');
}

describe('TenantStateCard suspend and resume', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('asks before suspending and sends nothing on Cancel', async () => {
    const sent = stubControlPlane({ [BY_NAME]: storedTenant('TENANT_STATE_ACTIVE') });
    await findAcme();

    await clickButton(screen.getByRole('button', { name: 'Suspend' }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Suspend ACME?');
    await clickButton(within(dialog).getByRole('button', { name: 'Cancel' }));

    expect(count(sent, SUSPEND)).toBe(0);
  });

  it('suspends after the confirm and re-reads', async () => {
    const sent = stubControlPlane({
      [BY_NAME]: storedTenant('TENANT_STATE_ACTIVE'),
      [SUSPEND]: ok({ status: { success: true, message: 'tenant suspended successfully' } }),
    });
    await findAcme();

    await clickButton(screen.getByRole('button', { name: 'Suspend' }));
    const dialog = await screen.findByRole('dialog');
    await clickButton(within(dialog).getByRole('button', { name: 'Suspend' }));

    const toast = await screen.findByText('Tenant suspended: tenant suspended successfully');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(count(sent, SUSPEND)).toBe(1);
    expect(count(sent, BY_NAME)).toBe(2);
  });

  it('resumes a suspended tenant at once', async () => {
    const sent = stubControlPlane({
      [BY_NAME]: storedTenant('TENANT_STATE_SUSPENDED'),
      [RESUME]: ok({ status: { success: true, message: 'tenant resumed successfully' } }),
    });
    await findAcme();

    await clickButton(screen.getByRole('button', { name: 'Resume' }));

    expect(screen.queryByRole('dialog')).toBeNull();
    const toast = await screen.findByText('Tenant resumed: tenant resumed successfully');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(count(sent, RESUME)).toBe(1);
  });

  it('shows a refusal verbatim and keeps the tenant', async () => {
    stubControlPlane({
      [BY_NAME]: storedTenant('TENANT_STATE_ACTIVE'),
      [SUSPEND]: refused(409, 'tenant has running workloads'),
    });
    await findAcme();

    await clickButton(screen.getByRole('button', { name: 'Suspend' }));
    const dialog = await screen.findByRole('dialog');
    await clickButton(within(dialog).getByRole('button', { name: 'Suspend' }));

    const toast = await screen.findByText('Suspend failed: tenant has running workloads');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.getByTestId('tenant-state-id').textContent).toBe('t-1');
  });
});
