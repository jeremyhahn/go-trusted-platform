import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { Tenant, TenantSettings } from '@/types/tenant';
import { TenantInfoCard } from './tenant-info-card';

// #1818: the tenant card shows the tenant's name, state, creation date and
// plan, the member, active and pending counts with the active share, and the
// enabled features and allowed domains when there are any.

afterEach(cleanup);

type CardTenant = Tenant & { plan?: 'free' | 'pro' | 'enterprise'; settings?: TenantSettings };

function tenant(overrides: Partial<CardTenant> = {}): CardTenant {
  return {
    id: 't1',
    name: 'acme',
    display_name: 'Acme Corp',
    state: 'active',
    created_at: '2025-03-05T12:00:00Z',
    updated_at: '2025-03-06T12:00:00Z',
    ...overrides,
  };
}

function renderCard(t: CardTenant, counts: Partial<{ memberCount: number; activeCount: number; pendingInvitations: number }> = {}, onEdit?: () => void) {
  return render(
    <TenantInfoCard
      tenant={t}
      memberCount={counts.memberCount ?? 4}
      activeCount={counts.activeCount ?? 3}
      pendingInvitations={counts.pendingInvitations ?? 2}
      onEdit={onEdit}
    />,
  );
}

function stat(label: string) {
  return screen.getByText(label).parentElement as HTMLElement;
}

describe('TenantInfoCard', () => {
  it('shows the display name, state and creation date', () => {
    renderCard(tenant());
    expect(screen.getByText('Acme Corp')).toBeTruthy();
    expect(screen.queryByText('acme')).toBeNull();
    expect(screen.getByText('active')).toBeTruthy();
    expect(screen.getByText(/Created March 5, 2025/)).toBeTruthy();
  });

  it('falls back to the name when there is no display name', () => {
    renderCard(tenant({ display_name: '' }));
    expect(screen.getByText('acme')).toBeTruthy();
  });

  it.each(['created', 'suspended', 'deleted'] as const)('shows the %s state', (state) => {
    renderCard(tenant({ state }));
    expect(screen.getByText(state)).toBeTruthy();
  });

  it('omits the state badge when the tenant has no state', () => {
    renderCard(tenant({ state: '' as Tenant['state'] }));
    expect(screen.queryByText('active')).toBeNull();
    expect(screen.getByText(/Created March 5, 2025/)).toBeTruthy();
  });

  it('shows Unknown when the tenant has no creation date', () => {
    renderCard(tenant({ created_at: '' }));
    expect(screen.getByText(/Created Unknown/)).toBeTruthy();
  });

  it('shows Unknown when the creation date cannot be parsed', () => {
    renderCard(tenant({ created_at: 'not-a-date' }));
    expect(screen.getByText(/Created Unknown/)).toBeTruthy();
    expect(screen.queryByText(/Invalid Date/)).toBeNull();
  });

  it('shows the free plan without an icon when no plan is set', () => {
    renderCard(tenant());
    const badge = screen.getByText('Free');
    expect(badge.querySelector('svg')).toBeNull();
  });

  it.each([
    ['pro', 'Pro'],
    ['enterprise', 'Enterprise'],
  ] as const)('shows the %s plan with its icon', (plan, label) => {
    renderCard(tenant({ plan }));
    expect(screen.getByText(label).querySelector('svg')).not.toBeNull();
  });

  it('shows the member, active and pending counts with the active share', () => {
    renderCard(tenant(), { memberCount: 4, activeCount: 3, pendingInvitations: 2 });
    expect(stat('Total Members').textContent).toContain('4');
    expect(stat('Active').textContent).toContain('3');
    expect(stat('Active').textContent).toContain('75% active');
    expect(stat('Pending Invitations').textContent).toContain('2');
    expect(screen.getByText('Awaiting acceptance')).toBeTruthy();
  });

  it('rounds the active share', () => {
    renderCard(tenant(), { memberCount: 3, activeCount: 1 });
    expect(stat('Active').textContent).toContain('33% active');
  });

  it('shows a zero active share when there are no members', () => {
    renderCard(tenant(), { memberCount: 0, activeCount: 0, pendingInvitations: 0 });
    expect(stat('Active').textContent).toContain('0% active');
    expect(stat('Active').textContent).not.toContain('NaN');
  });

  it('uses the default settings when the tenant has none', () => {
    renderCard(tenant());
    expect(screen.getByText('Max: 10')).toBeTruthy();
    expect(screen.queryByText('Enabled Features')).toBeNull();
    expect(screen.queryByText('Allowed Domains')).toBeNull();
  });

  it('shows the member limit, features and domains from the settings', () => {
    renderCard(
      tenant({
        settings: { maxMembers: 50, features: ['sso', 'audit'], allowedDomains: ['example.com', 'example.org'] },
      }),
    );
    expect(screen.getByText('Max: 50')).toBeTruthy();
    expect(screen.getByText('Enabled Features')).toBeTruthy();
    expect(screen.getByText('sso')).toBeTruthy();
    expect(screen.getByText('audit')).toBeTruthy();
    expect(screen.getByText('Allowed Domains')).toBeTruthy();
    expect(screen.getByText('example.com')).toBeTruthy();
    expect(screen.getByText('example.org')).toBeTruthy();
  });

  it('omits empty feature and domain lists', () => {
    renderCard(tenant({ settings: { maxMembers: 5, features: [], allowedDomains: [] } }));
    expect(screen.getByText('Max: 5')).toBeTruthy();
    expect(screen.queryByText('Enabled Features')).toBeNull();
    expect(screen.queryByText('Allowed Domains')).toBeNull();
  });

  it('omits the domains section when the settings have no domain list', () => {
    renderCard(tenant({ settings: { maxMembers: 5, features: ['sso'] } }));
    expect(screen.getByText('Enabled Features')).toBeTruthy();
    expect(screen.queryByText('Allowed Domains')).toBeNull();
  });

  it('has no edit button without an edit handler', () => {
    renderCard(tenant());
    expect(screen.queryByRole('button', { name: /edit/i })).toBeNull();
  });

  it('calls the edit handler when Edit is clicked', () => {
    const onEdit = vi.fn();
    renderCard(tenant(), {}, onEdit);
    fireEvent.click(screen.getByRole('button', { name: /edit/i }));
    expect(onEdit).toHaveBeenCalledTimes(1);
  });
});
