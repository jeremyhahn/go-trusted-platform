import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import type { IDevID } from '@/types/device';
import { IDevIDTable } from './idevid-table';

const push = vi.fn();
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push, back: vi.fn() }),
}));

// Radix menus do not open in jsdom; render every item inline instead.
vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div role="menu">{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: ({ children, onClick }: { children: ReactNode; onClick?: () => void }) => (
    <div role="menuitem" onClick={onClick}>
      {children}
    </div>
  ),
}));

const DAY = 24 * 60 * 60 * 1000;

function cert(over: Partial<IDevID> = {}): IDevID {
  return {
    id: 'c1',
    deviceId: '7',
    deviceName: 'edge-7',
    subject: 'CN=edge-7',
    serialNumber: '0A:1B',
    status: 'active',
    issuedAt: '2026-01-15T00:00:00Z',
    expiresAt: new Date(Date.now() + 200 * DAY).toISOString(),
    ...over,
  };
}

async function choose(item: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('menuitem', { name: item }));
  });
}

describe('IDevIDTable', () => {
  beforeEach(() => {
    push.mockReset();
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('shows the empty state without rows', () => {
    stubControlPlane({});
    render(withControlPlane(<IDevIDTable idevids={[]} />));

    expect(screen.getByText('No IDevID certificates found')).toBeDefined();
    expect(screen.queryByRole('menuitem')).toBeNull();
  });

  it('renders one row per certificate with subject, serial and dates', () => {
    stubControlPlane({});
    render(withControlPlane(<IDevIDTable idevids={[cert()]} />));

    const row = screen.getByText('edge-7').closest('tr') as HTMLElement;
    expect(within(row).getByText('CN=edge-7')).toBeDefined();
    expect(within(row).getByText('0A:1B')).toBeDefined();
    expect(within(row).getByText('Jan 15, 2026')).toBeDefined();
    expect(within(row).getByText('Active')).toBeDefined();
  });

  it.each([
    ['active', 'Active'],
    ['revoked', 'Revoked'],
    ['expired', 'Expired'],
    ['pending', 'Pending'],
  ] as const)('labels the %s status as %s', (status, label) => {
    stubControlPlane({});
    render(withControlPlane(<IDevIDTable idevids={[cert({ status })]} />));
    expect(screen.getByText(label)).toBeDefined();
  });

  it('offers renew and revoke only on an active certificate', () => {
    stubControlPlane({});
    render(withControlPlane(<IDevIDTable idevids={[cert({ status: 'revoked' })]} />));

    expect(screen.getByRole('menuitem', { name: 'View Details' })).toBeDefined();
    expect(screen.getByRole('menuitem', { name: 'Download Certificate' })).toBeDefined();
    expect(screen.queryByRole('menuitem', { name: 'Renew Certificate' })).toBeNull();
    expect(screen.queryByRole('menuitem', { name: 'Revoke Certificate' })).toBeNull();
  });

  it('marks a certificate expiring within 30 days, and not one already expired or far off', () => {
    stubControlPlane({});
    render(
      withControlPlane(
        <IDevIDTable
          idevids={[
            cert({ id: 'soon', deviceName: 'soon', expiresAt: new Date(Date.now() + 10 * DAY).toISOString() }),
            cert({ id: 'past', deviceName: 'past', expiresAt: new Date(Date.now() - 10 * DAY).toISOString() }),
            cert({ id: 'far', deviceName: 'far', expiresAt: new Date(Date.now() + 90 * DAY).toISOString() }),
          ]}
        />
      )
    );

    expect(screen.getAllByLabelText('Expiring soon')).toHaveLength(1);
    const soon = screen.getByText('soon').closest('tr') as HTMLElement;
    expect(within(soon).getByLabelText('Expiring soon')).toBeDefined();
  });

  it('opens the details page of the certificate', () => {
    stubControlPlane({});
    render(withControlPlane(<IDevIDTable idevids={[cert()]} />));

    fireEvent.click(screen.getByRole('menuitem', { name: 'View Details' }));
    expect(push).toHaveBeenCalledWith('/devices/idevid/c1');
  });

  it('renews by deleting then regenerating the IDevID, and reports the change', async () => {
    const sent = stubControlPlane({
      'DELETE /api/v1/idevid': ok({}),
      'POST /api/v1/idevid/generate': ok({}),
    });
    const onChange = vi.fn();
    render(withControlPlane(<IDevIDTable idevids={[cert()]} onIDevIDChange={onChange} />));

    await choose('Renew Certificate');

    expect(await screen.findByText('Success: IDevID certificate for edge-7 renewed')).toBeDefined();
    expect(sent.map((r) => `${r.method} ${r.path}`)).toEqual(['DELETE /api/v1/idevid', 'POST /api/v1/idevid/generate']);
    expect(onChange).toHaveBeenCalledTimes(1);
  });

  it('stops a renewal whose delete is refused, and never regenerates', async () => {
    const sent = stubControlPlane({ 'DELETE /api/v1/idevid': refused(403, 'admin role required') });
    const onChange = vi.fn();
    render(withControlPlane(<IDevIDTable idevids={[cert()]} onIDevIDChange={onChange} />));

    await choose('Renew Certificate');

    const toast = await screen.findByText('Error: admin role required');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(sent.map((r) => r.path)).toEqual(['/api/v1/idevid']);
    expect(onChange).not.toHaveBeenCalled();
  });

  it('reports a refused regeneration during renewal', async () => {
    stubControlPlane({
      'DELETE /api/v1/idevid': ok({}),
      'POST /api/v1/idevid/generate': refused(409, 'key slot busy'),
    });
    render(withControlPlane(<IDevIDTable idevids={[cert()]} />));

    await choose('Renew Certificate');

    expect(await screen.findByText('Error: key slot busy')).toBeDefined();
  });

  it('revokes only after the operator confirms', async () => {
    const sent = stubControlPlane({ 'DELETE /api/v1/idevid/certificate': ok({}) });
    const confirm = vi.fn(() => false);
    vi.stubGlobal('confirm', confirm);
    const onChange = vi.fn();
    render(withControlPlane(<IDevIDTable idevids={[cert()]} onIDevIDChange={onChange} />));

    await choose('Revoke Certificate');
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining('edge-7'));
    expect(sent).toEqual([]);

    confirm.mockReturnValue(true);
    await choose('Revoke Certificate');

    expect(await screen.findByText('Success: Certificate revoked successfully')).toBeDefined();
    expect(sent.map((r) => `${r.method} ${r.path}`)).toEqual(['DELETE /api/v1/idevid/certificate']);
    expect(onChange).toHaveBeenCalledTimes(1);
  });

  it('shows a refused revocation', async () => {
    stubControlPlane({ 'DELETE /api/v1/idevid/certificate': refused(403, 'admin role required') });
    vi.stubGlobal('confirm', () => true);
    const onChange = vi.fn();
    render(withControlPlane(<IDevIDTable idevids={[cert()]} onIDevIDChange={onChange} />));

    await choose('Revoke Certificate');

    const toast = await screen.findByText('Error: admin role required');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(onChange).not.toHaveBeenCalled();
  });

  it('downloads the PEM as <device>-idevid.pem', async () => {
    stubControlPlane({ 'GET /api/v1/idevid/certificate': ok({ certificate: { pem: 'PEM-DATA' } }) });
    const createObjectURL = vi.fn(() => 'blob:pem');
    const revokeObjectURL = vi.fn();
    Object.assign(window.URL, { createObjectURL, revokeObjectURL });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      expect(this.download).toBe('edge-7-idevid.pem');
    });
    render(withControlPlane(<IDevIDTable idevids={[cert()]} />));

    await choose('Download Certificate');

    expect(await screen.findByText('Success: Certificate downloaded successfully')).toBeDefined();
    expect(click).toHaveBeenCalledTimes(1);
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:pem');
  });

  it('refuses a download without certificate data', async () => {
    stubControlPlane({ 'GET /api/v1/idevid/certificate': ok({}) });
    render(withControlPlane(<IDevIDTable idevids={[cert()]} />));

    await choose('Download Certificate');

    expect(await screen.findByText('Error: Failed to download certificate: No certificate data')).toBeDefined();
  });

  it('shows a refused download', async () => {
    stubControlPlane({ 'GET /api/v1/idevid/certificate': refused(404, 'no certificate installed') });
    render(withControlPlane(<IDevIDTable idevids={[cert()]} />));

    await choose('Download Certificate');

    const toast = await screen.findByText('Error: no certificate installed');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    await waitFor(() => expect(screen.getByRole('button', { name: 'Open menu' }).hasAttribute('disabled')).toBe(false));
  });
});
