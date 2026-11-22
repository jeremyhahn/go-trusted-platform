import type { ReactNode } from 'react';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { Certificate } from '@/types/security';
import { CertTable } from './cert-table';

// Opening a Radix menu in jsdom is slow, so the row menu renders its items
// inline (as in device-table.test.tsx). The actions and their handlers are
// the table's own; only the popup machinery is replaced.
vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div role="menu">{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: ({
    children,
    className,
    onClick,
  }: {
    children: ReactNode;
    className?: string;
    onClick?: () => void;
  }) => (
    <div role="menuitem" className={className} onClick={onClick}>
      {children}
    </div>
  ),
}));

const DAY = 24 * 60 * 60 * 1000;

function inDays(days: number): string {
  return new Date(Date.now() + days * DAY).toISOString();
}

function cert(overrides: Partial<Certificate> = {}): Certificate {
  return {
    id: 'leaf',
    subject: 'CN=device-7',
    issuer: 'CN=Intermediate CA',
    serialNumber: '0a:1b',
    type: 'leaf',
    status: 'active',
    notBefore: inDays(-10),
    notAfter: inDays(355),
    publicKeyAlgorithm: 'ECDSA P-256',
    signatureAlgorithm: 'ECDSA-SHA256',
    ...overrides,
  };
}

// The column headers carry sort menus too, so the row menu is looked up in
// the first body row.
function rowMenu(): HTMLElement | null {
  const body = screen.getAllByRole('rowgroup')[1];
  return within(within(body).getAllByRole('row')[0]).queryByRole('menu');
}

function items(): string[] {
  const menu = rowMenu();
  return menu ? within(menu).queryAllByRole('menuitem').map((el) => el.textContent ?? '') : [];
}

function item(name: string): HTMLElement {
  return within(rowMenu()!).getByRole('menuitem', { name });
}

describe('CertTable', () => {
  afterEach(() => cleanup());

  it('shows an empty table for no certificates', () => {
    render(<CertTable certificates={[]} />);
    expect(screen.getByText('No results.')).toBeDefined();
  });

  it('shows a skeleton and no rows while loading', () => {
    const { container } = render(<CertTable certificates={[cert()]} loading />);
    expect(screen.queryByText('CN=device-7')).toBeNull();
    expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0);
  });

  it('shows each certificate column', () => {
    render(<CertTable certificates={[cert()]} />);
    expect(screen.getByText('CN=device-7')).toBeDefined();
    expect(screen.getByText('CN=Intermediate CA')).toBeDefined();
    expect(screen.getByText('0a:1b')).toBeDefined();
    expect(screen.getByText('leaf', { selector: '.capitalize' })).toBeDefined();
    expect(screen.getByText('active', { selector: ':not(button)' })).toBeDefined();
    expect(screen.getByText(new Date(cert().notAfter).toLocaleDateString())).toBeDefined();
    expect(screen.queryByText('Expiring soon')).toBeNull();
  });

  it('flags a certificate expiring within 30 days', () => {
    const notAfter = inDays(5);
    render(<CertTable certificates={[cert({ notAfter })]} />);
    expect(screen.getByText('Expiring soon')).toBeDefined();
    expect(screen.getByText(new Date(notAfter).toLocaleDateString()).className).toContain('text-orange-500');
  });

  it('shows an expired date in red without the expiring-soon note', () => {
    const notAfter = inDays(-2);
    render(<CertTable certificates={[cert({ notAfter, status: 'expired' })]} />);
    expect(screen.queryByText('Expiring soon')).toBeNull();
    expect(screen.getByText(new Date(notAfter).toLocaleDateString()).className).toContain('text-destructive');
  });

  it('offers no row menu without handlers', () => {
    render(<CertTable certificates={[cert()]} />);
    expect(rowMenu()).toBeNull();
  });

  it('offers every action for an active certificate and passes the row to each', () => {
    const c = cert();
    const onView = vi.fn();
    const onDownload = vi.fn();
    const onRenew = vi.fn();
    const onRevoke = vi.fn();
    render(
      <CertTable certificates={[c]} onView={onView} onDownload={onDownload} onRenew={onRenew} onRevoke={onRevoke} />
    );
    expect(items()).toEqual(['View Details', 'Download', 'Renew', 'Revoke']);
    for (const name of items()) {
      fireEvent.click(item(name));
    }
    expect(onView).toHaveBeenCalledWith(c);
    expect(onDownload).toHaveBeenCalledWith(c);
    expect(onRenew).toHaveBeenCalledWith(c);
    expect(onRevoke).toHaveBeenCalledWith(c);
    expect(item('Revoke').className).toContain('text-destructive');
    // Renew follows View and Download, and Revoke is always set apart.
    expect(rowMenu()!.querySelectorAll('hr')).toHaveLength(2);
  });

  it('sets Renew apart only when an action precedes it', () => {
    render(<CertTable certificates={[cert()]} onRenew={vi.fn()} />);
    expect(items()).toEqual(['Renew']);
    expect(rowMenu()!.querySelectorAll('hr')).toHaveLength(0);
  });

  it.each(['revoked', 'expired'] as const)('offers no Renew or Revoke for a %s certificate', (status) => {
    render(
      <CertTable
        certificates={[cert({ status })]}
        onView={vi.fn()}
        onDownload={vi.fn()}
        onRenew={vi.fn()}
        onRevoke={vi.fn()}
      />
    );
    expect(items()).toEqual(['View Details', 'Download']);
  });

  it('renders no menu for a revoked certificate with only Renew and Revoke handlers', () => {
    render(<CertTable certificates={[cert({ status: 'revoked' })]} onRenew={vi.fn()} onRevoke={vi.fn()} />);
    expect(rowMenu()).toBeNull();
  });

  it('filters rows by subject search', () => {
    render(
      <CertTable
        certificates={[
          cert(),
          cert({ id: 'other', subject: 'CN=gateway-1', serialNumber: '0c' }),
        ]}
      />
    );
    fireEvent.change(screen.getByPlaceholderText('Search certificates by subject...'), {
      target: { value: 'gateway' },
    });
    expect(screen.getByText('CN=gateway-1')).toBeDefined();
    expect(screen.queryByText('CN=device-7')).toBeNull();
  });

  it('pages after ten certificates', () => {
    const many = Array.from({ length: 11 }, (_, i) =>
      cert({ id: `c${i}`, subject: `CN=device-${String(i).padStart(2, '0')}`, serialNumber: `s${i}` })
    );
    render(<CertTable certificates={many} />);
    expect(screen.getByText('CN=device-00')).toBeDefined();
    expect(screen.queryByText('CN=device-10')).toBeNull();
  });
});
