import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  ok,
  refused,
  stubControlPlane,
  withControlPlane,
  type Answer,
  type SentRequest,
} from '@/test/control-plane-fetch';
import DNSZoneDetailPage from './dns-zone-detail-client';

// #2060: the zone page's record writes (add, edit, delete after a confirm)
// go through the SDK client to the control plane.

vi.mock('next/navigation', () => ({
  useParams: () => ({ zone: 'example.test' }),
  usePathname: () => '/networking/dns/example.test',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), back: vi.fn() }),
}));

const { off } = vi.hoisted(() => ({ off: new Set<string>() }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) => (off.has(op) ? { enabled: false, reason: 'not-configured: dns' } : { enabled: true }),
  }),
}));

// Radix DropdownMenu does not open in jsdom: render the items in place.
vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div role="menu">{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: ({ children, onClick }: { children: ReactNode; onClick?: () => void }) => (
    <button type="button" role="menuitem" onClick={onClick}>
      {children}
    </button>
  ),
}));

const ZONE = '/api/v1/dns/zones/example.test';
const RECORDS = `${ZONE}/records`;

function baseRoutes(): Record<string, Answer> {
  return {
    [`GET ${ZONE}`]: ok({
      zone: {
        id: 1,
        name: 'example.test',
        ttl: 3600,
        internal: true,
        records: {
          aRecords: [{ name: 'www', value: '192.0.2.10', ttl: 300 }],
          aaaaRecords: [{ name: 'www', value: '2001:db8::10', ttl: 300 }],
        },
      },
    }),
    [`GET ${RECORDS}`]: ok({ records: [] }),
    [`GET ${ZONE}/dnssec`]: ok({ enabled: false, zoneSigned: false, keys: [], dsRecords: [], algorithm: '', keySize: '' }),
  };
}

const zoneReads = (sent: SentRequest[]) => sent.filter((r) => r.method === 'GET' && r.path === ZONE).length;
const sentTo = (sent: SentRequest[], method: string, path: string) =>
  sent.filter((r) => r.method === method && r.path === path);

async function renderPage() {
  render(withControlPlane(<DNSZoneDetailPage />));
  await screen.findByRole('heading', { level: 1, name: 'example.test' });
}

function click(name: string) {
  act(() => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function rowAction(cellText: string, action: string) {
  const row = screen.getByText(cellText).closest('tr') as HTMLElement;
  act(() => {
    fireEvent.click(within(row).getByRole('menuitem', { name: action }));
  });
}

function setField(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe('DNSZoneDetailPage record writes (#2060)', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the records it read through GET /dns/zones/{zone}', async () => {
    stubControlPlane(baseRoutes());
    await renderPage();

    expect(await screen.findByText('192.0.2.10')).toBeDefined();
    expect(screen.getByText('2001:db8::10')).toBeDefined();
  });

  it('adds an A record through POST /records and re-reads the zone', async () => {
    const sent = stubControlPlane({ ...baseRoutes(), [`POST ${RECORDS}`]: ok({}) });
    await renderPage();
    await screen.findByText('192.0.2.10');
    const before = zoneReads(sent);

    click('Add Record');
    await screen.findByRole('dialog');
    setField('Name', 'api');
    setField('Value', '192.0.2.11');
    click('Create');

    await waitFor(() => expect(sentTo(sent, 'POST', RECORDS)).toHaveLength(1));
    const body = sentTo(sent, 'POST', RECORDS)[0].body as { record: { type: string; a: unknown } };
    expect(body.record.type).toBe('RECORD_TYPE_A');
    expect(body.record.a).toMatchObject({ name: 'api', value: '192.0.2.11' });
    expect(await screen.findByText('Success: DNS record created successfully')).toBeDefined();
    await waitFor(() => expect(zoneReads(sent)).toBeGreaterThan(before));
  });

  it('edits a record through PUT /records with the old and the new record', async () => {
    const sent = stubControlPlane({ ...baseRoutes(), [`PUT ${RECORDS}`]: ok({}) });
    await renderPage();
    await screen.findByText('192.0.2.10');

    rowAction('192.0.2.10', 'Edit');
    await screen.findByRole('dialog');
    setField('Value', '192.0.2.12');
    click('Update');

    await waitFor(() => expect(sentTo(sent, 'PUT', RECORDS)).toHaveLength(1));
    const body = sentTo(sent, 'PUT', RECORDS)[0].body as {
      oldRecord: { a: { value: string } };
      newRecord: { a: { value: string } };
    };
    expect(body.oldRecord.a.value).toBe('192.0.2.10');
    expect(body.newRecord.a.value).toBe('192.0.2.12');
  });

  it('deletes a record only after the confirm', async () => {
    const del = `${RECORDS}/A/www`;
    const sent = stubControlPlane({ ...baseRoutes(), [`DELETE ${del}`]: ok({}) });
    await renderPage();
    await screen.findByText('192.0.2.10');

    rowAction('192.0.2.10', 'Delete');
    expect(sent.filter((r) => r.method === 'DELETE')).toHaveLength(0);
    expect(await screen.findByText('Delete this record?')).toBeDefined();
    expect(screen.getByText('A www is removed from example.test.')).toBeDefined();

    click('Cancel');
    await waitFor(() => expect(screen.queryByText('Delete this record?')).toBeNull());
    expect(sent.filter((r) => r.method === 'DELETE')).toHaveLength(0);

    const before = zoneReads(sent);
    rowAction('192.0.2.10', 'Delete');
    await screen.findByText('Delete this record?');
    click('Delete record');

    await waitFor(() => expect(sentTo(sent, 'DELETE', del)).toHaveLength(1));
    expect(sent.filter((r) => r.method === 'DELETE')).toHaveLength(1);
    expect(await screen.findByText('Success: DNS record deleted successfully')).toBeDefined();
    await waitFor(() => expect(zoneReads(sent)).toBeGreaterThan(before));
  });

  it('a refused delete shows the server message', async () => {
    const sent = stubControlPlane({ ...baseRoutes(), [`DELETE ${RECORDS}/A/www`]: refused(404, 'record not found') });
    await renderPage();
    await screen.findByText('192.0.2.10');

    rowAction('192.0.2.10', 'Delete');
    await screen.findByText('Delete this record?');
    const before = zoneReads(sent);
    click('Delete record');

    const toast = await screen.findByText(/record not found/);
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(zoneReads(sent)).toBe(before);
  });
});
