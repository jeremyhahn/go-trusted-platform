import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer, type SentRequest } from '@/test/control-plane-fetch';
import DNSZoneDetailPage from './dns-zone-detail-client';

// #2060: the zone page reads the zone through GET /dns/zones/{zone}, writes its
// records through POST / PUT / DELETE /records (the delete only after a
// confirm), and edits the zone's TTL and description through PUT
// /dns/zones/{zone}, all on the real SDK client.

vi.mock('next/navigation', () => ({
  useParams: () => ({ zone: 'example.test' }),
  usePathname: () => '/networking/dns/example.test',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

// Radix DropdownMenu does not open in jsdom; render its items as plain buttons.
vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div role="menu">{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: ({ children, onClick }: { children: ReactNode; onClick?: () => void }) => (
    <button type="button" role="menuitem" onClick={onClick}>{children}</button>
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
        description: 'lab zone',
        internal: true,
        records: {
          aRecords: [{ name: 'www', value: '192.0.2.10', ttl: 300 }],
          aaaaRecords: [{ name: 'www', value: '2001:db8::10', ttl: 300 }],
        },
      },
    }),
    [`GET ${ZONE}/dnssec`]: ok({ enabled: false, zoneSigned: false, keys: [], dsRecords: [], algorithm: '', keySize: '' }),
  };
}

function zoneReads(sent: SentRequest[]): number {
  return sent.filter((r) => r.method === 'GET' && r.path === ZONE).length;
}

function sentTo(sent: SentRequest[], method: string, path: string): SentRequest[] {
  return sent.filter((r) => r.method === method && r.path === path);
}

async function renderPage() {
  render(withControlPlane(<DNSZoneDetailPage />));
  await screen.findByRole('heading', { level: 1, name: 'example.test' });
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

async function rowAction(cellText: string, action: string) {
  const row = screen.getByText(cellText).closest('tr') as HTMLElement;
  await act(async () => {
    fireEvent.click(within(row).getByRole('menuitem', { name: action }));
  });
}

function setField(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe('DNSZoneDetailPage record writes and zone edits', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the zone it read through GET /dns/zones/{zone}', async () => {
    stubControlPlane(baseRoutes());
    await renderPage();

    expect(screen.getByText('192.0.2.10')).toBeDefined();
    expect(screen.getByText('2001:db8::10')).toBeDefined();
    expect(screen.getByText('lab zone')).toBeDefined();
  });

  it('adds an A record through POST /records and re-reads the zone', async () => {
    const sent = stubControlPlane({ ...baseRoutes(), [`POST ${RECORDS}`]: ok({}) });
    await renderPage();
    const before = zoneReads(sent);

    await click('Add Record');
    await screen.findByRole('dialog');
    setField('Name', 'api');
    setField('Value', '192.0.2.11');
    await click('Create');

    await waitFor(() => expect(sentTo(sent, 'POST', RECORDS)).toHaveLength(1));
    const body = sentTo(sent, 'POST', RECORDS)[0].body as { record: { type: string; a: unknown } };
    expect(body.record.type).toBe('RECORD_TYPE_A');
    expect(body.record.a).toEqual({ name: 'api', value: '192.0.2.11', ttl: 3600 });
    expect(await screen.findByText('Success: DNS record created successfully')).toBeDefined();
    await waitFor(() => expect(zoneReads(sent)).toBeGreaterThan(before));
  });

  it('edits a record through PUT /records with the old and the new record', async () => {
    const sent = stubControlPlane({ ...baseRoutes(), [`PUT ${RECORDS}`]: ok({}) });
    await renderPage();

    await rowAction('192.0.2.10', 'Edit');
    await screen.findByRole('dialog');
    setField('Value', '192.0.2.12');
    await click('Update');

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

    await rowAction('192.0.2.10', 'Delete');
    expect(sentTo(sent, 'DELETE', del)).toHaveLength(0);
    expect(await screen.findByText('Delete this record?')).toBeDefined();
    expect(screen.getByText('A www is removed from example.test.')).toBeDefined();

    await click('Cancel');
    await waitFor(() => expect(screen.queryByText('Delete this record?')).toBeNull());
    expect(sent.some((r) => r.method === 'DELETE')).toBe(false);

    const before = zoneReads(sent);
    await rowAction('192.0.2.10', 'Delete');
    await screen.findByText('Delete this record?');
    await click('Delete record');

    await waitFor(() => expect(sentTo(sent, 'DELETE', del)).toHaveLength(1));
    expect(sent.filter((r) => r.method === 'DELETE')).toHaveLength(1);
    expect(await screen.findByText('Success: DNS record deleted successfully')).toBeDefined();
    await waitFor(() => expect(zoneReads(sent)).toBeGreaterThan(before));
  });

  it('a refused delete shows the server message', async () => {
    const sent = stubControlPlane({
      ...baseRoutes(),
      [`DELETE ${RECORDS}/A/www`]: refused(404, 'record not found'),
    });
    await renderPage();

    await rowAction('192.0.2.10', 'Delete');
    await screen.findByText('Delete this record?');
    const before = zoneReads(sent);
    await click('Delete record');

    const toast = await screen.findByText(/record not found/);
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(zoneReads(sent)).toBe(before);
  });

  it('edits the zone through PUT /dns/zones/{zone}', async () => {
    const sent = stubControlPlane({ ...baseRoutes(), [`PUT ${ZONE}`]: ok({}) });
    await renderPage();
    const before = zoneReads(sent);

    await click('Edit Zone');
    await screen.findByRole('dialog', { name: 'Edit Zone' });
    expect((screen.getByLabelText('TTL (seconds)') as HTMLInputElement).value).toBe('3600');
    expect((screen.getByLabelText('Description') as HTMLInputElement).value).toBe('lab zone');
    setField('TTL (seconds)', '7200');
    setField('Description', 'edge zone');
    await click('Save');

    await waitFor(() => expect(sentTo(sent, 'PUT', ZONE)).toHaveLength(1));
    expect(sentTo(sent, 'PUT', ZONE)[0].body).toEqual({ ttl: 7200, description: 'edge zone' });
    expect(await screen.findByText('Success: Zone updated')).toBeDefined();
    await waitFor(() => expect(zoneReads(sent)).toBeGreaterThan(before));
  });

  it('refuses a zone TTL out of range and sends nothing', async () => {
    const sent = stubControlPlane({ ...baseRoutes(), [`PUT ${ZONE}`]: ok({}) });
    await renderPage();

    await click('Edit Zone');
    await screen.findByRole('dialog', { name: 'Edit Zone' });
    setField('TTL (seconds)', '30');
    await click('Save');

    expect(await screen.findByText('TTL must be a whole number from 60 to 86400.')).toBeDefined();
    expect(sentTo(sent, 'PUT', ZONE)).toHaveLength(0);
  });

  it('a refused zone update keeps the dialog open with the message', async () => {
    stubControlPlane({ ...baseRoutes(), [`PUT ${ZONE}`]: refused(400, 'ttl too large') });
    await renderPage();

    await click('Edit Zone');
    await screen.findByRole('dialog', { name: 'Edit Zone' });
    setField('TTL (seconds)', '7200');
    await click('Save');

    const toast = await screen.findByText('Error: Failed to update zone: ttl too large');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.getByRole('dialog', { name: 'Edit Zone' })).toBeDefined();
  });
});
