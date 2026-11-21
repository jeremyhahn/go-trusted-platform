import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { DNSRecordsCard } from './dns-records-card';

// #2060: the DNS records card lists a zone's records through the SDK
// DNSService (ListRecords) and shows a refusal verbatim as a destructive toast.

const RECORDS_PATH = 'GET /api/v1/dns/zones/example.test/records';

const RECORDS = [
  { type: 'RECORD_TYPE_A', a: { name: 'www', value: '192.0.2.10', ttl: 300 } },
  { type: 'RECORD_TYPE_A', a: { name: 'api', value: '192.0.2.11', ttl: 300 } },
  { type: 'RECORD_TYPE_AAAA', aaaa: { name: 'www', value: '2001:db8::10', ttl: 300 } },
  { type: 'RECORD_TYPE_MX', mx: { name: '@', value: 'mail.example.test', priority: 10, ttl: 3600 } },
];

describe('DNSRecordsCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("lists the zone's records", async () => {
    stubControlPlane({ [RECORDS_PATH]: ok({ records: RECORDS }) });
    render(withControlPlane(<DNSRecordsCard zoneName="example.test" />));

    await waitFor(() => expect(screen.getAllByTestId('dns-record-row')).toHaveLength(4));
    const rows = screen.getAllByTestId('dns-record-row');
    const first = rows[0].textContent ?? '';
    for (const text of ['A', 'www', '192.0.2.10', '300']) expect(first).toContain(text);
    const last = rows[3].textContent ?? '';
    for (const text of ['MX', '@', '10 mail.example.test', '3600']) expect(last).toContain(text);
    expect(screen.getByText(/Records — example\.test/)).toBeDefined();
  });

  it('shows an empty zone', async () => {
    stubControlPlane({ [RECORDS_PATH]: ok({ records: [] }) });
    render(withControlPlane(<DNSRecordsCard zoneName="example.test" />));

    expect(await screen.findByText('No records in example.test')).toBeDefined();
  });

  it('shows an unknown zone verbatim', async () => {
    stubControlPlane({
      'GET /api/v1/dns/zones/nope.test/records': refused(404, 'zone not found: nope.test'),
    });
    render(withControlPlane(<DNSRecordsCard zoneName="nope.test" />));

    const toast = await screen.findByText('Records unavailable: zone not found: nope.test');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryAllByTestId('dns-record-row')).toHaveLength(0);
  });

  it('re-reads on Refresh', async () => {
    const sent = stubControlPlane({ [RECORDS_PATH]: ok({ records: RECORDS }) });
    render(withControlPlane(<DNSRecordsCard zoneName="example.test" />));
    await waitFor(() => expect(screen.getAllByTestId('dns-record-row')).toHaveLength(4));

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    });

    await waitFor(() =>
      expect(sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/dns/zones/example.test/records')).toHaveLength(2)
    );
  });
});
