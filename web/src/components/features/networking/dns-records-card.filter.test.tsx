import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { DNSRecordsCard } from './dns-records-card';

// #2060: the DNS records card sends the record-type filter to the server as
// ?type= and counts the records it shows per type.

const RECORDS_PATH = 'GET /api/v1/dns/zones/example.test/records';

const RECORDS = [
  { type: 'RECORD_TYPE_A', a: { name: 'www', value: '192.0.2.10', ttl: 300 } },
  { type: 'RECORD_TYPE_A', a: { name: 'api', value: '192.0.2.11', ttl: 300 } },
  { type: 'RECORD_TYPE_AAAA', aaaa: { name: 'www', value: '2001:db8::10', ttl: 300 } },
  { type: 'RECORD_TYPE_MX', mx: { name: '@', value: 'mail.example.test', priority: 10, ttl: 3600 } },
];

function lastURL(): URL {
  const input = vi.mocked(fetch).mock.calls.at(-1)![0];
  return new URL(input instanceof Request ? input.url : String(input));
}

async function selectType(value: string) {
  await act(async () => {
    fireEvent.change(screen.getByLabelText('Record type'), { target: { value } });
  });
}

describe('DNSRecordsCard record-type filter', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('offers every filter type', async () => {
    stubControlPlane({ [RECORDS_PATH]: ok({ records: RECORDS }) });
    render(withControlPlane(<DNSRecordsCard zoneName="example.test" />));

    const select = (await screen.findByLabelText('Record type')) as HTMLSelectElement;
    expect(Array.from(select.options).map((o) => o.textContent)).toEqual([
      'All types',
      'A',
      'AAAA',
      'CNAME',
      'MX',
      'NS',
      'TXT',
      'SRV',
      'CAA',
    ]);
    expect(select.value).toBe('');
  });

  it('counts the records per type', async () => {
    stubControlPlane({ [RECORDS_PATH]: ok({ records: RECORDS }) });
    render(withControlPlane(<DNSRecordsCard zoneName="example.test" />));

    await waitFor(() => expect(screen.getByTestId('dns-record-counts').textContent).toBe('A 2 · AAAA 1 · MX 1'));
  });

  it('sends the type filter to the server', async () => {
    const sent = stubControlPlane({ [RECORDS_PATH]: ok({ records: RECORDS }) });
    render(withControlPlane(<DNSRecordsCard zoneName="example.test" />));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(lastURL().search).toBe('');

    await selectType('AAAA');

    await waitFor(() => {
      expect(sent.filter((r) => r.path === '/api/v1/dns/zones/example.test/records')).toHaveLength(2);
      expect(lastURL().searchParams.get('type')).toBe('AAAA');
    });
  });

  it('clears the filter', async () => {
    const sent = stubControlPlane({ [RECORDS_PATH]: ok({ records: RECORDS }) });
    render(withControlPlane(<DNSRecordsCard zoneName="example.test" />));
    await waitFor(() => expect(sent).toHaveLength(1));

    await selectType('MX');
    await waitFor(() => expect(sent).toHaveLength(2));
    await selectType('');

    await waitFor(() => {
      expect(sent.filter((r) => r.path === '/api/v1/dns/zones/example.test/records')).toHaveLength(3);
      expect(lastURL().search).toBe('');
    });
  });
});
