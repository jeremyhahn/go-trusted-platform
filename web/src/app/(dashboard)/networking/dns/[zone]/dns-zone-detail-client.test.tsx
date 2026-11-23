import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import DNSZoneDetailPage from './dns-zone-detail-client';

// #2060: the DNS zone page mounts DNSRecordsCard, which lists the zone's
// records through the SDK DNSService ListRecords, next to the record writes
// card built from GetZone.

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

const ZONE_PATH = 'GET /api/v1/dns/zones/example.test';
const RECORDS_PATH = 'GET /api/v1/dns/zones/example.test/records';
const DNSSEC_PATH = 'GET /api/v1/dns/zones/example.test/dnssec';

const RECORDS = [
  { type: 'RECORD_TYPE_A', a: { name: 'www', value: '192.0.2.10', ttl: 300 } },
  { type: 'RECORD_TYPE_A', a: { name: 'api', value: '192.0.2.11', ttl: 300 } },
  { type: 'RECORD_TYPE_AAAA', aaaa: { name: 'www', value: '2001:db8::10', ttl: 300 } },
  { type: 'RECORD_TYPE_MX', mx: { name: '@', value: 'mail.example.test', priority: 10, ttl: 3600 } },
];

function routes() {
  return {
    [ZONE_PATH]: ok({
      zone: { name: 'example.test', records: { aRecords: [{ name: 'www', value: '192.0.2.10', ttl: 300 }] } },
    }),
    [RECORDS_PATH]: ok({ records: RECORDS }),
    [DNSSEC_PATH]: ok({ enabled: true, zoneSigned: false, keys: [], dsRecords: [], algorithm: '', keySize: '' }),
  };
}

describe('DNSZoneDetailPage records card', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    off.clear();
  });

  it("lists the zone's records through GET /dns/zones/{zone}/records on the zone page", async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<DNSZoneDetailPage />));

    expect(await screen.findByText(/Records — example\.test/)).toBeDefined();
    await waitFor(() => expect(screen.getAllByTestId('dns-record-row')).toHaveLength(4));
    const listed = sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/dns/zones/example.test/records');
    expect(listed).toHaveLength(1);
  });

  it('keeps the record writes card next to it', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<DNSZoneDetailPage />));

    expect(await screen.findByText('DNS Records')).toBeDefined();
    expect(screen.getAllByRole('button', { name: /Add Record/ }).length).toBeGreaterThan(0);
  });
});

describe('DNSZoneDetailPage capability gate', () => {
  const ADD_RECORD_OP = 'POST /api/v1/dns/zones/{zone}/records';

  function addRecordButton(): HTMLButtonElement | null {
    return document.querySelector(`[data-capability-op="${ADD_RECORD_OP}"]`) as HTMLButtonElement | null;
  }

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    off.clear();
  });

  it("withholds Add Record with the server's reason when POST /api/v1/dns/zones/{zone}/records is not offered", async () => {
    off.add(ADD_RECORD_OP);
    stubControlPlane(routes());
    render(withControlPlane(<DNSZoneDetailPage />));

    expect(await screen.findByText('DNS Records')).toBeDefined();
    const button = addRecordButton();
    expect(button).not.toBeNull();
    expect(button?.textContent).toContain('Add Record');
    expect(button?.disabled).toBe(true);
    expect(button?.getAttribute('title')).toBe('not-configured: dns');
    expect(button?.getAttribute('data-capability-enabled')).toBe('false');

    fireEvent.click(button as HTMLButtonElement);
    expect(screen.queryByText('Add DNS Record')).toBeNull();
  });

  it('leaves Add Record enabled and opens the record form when the server offers it', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<DNSZoneDetailPage />));

    expect(await screen.findByText('DNS Records')).toBeDefined();
    const button = addRecordButton();
    expect(button).not.toBeNull();
    expect(button?.getAttribute('data-capability-enabled')).toBe('true');
    expect(button?.disabled).toBe(false);

    fireEvent.click(button as HTMLButtonElement);
    expect(await screen.findByText('Add DNS Record')).toBeDefined();
  });
});
