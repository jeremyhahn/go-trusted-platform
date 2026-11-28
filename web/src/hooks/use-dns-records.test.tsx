import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DNSRecord, RecordType } from 'trusted-platform-sdk';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { recordRow, shortRecordType, useDNSRecords } from './use-dns-records';

const wrapper = ({ children }: { children: React.ReactNode }) => withControlPlane(children);

function lastURL(): URL {
  const input = vi.mocked(fetch).mock.calls.at(-1)![0];
  return new URL(input instanceof Request ? input.url : String(input));
}

describe('useDNSRecords', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("lists a zone's records", async () => {
    stubControlPlane({
      'GET /api/v1/dns/zones/example.test/records': ok({
        records: [
          { type: 'RECORD_TYPE_A', a: { name: 'www', value: '192.0.2.10', ttl: 300 } },
          { type: 'RECORD_TYPE_MX', mx: { name: '@', value: 'mail.example.test', priority: 10, ttl: 3600 } },
        ],
      }),
    });
    const { result } = renderHook(() => useDNSRecords(), { wrapper });
    let res: Awaited<ReturnType<ReturnType<typeof useDNSRecords>['listRecords']>> | undefined;
    await act(async () => {
      res = await result.current.listRecords('example.test');
    });
    expect(res!.success).toBe(true);
    expect(res!.data!.records.map(recordRow)).toEqual([
      { type: 'A', name: 'www', value: '192.0.2.10', ttl: 300 },
      { type: 'MX', name: '@', value: '10 mail.example.test', ttl: 3600 },
    ]);
    expect(lastURL().search).toBe('');
  });

  it('filters by type in the query', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/dns/zones/example.test/records': ok({ records: [] }),
    });
    const { result } = renderHook(() => useDNSRecords(), { wrapper });
    let res: Awaited<ReturnType<ReturnType<typeof useDNSRecords>['listRecords']>> | undefined;
    await act(async () => {
      res = await result.current.listRecords('example.test', 'AAAA');
    });
    expect(res!.success).toBe(true);
    expect(sent[0].path).toBe('/api/v1/dns/zones/example.test/records');
    expect(lastURL().searchParams.get('type')).toBe('AAAA');
  });

  it('surfaces an unknown zone', async () => {
    stubControlPlane({
      'GET /api/v1/dns/zones/nope.test/records': refused(404, 'zone not found: nope.test'),
    });
    const { result } = renderHook(() => useDNSRecords(), { wrapper });
    let res: Awaited<ReturnType<ReturnType<typeof useDNSRecords>['listRecords']>> | undefined;
    await act(async () => {
      res = await result.current.listRecords('nope.test');
    });
    expect(res!.success).toBe(false);
    expect(res!.error?.status).toBe(404);
  });

  it('surfaces an invalid type', async () => {
    stubControlPlane({
      'GET /api/v1/dns/zones/example.test/records': refused(400, 'invalid record type: BOGUS'),
    });
    const { result } = renderHook(() => useDNSRecords(), { wrapper });
    let res: Awaited<ReturnType<ReturnType<typeof useDNSRecords>['listRecords']>> | undefined;
    await act(async () => {
      res = await result.current.listRecords('example.test', 'BOGUS' as RecordType);
    });
    expect(res!.success).toBe(false);
    expect(res!.error?.status).toBe(400);
  });

  it('shortens types and summarises records', () => {
    expect(shortRecordType('RECORD_TYPE_TXT')).toBe('TXT');
    expect(shortRecordType('CNAME')).toBe('CNAME');
    expect(
      recordRow({ type: 'RECORD_TYPE_CNAME', cname: { name: 'api', value: 'www.example.test', ttl: 60 } } as DNSRecord)
    ).toEqual({ type: 'CNAME', name: 'api', value: 'www.example.test', ttl: 60 });
    expect(recordRow({ type: 'RECORD_TYPE_DS' } as DNSRecord)).toEqual({ type: 'DS', name: '', value: '', ttl: 0 });
  });
});
