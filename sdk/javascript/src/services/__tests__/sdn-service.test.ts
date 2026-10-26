/**
 * Unit tests for the SDN list query encoding.
 *
 * The daemon's REST routes bind URL parameters to the request proto by field
 * name (`pkg/api/rest/protorest.go` decodeProtoParams), so the client must
 * name them `pagination.page`, `pagination.pageSize` and
 * `selector.matchLabels.<key>`. The old `page`, `limit` and `label_<key>`
 * names match no field and are refused (docs/sdn/api-reference-rest.md).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SDNService } from '../sdn-service.js';
import type { ApiClient } from '../../client/api-client.js';

function createMockApiClient(): ApiClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
    baseUrl: 'https://api.example.com',
  } as unknown as ApiClient;
}

/** Splits the requested URL into its path and its query parameters. */
function requested(client: ApiClient): { path: string; query: URLSearchParams } {
  const url = vi.mocked(client.get).mock.calls[0]?.[0] ?? '';
  const [path = '', query = ''] = url.split('?');
  return { path, query: new URLSearchParams(query) };
}

describe('SDNService list query encoding', () => {
  let service: SDNService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });
    service = new SDNService(mockClient);
  });

  it('names the bridge list pagination and selector by their proto fields', async () => {
    await service.listBridges({
      page: 2,
      pageSize: 25,
      selector: { matchLabels: { env: 'prod' } },
    });

    const { path, query } = requested(mockClient);
    expect(path).toBe('/v1/sdn/bridges');
    expect(Object.fromEntries(query)).toEqual({
      'pagination.page': '2',
      'pagination.pageSize': '25',
      'selector.matchLabels.env': 'prod',
    });
  });

  it('sends no query when a bridge list sets nothing', async () => {
    await service.listBridges();

    expect(mockClient.get).toHaveBeenCalledWith('/v1/sdn/bridges');
  });

  it('names the port list pagination and every selector label by their proto fields', async () => {
    await service.listPorts({
      bridgeId: 'br-int',
      page: 1,
      pageSize: 10,
      selector: { matchLabels: { role: 'uplink', zone: 'a' } },
    });

    const { path, query } = requested(mockClient);
    expect(path).toBe('/v1/sdn/bridges/br-int/ports');
    expect(Object.fromEntries(query)).toEqual({
      'pagination.page': '1',
      'pagination.pageSize': '10',
      'selector.matchLabels.role': 'uplink',
      'selector.matchLabels.zone': 'a',
    });
  });

  it('names the flow list pagination by its proto fields beside the table', async () => {
    await service.listFlows({ bridgeId: 'br-int', table: 'FLOW_TABLE_1', page: 3, pageSize: 50 });

    const { path, query } = requested(mockClient);
    expect(path).toBe('/v1/sdn/bridges/br-int/flows');
    expect(Object.fromEntries(query)).toEqual({
      'pagination.page': '3',
      'pagination.pageSize': '50',
      table: 'FLOW_TABLE_1',
    });
  });

  it('names the VLAN list selector by its proto field and sends no pagination', async () => {
    await service.listVLANs({ bridgeId: 'br-int', selector: { matchLabels: { tenant: 't1' } } });

    const { path, query } = requested(mockClient);
    expect(path).toBe('/v1/sdn/bridges/br-int/vlans');
    expect(Object.fromEntries(query)).toEqual({ 'selector.matchLabels.tenant': 't1' });
  });

  it('never sends the old page, limit or label_ names', async () => {
    await service.listPorts({
      bridgeId: 'br-int',
      page: 1,
      pageSize: 10,
      selector: { matchLabels: { env: 'dev' } },
    });

    const { query } = requested(mockClient);
    expect(query.has('page')).toBe(false);
    expect(query.has('limit')).toBe(false);
    expect(query.has('label_env')).toBe(false);
  });

  it('propagates a transport error unchanged', async () => {
    const failure = new Error('400 Bad Request: unknown parameter');
    vi.mocked(mockClient.get).mockRejectedValue(failure);

    await expect(service.listBridges({ page: 1 })).rejects.toBe(failure);
  });
});
