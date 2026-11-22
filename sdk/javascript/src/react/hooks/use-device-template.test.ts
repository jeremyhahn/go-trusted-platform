/**
 * Unit tests for the device-template React hook (#1802).
 *
 * The hook runs as a plain function: the platform client context, useMutation
 * and useApi are mocked (see use-eab.test.ts for the rationale).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../context.js', () => ({ usePlatformClient: vi.fn() }));
vi.mock('./use-mutation.js', () => ({
  useMutation: vi.fn((fn: unknown) => ({ mutationFn: fn })),
}));
vi.mock('./use-api.js', () => ({ useApi: vi.fn() }));

import { usePlatformClient } from '../context.js';
import { useMutation } from './use-mutation.js';
import { useApi } from './use-api.js';
import { useDeviceTemplates } from './use-device-template.js';

type Fn = (...args: unknown[]) => Promise<unknown>;

const service = {
  listTemplates: vi.fn(),
  createTemplate: vi.fn(),
  updateTemplate: vi.fn(),
  deleteTemplate: vi.fn(),
  createProfileFromTemplate: vi.fn(),
};

const refetch = vi.fn();

function listResult(data: unknown, extra: Record<string, unknown> = {}): void {
  vi.mocked(useApi).mockReturnValue({
    data,
    isLoading: false,
    error: null,
    refetch,
    ...extra,
  } as never);
}

function mutationFn(result: unknown): Fn {
  return (result as { mutationFn: Fn }).mutationFn;
}

function apiCall(): { fetcher: Fn; deps: unknown[]; options: unknown } {
  const calls = vi.mocked(useApi).mock.calls;
  const last = calls[calls.length - 1];
  if (!last) {
    throw new Error('useApi was not called');
  }
  return { fetcher: last[0] as Fn, deps: last[1], options: last[2] };
}

const tplA = { id: 'a', name: 'A' };
const tplB = { id: 'b', name: 'B' };

beforeEach(() => {
  vi.clearAllMocks();
  for (const fn of Object.values(service)) {
    fn.mockResolvedValue({ success: true, data: 'ok' });
  }
  refetch.mockResolvedValue(undefined);
  vi.mocked(usePlatformClient).mockReturnValue({ device: service } as never);
  listResult(undefined);
});

describe('useDeviceTemplates list fetcher', () => {
  it('lists without params when neither page nor pageSize is given', async () => {
    useDeviceTemplates();
    const { fetcher, deps, options } = apiCall();
    expect(deps).toEqual([undefined, undefined]);
    expect(options).toBeUndefined();
    await fetcher();
    expect(service.listTemplates).toHaveBeenCalledWith(undefined);
  });

  it('passes page and pageSize when both are given', async () => {
    useDeviceTemplates(2, 25);
    const { fetcher, deps } = apiCall();
    expect(deps).toEqual([2, 25]);
    await fetcher();
    expect(service.listTemplates).toHaveBeenCalledWith({ page: 2, pageSize: 25 });
  });

  it('passes only page when pageSize is absent', async () => {
    useDeviceTemplates(3);
    await apiCall().fetcher();
    expect(service.listTemplates).toHaveBeenCalledWith({ page: 3 });
  });

  it('passes only pageSize when page is undefined', async () => {
    useDeviceTemplates(undefined, 50);
    await apiCall().fetcher();
    expect(service.listTemplates).toHaveBeenCalledWith({ pageSize: 50 });
  });

  it('keeps a zero page and pageSize', async () => {
    useDeviceTemplates(0, 0);
    await apiCall().fetcher();
    expect(service.listTemplates).toHaveBeenCalledWith({ page: 0, pageSize: 0 });
  });

  it('propagates a list rejection through the fetcher', async () => {
    service.listTemplates.mockRejectedValueOnce(new Error('list failed'));
    useDeviceTemplates();
    await expect(apiCall().fetcher()).rejects.toThrow('list failed');
  });
});

describe('useDeviceTemplates templates', () => {
  it('returns a bare array response as is', () => {
    listResult([tplA, tplB]);
    expect(useDeviceTemplates().templates).toEqual([tplA, tplB]);
  });

  it('unwraps a {templates, pagination} envelope', () => {
    listResult({ templates: [tplB], pagination: { page: 1 } });
    expect(useDeviceTemplates().templates).toEqual([tplB]);
  });

  it.each([
    ['undefined data', undefined],
    ['null data', null],
    ['an object without templates', { pagination: {} }],
    ['a non-array templates field', { templates: 'nope' }],
    ['a string', 'templates'],
    ['a number', 42],
  ])('returns an empty list for %s', (_name, data) => {
    listResult(data);
    expect(useDeviceTemplates().templates).toEqual([]);
  });
});

describe('useDeviceTemplates state', () => {
  it('passes isLoading through', () => {
    listResult(undefined, { isLoading: true });
    expect(useDeviceTemplates().isLoading).toBe(true);
  });

  it('passes an error through', () => {
    const err = new Error('boom');
    listResult(undefined, { error: err });
    expect(useDeviceTemplates().error).toBe(err);
  });

  it('maps an undefined error to null', () => {
    listResult(undefined, { error: undefined });
    expect(useDeviceTemplates().error).toBeNull();
  });

  it('refetch calls the list refetch and returns nothing', () => {
    const result = useDeviceTemplates();
    expect(result.refetch()).toBeUndefined();
    expect(refetch).toHaveBeenCalledTimes(1);
  });
});

describe('useDeviceTemplates mutations', () => {
  it('builds exactly four mutations', () => {
    useDeviceTemplates();
    expect(useMutation).toHaveBeenCalledTimes(4);
  });

  it('create forwards the request to service.createTemplate', async () => {
    const req = { name: 'edge' };
    await expect(mutationFn(useDeviceTemplates().create)(req)).resolves.toEqual({
      success: true,
      data: 'ok',
    });
    expect(service.createTemplate).toHaveBeenCalledWith(req);
  });

  it('update forwards the request to service.updateTemplate', async () => {
    const req = { id: 'a', name: 'renamed' };
    await mutationFn(useDeviceTemplates().update)(req);
    expect(service.updateTemplate).toHaveBeenCalledWith(req);
  });

  it('remove forwards the id to service.deleteTemplate', async () => {
    await mutationFn(useDeviceTemplates().remove)('a');
    expect(service.deleteTemplate).toHaveBeenCalledWith('a');
  });

  it('createProfileFromTemplate forwards the request', async () => {
    const req = { templateId: 'a', name: 'profile' };
    await mutationFn(useDeviceTemplates().createProfileFromTemplate)(req);
    expect(service.createProfileFromTemplate).toHaveBeenCalledWith(req);
  });

  it('propagates a service rejection through the mutation function', async () => {
    service.deleteTemplate.mockRejectedValueOnce(new Error('not found'));
    await expect(mutationFn(useDeviceTemplates().remove)('missing')).rejects.toThrow('not found');
  });

  it('throws when the platform client is missing', () => {
    vi.mocked(usePlatformClient).mockImplementationOnce(() => {
      throw new Error('usePlatformClient must be used within a PlatformProvider');
    });
    expect(() => useDeviceTemplates()).toThrow('PlatformProvider');
  });
});
