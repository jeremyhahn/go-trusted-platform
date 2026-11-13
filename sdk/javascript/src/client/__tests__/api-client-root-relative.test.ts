/**
 * Regression tests for #1723 (Codex round 4 on #1741).
 *
 * `rootRelative` requests resolve their path against the root of the
 * configured `baseUrl`. A protocol-relative base (`//host/api/v1`) used to
 * fail the scheme check and fall through to the bare path, so registry
 * `listTags` and `deleteManifest` went to the browser's own host while every
 * other request went to the configured one.
 */

import { describe, it, expect, vi } from 'vitest';
import { ApiClient } from '../api-client.js';
import { RegistryService } from '../../services/registry-service.js';

function stubFetch() {
  return vi.fn((..._args: unknown[]) =>
    Promise.resolve(
      new Response('{}', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    )
  );
}

function clientFor(baseUrl: string, fetchImpl: ReturnType<typeof stubFetch>): ApiClient {
  return new ApiClient({
    baseUrl,
    fetch: fetchImpl as unknown as typeof fetch,
    retry: { maxRetries: 0 },
  });
}

function calledUrl(fetchImpl: ReturnType<typeof stubFetch>): string {
  return String(fetchImpl.mock.calls[0][0]);
}

describe('ApiClient rootRelative with a protocol-relative baseUrl', () => {
  const base = '//registry.example.test/api/v1';

  it('listTags keeps the configured host', async () => {
    const fetchImpl = stubFetch();
    const registry = new RegistryService(clientFor(base, fetchImpl));
    await registry.listTags('team/app');
    expect(calledUrl(fetchImpl)).toBe('//registry.example.test/v2/team/app/tags/list');
  });

  it('deleteManifest keeps the configured host', async () => {
    const fetchImpl = stubFetch();
    const registry = new RegistryService(clientFor(base, fetchImpl));
    await registry.deleteManifest('team/app', 'v1');
    expect(calledUrl(fetchImpl)).toBe('//registry.example.test/v2/team/app/manifests/v1');
    const init = fetchImpl.mock.calls[0][1] as RequestInit | undefined;
    expect(init?.method).toBe('DELETE');
  });

  it('getStatus still goes under the base', async () => {
    const fetchImpl = stubFetch();
    const registry = new RegistryService(clientFor(base, fetchImpl));
    await registry.getStatus();
    expect(calledUrl(fetchImpl).startsWith('//registry.example.test/')).toBe(true);
    expect(calledUrl(fetchImpl).startsWith('//registry.example.test/api/v1/')).toBe(true);
  });
});

describe('ApiClient rootRelative guards', () => {
  it('an absolute base gives its origin plus the path', async () => {
    const fetchImpl = stubFetch();
    await clientFor('https://h.example.test/api/v1', fetchImpl).get('/v2/x', {
      rootRelative: true,
    });
    expect(calledUrl(fetchImpl)).toBe('https://h.example.test/v2/x');
  });

  it('a relative base leaves the path as it is', async () => {
    const fetchImpl = stubFetch();
    await clientFor('/api', fetchImpl).get('/v2/x', { rootRelative: true });
    expect(calledUrl(fetchImpl)).toBe('/v2/x');
  });
});
