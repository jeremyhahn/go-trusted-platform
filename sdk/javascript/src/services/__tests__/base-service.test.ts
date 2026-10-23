/**
 * Unit tests for BaseService URL building.
 *
 * buildUrlUnder exists for services whose routes span more than one prefix:
 * DeviceService serves device records under `/v1/devices` and profiles and
 * templates under `/v1/device` (#266). The prefix must come from the
 * argument, and the service's own base path must not leak into the URL.
 */

import { describe, it, expect, vi } from 'vitest';
import { BaseService, type ListOptions } from '../base-service.js';
import type { ApiClient } from '../../client/api-client.js';

class ProbeService extends BaseService {
  constructor() {
    super({ get: vi.fn() } as unknown as ApiClient, '/v1/plural');
  }

  url(path?: string, options?: ListOptions): string {
    return this.buildUrl(path, options);
  }

  urlUnder(basePath: string, path?: string, options?: ListOptions): string {
    return this.buildUrlUnder(basePath, path, options);
  }
}

describe('BaseService buildUrlUnder', () => {
  const service = new ProbeService();

  it('joins the given base path and segment, ignoring the service base path', () => {
    expect(service.urlUnder('/v1/singular', '/profiles/7')).toBe('/v1/singular/profiles/7');
  });

  it('returns the bare base path when no segment is given', () => {
    expect(service.urlUnder('/v1/singular')).toBe('/v1/singular');
    expect(service.urlUnder('/v1/singular', '')).toBe('/v1/singular');
  });

  it('appends list options as query parameters', () => {
    expect(service.urlUnder('/v1/singular', '/profiles', { page: 2, limit: 10 })).toBe(
      '/v1/singular/profiles?page=2&limit=10'
    );
  });

  it('drops undefined list options instead of sending them as blank parameters', () => {
    expect(service.urlUnder('/v1/singular', '/profiles', { page: undefined, limit: undefined })).toBe(
      '/v1/singular/profiles'
    );
    expect(service.urlUnder('/v1/singular', '/profiles', {})).toBe('/v1/singular/profiles');
  });
});

describe('BaseService buildUrl', () => {
  const service = new ProbeService();

  it('builds under the service base path', () => {
    expect(service.url('/5', { page: 1 })).toBe('/v1/plural/5?page=1');
  });

  it('returns the service base path alone for an empty segment', () => {
    expect(service.url()).toBe('/v1/plural');
  });
});
