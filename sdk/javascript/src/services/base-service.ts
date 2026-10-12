/**
 * Base Service class for all API services
 *
 * Provides common functionality for building URLs and accessing the API client.
 */

import type { ApiClient } from '../client/api-client.js';
import type { RequestOptions } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { QueryParams } from '../types/api.js';

/**
 * List options for paginated requests
 */
export interface ListOptions {
  /** Page number (1-indexed) */
  page?: number | undefined;
  /** Number of items per page */
  limit?: number | undefined;
  /** Field to sort by */
  sortBy?: string | undefined;
  /** Sort in ascending order */
  ascending?: boolean | undefined;
  /** Additional filter parameters */
  filters?: Record<string, string | number | boolean | undefined> | undefined;
}

/**
 * Converts ListOptions to QueryParams
 */
export function listOptionsToParams(options?: ListOptions): QueryParams | undefined {
  if (options === undefined) {
    return undefined;
  }

  const params: QueryParams = {};

  if (options.page !== undefined) {
    params.page = options.page;
  }

  if (options.limit !== undefined) {
    params.limit = options.limit;
  }

  if (options.sortBy !== undefined) {
    params.sortBy = options.sortBy;
  }

  if (options.ascending !== undefined) {
    params.ascending = options.ascending;
  }

  if (options.filters !== undefined) {
    for (const [key, value] of Object.entries(options.filters)) {
      if (value !== undefined) {
        params[key] = value;
      }
    }
  }

  return Object.keys(params).length > 0 ? params : undefined;
}

/**
 * Base service class that all API services extend
 *
 * @example
 * ```typescript
 * class MyService extends BaseService {
 *   constructor(client: Transport | ApiClient) {
 *     super(client, '/v1/my-resource');
 *   }
 *
 *   async getItems(options?: ListOptions) {
 *     return this.client.get(this.buildUrl('/items', options));
 *   }
 * }
 * ```
 */
export abstract class BaseService {
  /**
   * Underlying transport. Typed as `Transport` so any
   * implementation (REST/fetch, gRPC-Web, Wails IPC) can power
   * services without code changes. Existing call sites that
   * pass an `ApiClient` continue to work because `ApiClient`
   * now formally implements `Transport`.
   */
  protected readonly client: Transport;

  /** The base path for this service */
  protected readonly basePath: string;

  /**
   * Creates a new service instance
   *
   * @param client - The transport to use for requests (defaults
   *   to a REST-over-fetch ApiClient when callers don't supply
   *   one explicitly).
   * @param basePath - The base path for all requests in this service
   */
  constructor(client: Transport | ApiClient, basePath: string) {
    this.client = client;
    this.basePath = basePath;
  }

  /**
   * Builds a full URL path with optional query parameters
   *
   * @param path - The path segment to append to basePath
   * @param options - Optional list options to convert to query params
   * @returns The full path with query parameters if any
   */
  protected buildUrl(path: string = '', options?: ListOptions): string {
    return this.buildUrlUnder(this.basePath, path, options);
  }

  /**
   * Builds a full URL path under an explicit base path, for the services
   * whose routes span more than one prefix
   *
   * @param basePath - The base path to append the segment to
   * @param path - The path segment to append to basePath
   * @param options - Optional list options to convert to query params
   * @returns The full path with query parameters if any
   */
  protected buildUrlUnder(basePath: string, path: string = '', options?: ListOptions): string {
    const fullPath = path.length > 0 ? `${basePath}${path}` : basePath;

    if (options === undefined) {
      return fullPath;
    }

    const params = listOptionsToParams(options);
    if (params === undefined || Object.keys(params).length === 0) {
      return fullPath;
    }

    const searchParams = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) {
        searchParams.set(key, String(value));
      }
    }

    const queryString = searchParams.toString();
    return queryString.length > 0 ? `${fullPath}?${queryString}` : fullPath;
  }

  /**
   * Builds request options with optional parameters
   *
   * @param options - Optional list options
   * @returns Request options with params set
   */
  protected buildRequestOptions(options?: ListOptions): RequestOptions | undefined {
    const params = listOptionsToParams(options);
    return params !== undefined ? { params } : undefined;
  }

  /**
   * Encodes a path segment for safe URL inclusion
   *
   * @param segment - The path segment to encode
   * @returns The URL-encoded segment
   */
  protected encodePathSegment(segment: string): string {
    return encodeURIComponent(segment);
  }
}
