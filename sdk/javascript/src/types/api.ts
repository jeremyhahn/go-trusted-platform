import type { ApiErrorResponse } from '../errors/types.js';

/**
 * Standard API response wrapper
 *
 * All API responses are wrapped in this structure to provide
 * consistent success/error handling.
 *
 * @typeParam T - The type of the response data
 */
export interface ApiResponse<T> {
  /** Response data on success */
  data?: T;
  /** Error information on failure */
  error?: ApiErrorResponse;
  /** Whether the request was successful */
  success: boolean;
}

/**
 * Creates a successful API response
 */
export function successResponse<T>(data: T): ApiResponse<T> {
  return {
    data,
    success: true,
  };
}

/**
 * Creates a failed API response
 */
export function errorResponse<T = never>(error: ApiErrorResponse): ApiResponse<T> {
  return {
    error,
    success: false,
  };
}

/**
 * Type guard to check if response is successful
 */
export function isSuccessResponse<T>(response: ApiResponse<T>): response is ApiResponse<T> & { data: T } {
  return response.success && response.data !== undefined;
}

/**
 * Type guard to check if response is an error
 */
export function isErrorResponse<T>(
  response: ApiResponse<T>
): response is ApiResponse<T> & { error: ApiErrorResponse } {
  return !response.success && response.error !== undefined;
}

/**
 * Unwraps an API response, throwing if it's an error
 *
 * @throws {Error} If the response contains an error
 */
export function unwrapResponse<T>(response: ApiResponse<T>): T {
  if (isSuccessResponse(response)) {
    return response.data;
  }
  throw new Error(response.error?.message ?? 'Unknown error');
}

/**
 * HTTP method types
 */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

/**
 * Request body types
 *
 * Note: The object type is used to allow typed request interfaces to be passed
 * without requiring index signatures. At runtime, these are serialized to JSON.
 */
export type RequestBody = object | unknown[] | string | FormData | Blob | null;

/**
 * Query parameters type
 */
export type QueryParams = Record<string, string | number | boolean | string[] | number[] | undefined | null>;

/**
 * Headers type
 */
export type HeadersInit = Record<string, string> | Headers;

/**
 * Converts query params to URL search params
 */
export function toSearchParams(params: QueryParams): URLSearchParams {
  const searchParams = new URLSearchParams();

  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) {
      continue;
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        searchParams.append(key, String(item));
      }
    } else {
      searchParams.set(key, String(value));
    }
  }

  return searchParams;
}

/**
 * Appends query params to a URL path
 */
export function appendQueryParams(path: string, params?: QueryParams): string {
  if (params === undefined || Object.keys(params).length === 0) {
    return path;
  }

  const searchParams = toSearchParams(params);
  const queryString = searchParams.toString();

  if (queryString.length === 0) {
    return path;
  }

  const separator = path.includes('?') ? '&' : '?';
  return `${path}${separator}${queryString}`;
}
