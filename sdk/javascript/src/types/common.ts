/**
 * Common types used throughout the SDK
 */

/**
 * Pagination parameters for list requests
 */
export interface PaginationParams {
  /** Page number (1-indexed) */
  page?: number;
  /** Number of items per page */
  limit?: number;
  /** Cursor for cursor-based pagination */
  cursor?: string;
}

/**
 * Pagination metadata in list responses
 */
export interface PaginationMeta {
  /** Current page number */
  page: number;
  /** Number of items per page */
  limit: number;
  /** Total number of items */
  total: number;
  /** Total number of pages */
  totalPages: number;
  /** Whether there is a next page */
  hasNext: boolean;
  /** Whether there is a previous page */
  hasPrevious: boolean;
  /** Cursor for the next page (cursor-based pagination) */
  nextCursor?: string;
  /** Cursor for the previous page (cursor-based pagination) */
  previousCursor?: string;
}

/**
 * Paginated list response
 */
export interface PaginatedResponse<T> {
  /** List of items */
  items: T[];
  /** Pagination metadata */
  pagination: PaginationMeta;
}

/**
 * Sort direction
 */
export type SortDirection = 'asc' | 'desc';

/**
 * Sort parameters
 */
export interface SortParams {
  /** Field to sort by */
  sortBy?: string;
  /** Sort direction */
  sortDirection?: SortDirection;
}

/**
 * Filter operators for queries
 */
export type FilterOperator = 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte' | 'in' | 'nin' | 'like' | 'contains';

/**
 * Single filter condition
 */
export interface FilterCondition {
  field: string;
  operator: FilterOperator;
  value: unknown;
}

/**
 * Timestamp fields common to many entities
 */
export interface Timestamps {
  /** Creation timestamp (ISO 8601) */
  createdAt: string;
  /** Last update timestamp (ISO 8601) */
  updatedAt: string;
}

/**
 * Entity with ID and timestamps
 */
export interface BaseEntity extends Timestamps {
  /** Unique identifier */
  id: string;
}

/**
 * Branded type helper for creating nominal types
 *
 * @example
 * ```typescript
 * type UserId = Branded<string, 'UserId'>;
 * type OrderId = Branded<string, 'OrderId'>;
 *
 * // These are now distinct types
 * const userId: UserId = 'user-123' as UserId;
 * const orderId: OrderId = 'order-456' as OrderId;
 * ```
 */
export type Branded<T, Brand extends string> = T & { readonly __brand: Brand };

/**
 * UUID branded type
 */
export type UUID = Branded<string, 'UUID'>;

/**
 * ISO 8601 date string branded type
 */
export type ISODateString = Branded<string, 'ISODateString'>;

/**
 * Validates and casts a string as UUID (basic validation)
 */
export function asUUID(value: string): UUID {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(value)) {
    throw new Error(`Invalid UUID: ${value}`);
  }
  return value as UUID;
}

/**
 * Validates and casts a string as ISO date string
 */
export function asISODateString(value: string): ISODateString {
  const date = new Date(value);
  if (isNaN(date.getTime())) {
    throw new Error(`Invalid ISO date string: ${value}`);
  }
  return value as ISODateString;
}

/**
 * Result type for operations that can fail
 *
 * @example
 * ```typescript
 * function divide(a: number, b: number): Result<number, string> {
 *   if (b === 0) {
 *     return { ok: false, error: 'Division by zero' };
 *   }
 *   return { ok: true, value: a / b };
 * }
 * ```
 */
export type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

/**
 * Creates a successful result
 */
export function ok<T>(value: T): Result<T, never> {
  return { ok: true, value };
}

/**
 * Creates a failed result
 */
export function err<E>(error: E): Result<never, E> {
  return { ok: false, error };
}

/**
 * Type guard for successful result
 */
export function isOk<T, E>(result: Result<T, E>): result is { ok: true; value: T } {
  return result.ok;
}

/**
 * Type guard for failed result
 */
export function isErr<T, E>(result: Result<T, E>): result is { ok: false; error: E } {
  return !result.ok;
}

/**
 * Unwraps a result, throwing if it's an error
 */
export function unwrapResult<T, E>(result: Result<T, E>): T {
  if (isOk(result)) {
    return result.value;
  }
  if (result.error instanceof Error) {
    throw result.error;
  }
  throw new Error(String(result.error));
}

/**
 * Empty object type (use instead of {})
 */
export type EmptyObject = Record<string, never>;

/**
 * Deep partial type
 */
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

/**
 * Makes specific keys required
 */
export type RequireKeys<T, K extends keyof T> = Omit<T, K> & Required<Pick<T, K>>;

/**
 * Makes specific keys optional
 */
export type OptionalKeys<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;
