/**
 * Transport abstraction for the Trusted Platform SDK.
 *
 * Services (TPMService, CAService, IAMService, …) talk to the
 * platform through a `Transport` rather than a hard-coded HTTP
 * client. This lets the same service code dispatch over:
 *
 *   - REST (browser fetch)         — `RestTransport`
 *   - gRPC-Web (browser-friendly)  — to be added when the
 *                                     server's grpc-web filter
 *                                     ships
 *   - Wails IPC (desktop)          — wails-client.ts
 *   - Unix socket (Node CLI tools) — node-only
 *
 * The application picks a transport at boot via
 * `createPlatformClient({ transport })` and the rest of the SDK
 * is transport-agnostic. Switching transports is a one-line
 * config change, not a rewrite of every service call site.
 *
 * Method semantics mirror HTTP verbs: `get` for idempotent
 * read-only fetches, `post` for resource creation / arbitrary
 * RPC, `put` for full replacement, `patch` for partial updates,
 * `delete` for removal. Non-HTTP transports translate these to
 * their native verbs (e.g. gRPC-Web maps everything to a single
 * unary call; Wails IPC ignores the verb and uses the path as
 * the method name).
 *
 * Returning `ApiResponse<T>` (rather than throwing) keeps error
 * handling uniform across transports — a 404 over REST, a
 * `NOT_FOUND` gRPC code, and a Wails IPC `not found` error all
 * surface the same shape.
 */

import type { ApiResponse, RequestBody } from '../types/api.js';
import type { RequestOptions } from '../client/api-client.js';

/**
 * Transport is the surface every SDK service depends on. The
 * existing `ApiClient` (REST/fetch) already satisfies this
 * interface structurally — declaring it explicitly lets us swap
 * in alternative implementations without changing service code.
 */
export interface Transport {
  /**
   * Issue a GET-equivalent request. The path is the
   * platform-relative URL (e.g. `/api/v1/tpm/info`) for HTTP
   * transports or the RPC name for non-HTTP transports.
   */
  get<T>(path: string, options?: RequestOptions): Promise<ApiResponse<T>>;

  /**
   * Issue a POST-equivalent request. The body is JSON-serialized
   * for HTTP transports and passed verbatim to non-HTTP
   * transports.
   */
  post<T>(path: string, body?: RequestBody, options?: RequestOptions): Promise<ApiResponse<T>>;

  /**
   * Issue a PUT-equivalent request (full resource replacement).
   */
  put<T>(path: string, body?: RequestBody, options?: RequestOptions): Promise<ApiResponse<T>>;

  /**
   * Issue a PATCH-equivalent request (partial update).
   */
  patch<T>(path: string, body?: RequestBody, options?: RequestOptions): Promise<ApiResponse<T>>;

  /**
   * Issue a DELETE-equivalent request.
   */
  delete<T>(path: string, options?: RequestOptions): Promise<ApiResponse<T>>;
}

/**
 * TransportKind identifies the wire protocol an application
 * intends to use. Apps that don't need to inspect the kind can
 * ignore this; it's primarily for telemetry and for guarding
 * code paths that only make sense on certain transports (e.g.
 * Wails IPC has no "request retry" because there's no network).
 */
export type TransportKind = 'rest' | 'grpc-web' | 'wails' | 'unix';
