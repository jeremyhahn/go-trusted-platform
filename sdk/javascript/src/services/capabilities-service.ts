/**
 * Capabilities Service
 *
 * What the server offers: every service and route, enabled or dark, with
 * the reason a dark one is off. Wire contract:
 * pkg/webservice/v1/capabilities.go (`GET /api/v1/capabilities`).
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';

/** The service has no configuration; the service name follows the prefix. */
export const CAPABILITY_REASON_NOT_CONFIGURED = 'not-configured: ';
/** The operation is not implemented on this server. */
export const CAPABILITY_REASON_UNIMPLEMENTED = 'unimplemented';
/** The operation waits on an integration that has not landed. */
export const CAPABILITY_REASON_BLOCKED_INTEGRATION = 'blocked: integration';

/** One operation the server knows about. */
export interface Capability {
  op: string;
  /** 'service' or 'route' today; a newer server may send other kinds. */
  kind: string;
  service?: string;
  enabled: boolean;
  reason?: string;
}

/** Body of GET /api/v1/capabilities. */
export interface CapabilitiesResponse {
  capabilities: Capability[];
  total: number;
  enabled: number;
}

/**
 * Capabilities Service class
 *
 * @example
 * ```typescript
 * const caps = await client.capabilities.list();
 * ```
 */
export class CapabilitiesService extends BaseService {
  /**
   * Creates a new capabilities service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/capabilities');
  }

  /**
   * List what the server offers, enabled and dark
   *
   * @returns The capabilities, their total and the enabled count
   */
  async list(): Promise<ApiResponse<CapabilitiesResponse>> {
    return this.client.get<CapabilitiesResponse>(this.buildUrl(''));
  }
}
