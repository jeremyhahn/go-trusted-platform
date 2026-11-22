/**
 * Platform (Daemon) Service
 *
 * Provides operations for platform daemon management including system info and health.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import { TPM_BASE_PATH } from './tpm-service.js';
import type { TPMInfoResponse } from '../types/tpm.js';
import type {
  GetVersionResponse,
  GetSystemInfoResponse,
  GetHealthRequest,
  GetHealthResponse,
  GetConfigRequest,
  GetConfigResponse,
  ListEntityTypesResponse,
  GetMetricsRequest,
  GetMetricsResponse,
  ReloadConfigResponse,
} from '../types/platform.js';

/**
 * Platform Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Get platform version
 * const version = await client.platform.getVersion();
 * console.log(`Platform version: ${version.data.version.version}`);
 *
 * // Check platform health
 * const health = await client.platform.getHealth({ includeServices: true });
 * if (!health.data.health.healthy) {
 *   console.error('Platform unhealthy!');
 * }
 *
 * // Get TPM info; a successful response means a TPM is available
 * const tpm = await client.platform.getTPMInfo();
 * if (tpm.success) {
 *   console.log(`TPM: ${tpm.data.version}, ${tpm.data.manufacturer?.name ?? 'unknown vendor'}`);
 * }
 * ```
 */
export class PlatformService extends BaseService {
  /**
   * Creates a new Platform service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/platform');
  }

  // =========================================================================
  // Information Operations
  // =========================================================================

  /**
   * Get platform version
   *
   * @returns Version information
   */
  async getVersion(): Promise<ApiResponse<GetVersionResponse>> {
    return this.client.get<GetVersionResponse>(this.buildUrl('/version'));
  }

  /**
   * Get system information
   *
   * @returns System information
   */
  async getSystemInfo(): Promise<ApiResponse<GetSystemInfoResponse>> {
    return this.client.get<GetSystemInfoResponse>(this.buildUrl('/system'));
  }

  /**
   * Get TPM information
   *
   * @returns TPM information
   */
  async getTPMInfo(): Promise<ApiResponse<TPMInfoResponse>> {
    return this.client.get<TPMInfoResponse>(this.buildUrlUnder(TPM_BASE_PATH, '/info'));
  }

  // =========================================================================
  // Health Operations
  // =========================================================================

  /**
   * Get platform health status
   *
   * @param request - Health request options
   * @returns Health status
   */
  async getHealth(request?: GetHealthRequest): Promise<ApiResponse<GetHealthResponse>> {
    return this.client.get<GetHealthResponse>(this.buildUrl('/health', {
      filters: { includeServices: request?.includeServices?.toString() },
    }));
  }

  // =========================================================================
  // Configuration Operations
  // =========================================================================

  /**
   * Get the effective platform configuration (`GET /api/v1/platform/config`)
   *
   * Sends `redact=false` when `includeSensitive` is true and
   * `section=<name>` when a section is named; neither is sent otherwise.
   *
   * @param request - Config request options
   * @returns The config tree, its sources and the redaction state
   */
  async getConfig(request?: GetConfigRequest): Promise<ApiResponse<GetConfigResponse>> {
    const params = new URLSearchParams();
    if (request?.includeSensitive === true) {
      params.set('redact', 'false');
    }
    if (typeof request?.section === 'string' && request.section !== '') {
      params.set('section', request.section);
    }
    const query = params.toString();
    const url = this.buildUrl('/config');
    return this.client.get<GetConfigResponse>(query ? `${url}?${query}` : url);
  }

  /**
   * Reload platform configuration from disk
   *
   * @returns `reloaded`, the `sections` the reload applied and the
   *   `pre_reload_snapshot` id taken before it
   */
  async reloadConfig(): Promise<ApiResponse<ReloadConfigResponse>> {
    return this.client.post<ReloadConfigResponse>(this.buildUrl('/config/reload'), {});
  }

  // =========================================================================
  // Metrics Operations
  // =========================================================================

  /**
   * Get platform metrics
   *
   * @param request - Metrics request options
   * @returns Platform metrics
   */
  async getMetrics(request?: GetMetricsRequest): Promise<ApiResponse<GetMetricsResponse>> {
    return this.client.get<GetMetricsResponse>(this.buildUrl('/metrics', {
      filters: { includeHistory: request?.includeHistory?.toString() },
    }));
  }

  /**
   * List storage entity types and their entity counts
   * (GET /api/v1/platform/entity-types, PlatformDaemon.ListEntityTypes)
   *
   * @returns Entity types, total entities and active type count
   */
  async listEntityTypes(): Promise<ApiResponse<ListEntityTypesResponse>> {
    return this.client.get<ListEntityTypesResponse>(this.buildUrl('/entity-types'));
  }

  // =========================================================================
  // License Operations
  // =========================================================================

  // =========================================================================
  // Lifecycle Operations
  // =========================================================================

}
