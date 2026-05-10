/**
 * Platform (Daemon) Service
 *
 * Provides operations for platform daemon management including system info and health.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  GetVersionResponse,
  GetSystemInfoResponse,
  GetTPMInfoResponse,
  GetHealthRequest,
  GetHealthResponse,
  GetConfigRequest,
  GetConfigResponse,
  UpdateConfigRequest,
  UpdateConfigResponse,
  GetMetricsRequest,
  GetMetricsResponse,
  GetLicenseResponse,
  ReloadConfigResponse,
  ShutdownRequest,
  ShutdownResponse,
  RestartRequest,
  RestartResponse,
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
 * // Get TPM info
 * const tpm = await client.platform.getTPMInfo();
 * console.log(`TPM available: ${tpm.data.tpm.available}`);
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
  async getTPMInfo(): Promise<ApiResponse<GetTPMInfoResponse>> {
    return this.client.get<GetTPMInfoResponse>(this.buildUrl('/tpm'));
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
   * Get platform configuration
   *
   * @param request - Config request options
   * @returns Platform configuration
   */
  async getConfig(request?: GetConfigRequest): Promise<ApiResponse<GetConfigResponse>> {
    return this.client.get<GetConfigResponse>(this.buildUrl('/config', {
      filters: { includeSensitive: request?.includeSensitive?.toString() },
    }));
  }

  /**
   * Update platform configuration
   *
   * @param request - Update request
   * @returns Updated configuration
   */
  async updateConfig(request: UpdateConfigRequest): Promise<ApiResponse<UpdateConfigResponse>> {
    return this.client.put<UpdateConfigResponse>(this.buildUrl('/config'), request);
  }

  /**
   * Reload platform configuration from disk
   *
   * @returns Reload result
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

  // =========================================================================
  // License Operations
  // =========================================================================

  /**
   * Get license information
   *
   * @returns License information
   */
  async getLicense(): Promise<ApiResponse<GetLicenseResponse>> {
    return this.client.get<GetLicenseResponse>(this.buildUrl('/license'));
  }

  // =========================================================================
  // Lifecycle Operations
  // =========================================================================

  /**
   * Shutdown the platform
   *
   * @param request - Shutdown options
   * @returns Shutdown result
   */
  async shutdown(request?: ShutdownRequest): Promise<ApiResponse<ShutdownResponse>> {
    return this.client.post<ShutdownResponse>(this.buildUrl('/shutdown'), request ?? {});
  }

  /**
   * Restart the platform
   *
   * @param request - Restart options
   * @returns Restart result
   */
  async restart(request?: RestartRequest): Promise<ApiResponse<RestartResponse>> {
    return this.client.post<RestartResponse>(this.buildUrl('/restart'), request ?? {});
  }
}
