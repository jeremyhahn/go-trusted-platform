/**
 * PXE (Preboot Execution Environment) Service
 *
 * Provides operations for PXE device provisioning workflow.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  RegisterPXEDeviceRequest,
  RegisterPXEDeviceResponse,
  GetPXEDeviceResponse,
  GetPXEDeviceByMACResponse,
  ListPXEDevicesRequest,
  ListPXEDevicesResponse,
  RemovePXEDeviceResponse,
  UpdatePXEStateRequest,
  UpdatePXEStateResponse,
  SetPXEDeviceEnrolledRequest,
  SetPXEDeviceEnrolledResponse,
  AuthorizePXEDeviceRequest,
  AuthorizePXEDeviceResponse,
  QuarantinePXEDeviceRequest,
  QuarantinePXEDeviceResponse,
  RetryPXEDeviceResponse,
  GetPXEEventsResponse,
  GetPXEStatusResponse,
  StartPXEServiceResponse,
  StopPXEServiceResponse,
  PXEWebhookCompleteRequest,
  PXEWebhookCompleteResponse,
} from '../types/pxe.js';
import { PROVISIONING_STATE_PROTO_NAMES } from '../types/pxe.js';
import { encodeEnum } from './wire-enum.js';

/**
 * PXE Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Register a device
 * const device = await client.pxe.registerDevice({
 *   macAddress: '00:11:22:33:44:55',
 * });
 *
 * // Get provisioning events
 * const events = await client.pxe.getEvents(device.data.device.id);
 *
 * // Authorize device after enrollment
 * await client.pxe.authorizeDevice({
 *   deviceId: device.data.device.id,
 *   targetVlan: 100,
 * });
 * ```
 */
export class PXEService extends BaseService {
  /**
   * Creates a new PXE service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/pxe');
  }

  // =========================================================================
  // Device Operations
  // =========================================================================

  /**
   * Register a device for PXE provisioning
   *
   * @param request - Registration request
   * @returns Registered device
   */
  async registerDevice(request: RegisterPXEDeviceRequest): Promise<ApiResponse<RegisterPXEDeviceResponse>> {
    return this.client.post<RegisterPXEDeviceResponse>(this.buildUrl('/devices'), request);
  }

  /**
   * Get device by ID
   *
   * @param deviceId - Device ID
   * @returns Device information
   */
  async getDevice(deviceId: string): Promise<ApiResponse<GetPXEDeviceResponse>> {
    return this.client.get<GetPXEDeviceResponse>(
      this.buildUrl(`/devices/${this.encodePathSegment(deviceId)}`)
    );
  }

  /**
   * Get device by MAC address
   *
   * @param macAddress - MAC address
   * @returns Device information
   */
  async getDeviceByMAC(macAddress: string): Promise<ApiResponse<GetPXEDeviceByMACResponse>> {
    return this.client.get<GetPXEDeviceByMACResponse>(
      this.buildUrl(`/devices/mac/${this.encodePathSegment(macAddress)}`)
    );
  }

  /**
   * List devices
   *
   * @param request - List request with filters
   * @returns List of devices
   */
  async listDevices(request?: ListPXEDevicesRequest): Promise<ApiResponse<ListPXEDevicesResponse>> {
    const filters: Record<string, string | number | undefined> = {};
    if (request?.filter !== undefined) {
      if (request.filter.state !== undefined) {
        filters.state = request.filter.state;
      }
      if (request.filter.macAddress !== undefined) {
        filters.macAddress = request.filter.macAddress;
      }
      if (request.filter.vlan !== undefined) {
        filters.vlan = request.filter.vlan;
      }
    }
    return this.client.get<ListPXEDevicesResponse>(this.buildUrl('/devices', {
      page: request?.filter?.offset !== undefined && request?.filter?.limit !== undefined
        ? Math.floor(request.filter.offset / request.filter.limit) + 1
        : undefined,
      limit: request?.filter?.limit,
      filters,
    }));
  }

  /**
   * Remove a device
   *
   * @param deviceId - Device ID
   * @returns Removal result
   */
  async removeDevice(deviceId: string): Promise<ApiResponse<RemovePXEDeviceResponse>> {
    return this.client.delete<RemovePXEDeviceResponse>(
      this.buildUrl(`/devices/${this.encodePathSegment(deviceId)}`)
    );
  }

  // =========================================================================
  // State Management Operations
  // =========================================================================

  /**
   * Update device provisioning state
   *
   * @param request - State update request
   * @returns Updated device
   */
  async updateState(request: UpdatePXEStateRequest): Promise<ApiResponse<UpdatePXEStateResponse>> {
    return this.client.put<UpdatePXEStateResponse>(
      this.buildUrl(`/devices/${this.encodePathSegment(request.deviceId)}/state`),
      {
        state: encodeEnum('state', PROVISIONING_STATE_PROTO_NAMES, request.state),
        reason: request.reason,
        installCertificateSha256: request.installCertificateSha256,
      }
    );
  }

  /**
   * Mark device as enrolled
   *
   * @param request - Enrollment request
   * @returns Updated device
   */
  async setDeviceEnrolled(request: SetPXEDeviceEnrolledRequest): Promise<ApiResponse<SetPXEDeviceEnrolledResponse>> {
    return this.client.post<SetPXEDeviceEnrolledResponse>(
      this.buildUrl(`/devices/${this.encodePathSegment(request.deviceId)}/enrolled`),
      { certificateSerial: request.certificateSerial }
    );
  }

  /**
   * Authorize a device to access production network
   *
   * @param request - Authorization request
   * @returns Updated device
   */
  async authorizeDevice(request: AuthorizePXEDeviceRequest): Promise<ApiResponse<AuthorizePXEDeviceResponse>> {
    return this.client.post<AuthorizePXEDeviceResponse>(
      this.buildUrl(`/devices/${this.encodePathSegment(request.deviceId)}/authorize`),
      { targetVlan: request.targetVlan }
    );
  }

  /**
   * Quarantine a device
   *
   * @param request - Quarantine request
   * @returns Updated device
   */
  async quarantineDevice(request: QuarantinePXEDeviceRequest): Promise<ApiResponse<QuarantinePXEDeviceResponse>> {
    return this.client.post<QuarantinePXEDeviceResponse>(
      this.buildUrl(`/devices/${this.encodePathSegment(request.deviceId)}/quarantine`),
      { reason: request.reason }
    );
  }

  /**
   * Retry provisioning for a failed device. The retried installation must be
   * bound to a new installer certificate (`updateState` with a fresh
   * `installCertificateSha256`); one the device was already installed under
   * is refused.
   *
   * @param deviceId - Device ID
   * @returns Updated device
   */
  async retryDevice(deviceId: string): Promise<ApiResponse<RetryPXEDeviceResponse>> {
    return this.client.post<RetryPXEDeviceResponse>(
      this.buildUrl(`/devices/${this.encodePathSegment(deviceId)}/retry`),
      {}
    );
  }

  // =========================================================================
  // Event Operations
  // =========================================================================

  /**
   * Get provisioning events for a device
   *
   * @param deviceId - Device ID
   * @returns List of events
   */
  async getEvents(deviceId: string): Promise<ApiResponse<GetPXEEventsResponse>> {
    return this.client.get<GetPXEEventsResponse>(
      this.buildUrl(`/devices/${this.encodePathSegment(deviceId)}/events`)
    );
  }

  // =========================================================================
  // Service Management Operations
  // =========================================================================

  /**
   * Get PXE service status
   *
   * @returns Service status
   */
  async getStatus(): Promise<ApiResponse<GetPXEStatusResponse>> {
    return this.client.get<GetPXEStatusResponse>(this.buildUrl('/status'));
  }

  /**
   * Start PXE service
   *
   * @returns Start result
   */
  async startService(): Promise<ApiResponse<StartPXEServiceResponse>> {
    return this.client.post<StartPXEServiceResponse>(this.buildUrl('/start'), {});
  }

  /**
   * Stop PXE service
   *
   * @returns Stop result
   */
  async stopService(): Promise<ApiResponse<StopPXEServiceResponse>> {
    return this.client.post<StopPXEServiceResponse>(this.buildUrl('/stop'), {});
  }

  // =========================================================================
  // Webhook Operations
  // =========================================================================

  /**
   * Handle install completion webhook
   *
   * @param request - Webhook request
   * @returns Webhook result
   */
  async webhookComplete(request: PXEWebhookCompleteRequest): Promise<ApiResponse<PXEWebhookCompleteResponse>> {
    return this.client.post<PXEWebhookCompleteResponse>(this.buildUrl('/webhook/complete'), request);
  }
}
