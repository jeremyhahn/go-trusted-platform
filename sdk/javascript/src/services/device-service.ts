/**
 * Device Service
 *
 * Provides operations for device and profile management.
 */

import type { ApiClient } from '../client/api-client.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  CreateDeviceRequest,
  UpdateDeviceRequest,
  ListDevicesRequest,
  CreateProfileRequest,
  UpdateProfileRequest,
  ListProfilesRequest,
  FindMatchingProfileRequest,
  ActivateDeviceRequest,
  CreateDeviceResponse,
  GetDeviceResponse,
  UpdateDeviceResponse,
  DeleteDeviceResponse,
  ListDevicesResponse,
  FindDeviceBySerialResponse,
  CountDevicesResponse,
  CreateProfileResponse,
  GetProfileResponse,
  UpdateProfileResponse,
  DeleteProfileResponse,
  ListProfilesResponse,
  FindProfileByMACAddressResponse,
  FindProfileBySerialResponse,
  FindMatchingProfileResponse,
  CountProfilesResponse,
  ActivateDeviceResponse,
  DeviceTemplate,
  DeviceProfile,
  ProvisioningSession,
  CreateDeviceTemplateRequest,
  UpdateDeviceTemplateRequest,
  ListDeviceTemplatesRequest,
  CreateProfileFromTemplateRequest,
  FindConfigForDeviceRequest,
  AssignProfileToDeviceRequest,
  FulfillSessionRequest,
} from '../types/device.js';

/**
 * Device Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create a device
 * const device = await client.device.createDevice({
 *   device: { serial: 'ABC123' }
 * });
 *
 * // Find matching profile for a device
 * const profile = await client.device.findMatchingProfile({
 *   macAddress: '00:11:22:33:44:55',
 *   serial: 'ABC123',
 * });
 * ```
 */
export class DeviceService extends BaseService {
  /**
   * Creates a new Device service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/devices');
  }

  // =========================================================================
  // Device Operations
  // =========================================================================

  /**
   * Create a device
   *
   * @param request - Device creation request
   * @returns Created device
   */
  async createDevice(request: CreateDeviceRequest): Promise<ApiResponse<CreateDeviceResponse>> {
    return this.client.post<CreateDeviceResponse>(this.buildUrl(''), request);
  }

  /**
   * Get device by ID
   *
   * @param id - Device ID
   * @returns Device information
   */
  async getDevice(id: number): Promise<ApiResponse<GetDeviceResponse>> {
    return this.client.get<GetDeviceResponse>(this.buildUrl(`/${id}`));
  }

  /**
   * Update a device
   *
   * @param request - Device update request
   * @returns Updated device
   */
  async updateDevice(request: UpdateDeviceRequest): Promise<ApiResponse<UpdateDeviceResponse>> {
    return this.client.put<UpdateDeviceResponse>(
      this.buildUrl(`/${request.device.id}`),
      request
    );
  }

  /**
   * Delete a device
   *
   * @param id - Device ID
   * @returns Deletion result
   */
  async deleteDevice(id: number): Promise<ApiResponse<DeleteDeviceResponse>> {
    return this.client.delete<DeleteDeviceResponse>(this.buildUrl(`/${id}`));
  }

  /**
   * List devices
   *
   * @param request - List request with pagination
   * @returns List of devices
   */
  async listDevices(request?: ListDevicesRequest): Promise<ApiResponse<ListDevicesResponse>> {
    return this.client.get<ListDevicesResponse>(this.buildUrl('', {
      page: request?.page,
      limit: request?.pageSize,
    }));
  }

  /**
   * Find device by serial number
   *
   * @param serial - Serial number
   * @returns Found device
   */
  async findDeviceBySerial(serial: string): Promise<ApiResponse<FindDeviceBySerialResponse>> {
    return this.client.get<FindDeviceBySerialResponse>(
      this.buildUrl(`/by-serial/${this.encodePathSegment(serial)}`)
    );
  }

  /**
   * Count devices
   *
   * @returns Device count
   */
  async countDevices(): Promise<ApiResponse<CountDevicesResponse>> {
    return this.client.get<CountDevicesResponse>(this.buildUrl('/count'));
  }

  /**
   * Activate a device
   *
   * @param request - Activation request
   * @returns Activation result
   */
  async activateDevice(request: ActivateDeviceRequest): Promise<ApiResponse<ActivateDeviceResponse>> {
    return this.client.post<ActivateDeviceResponse>(this.buildUrl('/activate'), request);
  }

  // =========================================================================
  // Profile Operations
  // =========================================================================

  /**
   * Create a device profile
   *
   * @param request - Profile creation request
   * @returns Created profile
   */
  async createProfile(request: CreateProfileRequest): Promise<ApiResponse<CreateProfileResponse>> {
    return this.client.post<CreateProfileResponse>(this.buildUrl('/profiles'), request);
  }

  /**
   * Get profile by ID
   *
   * @param id - Profile ID
   * @returns Profile information
   */
  async getProfile(id: number): Promise<ApiResponse<GetProfileResponse>> {
    return this.client.get<GetProfileResponse>(this.buildUrl(`/profiles/${id}`));
  }

  /**
   * Update a profile
   *
   * @param request - Profile update request
   * @returns Updated profile
   */
  async updateProfile(request: UpdateProfileRequest): Promise<ApiResponse<UpdateProfileResponse>> {
    return this.client.put<UpdateProfileResponse>(
      this.buildUrl(`/profiles/${request.profile.id}`),
      request
    );
  }

  /**
   * Delete a profile
   *
   * @param id - Profile ID
   * @returns Deletion result
   */
  async deleteProfile(id: number): Promise<ApiResponse<DeleteProfileResponse>> {
    return this.client.delete<DeleteProfileResponse>(this.buildUrl(`/profiles/${id}`));
  }

  /**
   * List profiles
   *
   * @param request - List request with pagination
   * @returns List of profiles
   */
  async listProfiles(request?: ListProfilesRequest): Promise<ApiResponse<ListProfilesResponse>> {
    return this.client.get<ListProfilesResponse>(this.buildUrl('/profiles', {
      page: request?.page,
      limit: request?.pageSize,
    }));
  }

  /**
   * Find profile by MAC address
   *
   * @param macAddress - MAC address
   * @returns Found profile
   */
  async findProfileByMACAddress(macAddress: string): Promise<ApiResponse<FindProfileByMACAddressResponse>> {
    return this.client.get<FindProfileByMACAddressResponse>(
      this.buildUrl(`/profiles/by-mac/${this.encodePathSegment(macAddress)}`)
    );
  }

  /**
   * Find profile by serial number
   *
   * @param serial - Serial number
   * @returns Found profile
   */
  async findProfileBySerial(serial: string): Promise<ApiResponse<FindProfileBySerialResponse>> {
    return this.client.get<FindProfileBySerialResponse>(
      this.buildUrl(`/profiles/by-serial/${this.encodePathSegment(serial)}`)
    );
  }

  /**
   * Find matching profile for a device
   *
   * @param request - Match request
   * @returns Matched profile
   */
  async findMatchingProfile(request: FindMatchingProfileRequest): Promise<ApiResponse<FindMatchingProfileResponse>> {
    return this.client.post<FindMatchingProfileResponse>(
      this.buildUrl('/profiles/match'),
      request
    );
  }

  /**
   * Count profiles
   *
   * @returns Profile count
   */
  async countProfiles(): Promise<ApiResponse<CountProfilesResponse>> {
    return this.client.get<CountProfilesResponse>(this.buildUrl('/profiles/count'));
  }

  // =========================================================================
  // Template Operations
  // =========================================================================

  /**
   * Create a device template
   *
   * @param request - Template creation request
   * @returns Created template
   */
  async createTemplate(request: CreateDeviceTemplateRequest): Promise<ApiResponse<DeviceTemplate>> {
    return this.client.post<DeviceTemplate>(this.buildUrl('/templates'), request);
  }

  /**
   * Get template by ID
   *
   * @param id - Template ID
   * @returns Template information
   */
  async getTemplate(id: number): Promise<ApiResponse<DeviceTemplate>> {
    return this.client.get<DeviceTemplate>(this.buildUrl(`/templates/${id}`));
  }

  /**
   * Update a device template
   *
   * @param request - Template update request
   * @returns Updated template
   */
  async updateTemplate(request: UpdateDeviceTemplateRequest): Promise<ApiResponse<DeviceTemplate>> {
    return this.client.put<DeviceTemplate>(
      this.buildUrl(`/templates/${request.id}`),
      request
    );
  }

  /**
   * Delete a device template
   *
   * @param id - Template ID
   * @returns Deletion result
   */
  async deleteTemplate(id: number): Promise<ApiResponse<void>> {
    return this.client.delete<void>(this.buildUrl(`/templates/${id}`));
  }

  /**
   * List device templates
   *
   * @param request - List request with pagination
   * @returns List of templates
   */
  async listTemplates(request?: ListDeviceTemplatesRequest): Promise<ApiResponse<DeviceTemplate[]>> {
    return this.client.get<DeviceTemplate[]>(this.buildUrl('/templates', {
      page: request?.page,
      limit: request?.pageSize,
    }));
  }

  /**
   * Create a device profile from a template
   *
   * @param request - Create from template request
   * @returns Created profile
   */
  async createProfileFromTemplate(
    request: CreateProfileFromTemplateRequest
  ): Promise<ApiResponse<DeviceProfile>> {
    return this.client.post<DeviceProfile>(
      this.buildUrl(`/templates/${request.templateId}/profiles`),
      request
    );
  }

  // =========================================================================
  // Config Delivery Operations
  // =========================================================================

  /**
   * Find config for a device by EK serial or MAC address
   *
   * @param request - Device identifier request
   * @returns Matching profile, or null if not found
   */
  async findConfigForDevice(
    request: FindConfigForDeviceRequest
  ): Promise<ApiResponse<DeviceProfile | null>> {
    return this.client.post<DeviceProfile | null>(
      this.buildUrl('/profiles/config'),
      request
    );
  }

  /**
   * Assign a profile to a device
   *
   * @param request - Profile assignment request
   * @returns Updated profile
   */
  async assignProfileToDevice(
    request: AssignProfileToDeviceRequest
  ): Promise<ApiResponse<DeviceProfile>> {
    return this.client.post<DeviceProfile>(
      this.buildUrl(`/profiles/${request.profileId}/assign`),
      request
    );
  }

  // =========================================================================
  // Provisioning Session Operations
  // =========================================================================

  /**
   * List all provisioning sessions
   *
   * @returns List of provisioning sessions
   */
  async listProvisioningSessions(): Promise<ApiResponse<ProvisioningSession[]>> {
    return this.client.get<ProvisioningSession[]>(this.buildUrl('/sessions'));
  }

  /**
   * Get a provisioning session by ID
   *
   * @param sessionId - Session ID
   * @returns Provisioning session
   */
  async getProvisioningSession(sessionId: string): Promise<ApiResponse<ProvisioningSession>> {
    return this.client.get<ProvisioningSession>(
      this.buildUrl(`/sessions/${this.encodePathSegment(sessionId)}`)
    );
  }

  /**
   * Fulfill a provisioning session by assigning a profile
   *
   * @param request - Fulfill session request
   * @returns Fulfillment result
   */
  async fulfillProvisioningSession(request: FulfillSessionRequest): Promise<ApiResponse<void>> {
    return this.client.post<void>(
      this.buildUrl(`/sessions/${this.encodePathSegment(request.sessionId)}/fulfill`),
      request
    );
  }
}
