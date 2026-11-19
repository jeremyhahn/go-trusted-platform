/**
 * Device Service
 *
 * Provides operations for device and profile management.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type { ListOptions } from './base-service.js';
import type {
  CreateDeviceRequest,
  UpdateDeviceRequest,
  ListDevicesRequest,
  CreateProfileRequest,
  UpdateProfileRequest,
  ListProfilesRequest,
  FindMatchingProfileRequest,
  ActivateDeviceRequest,
  DeviceAttestRequest,
  DeviceAttestResponse,
  DisableDeviceRequest,
  DeviceLifecycleResponse,
  RecordAttestCertRequest,
  RecordAttestCertResponse,
  CreateDeviceResponse,
  GetDeviceResponse,
  DeleteDeviceResponse,
  ListDevicesResponse,
  CountDevicesResponse,
  CreateProfileResponse,
  GetProfileResponse,
  DeleteProfileResponse,
  ListProfilesResponse,
  Device,
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
 * The server's device surface has one name per resource (docs/device/api.md
 * §3.1, #266): device RECORDS live under the plural base path `/v1/devices`,
 * and profiles, templates and the machine-facing routes under the singular
 * `/v1/device`. No route is served under both.
 */
const SINGULAR_BASE_PATH = '/v1/device';
import type { DeviceSelfServiceProfile } from '../types/device-self-service.js';
import type { NetworkPhaseConfig } from '../types/device.js';
import { AUTH_METHOD_WIRE_NAMES } from '../types/device.js';
import { encodeOptionalEnum } from './wire-enum.js';

/** A network phase as pkg/webservice/v1/device/types.go decodes it. */
type WireNetworkPhase = Omit<NetworkPhaseConfig, 'auth_method' | 'firewallZone'> & {
  auth_method?: string;
  zone?: string;
};

/** A profile as the REST handler decodes it: flat, with wire network phases. */
type WireProfile = Omit<Partial<DeviceProfile>, 'networks'> & {
  networks?: Record<string, WireNetworkPhase>;
};

function toWireNetworkPhase(phase: NetworkPhaseConfig): WireNetworkPhase {
  const { auth_method: authMethod, firewallZone, ...rest } = phase;
  const wireAuthMethod = encodeOptionalEnum('auth_method', AUTH_METHOD_WIRE_NAMES, authMethod);
  return {
    ...rest,
    ...(wireAuthMethod !== undefined && { auth_method: wireAuthMethod }),
    ...(firewallZone !== undefined && { zone: firewallZone }),
  };
}

/**
 * Builds the flat profile body the REST handler decodes; the request's
 * `profile` wrapper is not part of it, and the handler ignores what it does
 * not know, so a wrapped body arrives empty.
 */
function toWireProfile(profile: Partial<DeviceProfile>): WireProfile {
  const { networks, ...rest } = profile;
  if (networks === undefined) {
    return rest;
  }
  const wireNetworks: Record<string, WireNetworkPhase> = {};
  for (const [name, phase] of Object.entries(networks)) {
    wireNetworks[name] = toWireNetworkPhase(phase);
  }
  return { ...rest, networks: wireNetworks };
}

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
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/devices');
  }

  /**
   * Builds a path under the singular `/v1/device` prefix, where profiles,
   * templates and the machine-facing routes live
   *
   * @param path - The path segment to append to the singular prefix
   * @param options - Optional list options to convert to query params
   * @returns The full path with query parameters if any
   */
  private singularUrl(path: string, options?: ListOptions): string {
    return this.buildUrlUnder(SINGULAR_BASE_PATH, path, options);
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
  async getDevice(id: string): Promise<ApiResponse<GetDeviceResponse>> {
    return this.client.get<GetDeviceResponse>(this.buildUrl(`/${id}`));
  }

  /**
   * Update a device
   *
   * @param request - Device update request
   * @returns Updated device
   */
  async updateDevice(request: UpdateDeviceRequest): Promise<ApiResponse<Device>> {
    return this.client.put<Device>(
      this.buildUrl(`/${request.device.id}`),
      request
    );
  }

  /**
   * Verify quote evidence submitted for a device.
   *
   * `POST /api/v1/devices/{id}/attest` (docs/device/api.md §4.4). The
   * response reports each check separately; a negative verdict is a 200 with
   * `verified: false`, so callers read the result rather than catching.
   *
   * @param id - Device ID
   * @param request - Base64 quote evidence
   * @returns Per-check verification result
   */
  async attestDevice(
    id: number | string,
    request: DeviceAttestRequest
  ): Promise<ApiResponse<DeviceAttestResponse>> {
    return this.client.post<DeviceAttestResponse>(this.buildUrl(`/${id}/attest`), request);
  }

  /**
   * Disable a device: the control plane blocks its switch port and records it
   * `suspended` (docs/device/api.md). The control plane refuses the
   * transition, with an error rather than a 200, when it runs no SDN engine,
   * the device has no switch port on record, or its state cannot be suspended.
   *
   * @param id - Device ID
   * @param request - Optional reason recorded on the device
   * @returns The device's state before and after
   */
  async disableDevice(
    id: number | string,
    request: DisableDeviceRequest = {}
  ): Promise<ApiResponse<DeviceLifecycleResponse>> {
    return this.client.post<DeviceLifecycleResponse>(this.buildUrl(`/${id}/disable`), request);
  }

  /**
   * Enable a disabled device: the control plane re-admits its switch port to
   * the quarantine zone and records it `quarantined`. A passing re-attestation
   * then restores the state it held before the disable (docs/device/api.md).
   *
   * @param id - Device ID
   * @returns The device's state before and after
   */
  async enableDevice(id: number | string): Promise<ApiResponse<DeviceLifecycleResponse>> {
    return this.client.post<DeviceLifecycleResponse>(this.buildUrl(`/${id}/enable`), {});
  }

  /**
   * Record (or re-record) the device's attestation certificate without
   * re-enrolling it.
   *
   * `POST /api/v1/devices/{id}/attest-cert/record` (docs/device/api.md §4.5).
   * The verb fails closed and has no override: a refusal is an HTTP 400 whose
   * message names every candidate and why it was refused, returned verbatim
   * in `error.message`. Nothing is written on refusal.
   *
   * @param id - Device ID
   * @param request - `reissue: true` lets the CA issue over the enrolled key
   * @returns The recorded certificate and where it came from
   */
  async recordAttestCert(
    id: number | string,
    request: RecordAttestCertRequest = {}
  ): Promise<ApiResponse<RecordAttestCertResponse>> {
    return this.client.post<RecordAttestCertResponse>(this.buildUrl(`/${id}/attest-cert/record`), {
      reissue: request.reissue ?? false,
    });
  }

  /**
   * Delete a device
   *
   * @param id - Device ID
   * @returns Deletion result
   */
  async deleteDevice(id: string): Promise<ApiResponse<DeleteDeviceResponse>> {
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
  async findDeviceBySerial(serial: string): Promise<ApiResponse<Device>> {
    return this.client.get<Device>(
      this.buildUrl(`/serial/${this.encodePathSegment(serial)}`)
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
   * Posts to the operator's JSON-body route, `POST /api/v1/device/activate-json`.
   * The other activation route, `POST /api/v1/device/activate`, is
   * machine-facing: it reads the serial from the device's verified client
   * certificate, not from a body.
   *
   * @param request - Activation request
   * @returns Activation result
   */
  async activateDevice(request: ActivateDeviceRequest): Promise<ApiResponse<ActivateDeviceResponse>> {
    // The server decodes snake_case: map the MAC and omit it when empty.
    const body: { serial: string; mac_address?: string } = { serial: request.serial };
    if (request.macAddress !== undefined && request.macAddress !== '') {
      body.mac_address = request.macAddress;
    }
    return this.client.post<ActivateDeviceResponse>(this.singularUrl('/activate-json'), body);
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
    return this.client.post<CreateProfileResponse>(this.singularUrl('/profiles'), toWireProfile(request.profile));
  }

  /**
   * Get profile by ID
   *
   * @param id - Profile ID
   * @returns Profile information
   */
  async getProfile(id: string): Promise<ApiResponse<GetProfileResponse>> {
    return this.client.get<GetProfileResponse>(this.singularUrl(`/profiles/${id}`));
  }

  /**
   * Update a profile
   *
   * @param request - Profile update request
   * @returns Updated profile
   */
  async updateProfile(request: UpdateProfileRequest): Promise<ApiResponse<DeviceProfile>> {
    // The server decodes a flat profile and replaces every field the body
    // omits: send the whole profile, not the request envelope.
    return this.client.put<DeviceProfile>(
      this.singularUrl(`/profiles/${request.profile.id}`),
      toWireProfile(request.profile)
    );
  }

  /**
   * Delete a profile
   *
   * @param id - Profile ID
   * @returns Deletion result
   */
  async deleteProfile(id: string): Promise<ApiResponse<DeleteProfileResponse>> {
    return this.client.delete<DeleteProfileResponse>(this.singularUrl(`/profiles/${id}`));
  }

  /**
   * List profiles
   *
   * @param request - List request with pagination
   * @returns List of profiles
   */
  async listProfiles(request?: ListProfilesRequest): Promise<ApiResponse<ListProfilesResponse>> {
    return this.client.get<ListProfilesResponse>(this.singularUrl('/profiles', {
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
  async findProfileByMACAddress(macAddress: string): Promise<ApiResponse<DeviceProfile>> {
    return this.client.get<DeviceProfile>(
      this.singularUrl(`/profiles/mac/${this.encodePathSegment(macAddress)}`)
    );
  }

  /**
   * Find profile by serial number
   *
   * @param serial - Serial number
   * @returns Found profile
   */
  async findProfileBySerial(serial: string): Promise<ApiResponse<DeviceProfile>> {
    return this.client.get<DeviceProfile>(
      this.singularUrl(`/profiles/serial/${this.encodePathSegment(serial)}`)
    );
  }

  /**
   * Find matching profile for a device
   *
   * @param request - Match request
   * @returns Matched profile
   */
  async findMatchingProfile(request: FindMatchingProfileRequest): Promise<ApiResponse<DeviceProfile>> {
    // The server decodes snake_case: map the MAC and omit empty criteria.
    const body: { mac_address?: string; serial?: string; model?: string } = {};
    if (request.macAddress !== undefined && request.macAddress !== '') {
      body.mac_address = request.macAddress;
    }
    if (request.serial !== undefined && request.serial !== '') {
      body.serial = request.serial;
    }
    if (request.model !== undefined && request.model !== '') {
      body.model = request.model;
    }
    return this.client.post<DeviceProfile>(this.singularUrl('/profiles/match'), body);
  }

  /**
   * Count profiles
   *
   * @returns Profile count
   */
  async countProfiles(): Promise<ApiResponse<CountProfilesResponse>> {
    return this.client.get<CountProfilesResponse>(this.singularUrl('/profiles/count'));
  }

  // =========================================================================
  // Template Operations
  // =========================================================================

  /**
   * Create a device template
   *
   * `POST /api/v1/device/templates`. The plural `POST /api/v1/devices/templates`
   * is the bootstrap seeder's route and takes a different body
   * (`{role, template}`, docs/device/api.md §4.1).
   *
   * @param request - Template creation request
   * @returns Created template
   */
  async createTemplate(request: CreateDeviceTemplateRequest): Promise<ApiResponse<DeviceTemplate>> {
    return this.client.post<DeviceTemplate>(this.singularUrl('/templates'), request);
  }

  /**
   * Get template by ID
   *
   * @param id - Template ID
   * @returns Template information
   */
  async getTemplate(id: string): Promise<ApiResponse<DeviceTemplate>> {
    return this.client.get<DeviceTemplate>(this.singularUrl(`/templates/${id}`));
  }

  /**
   * Update a device template
   *
   * @param request - Template update request
   * @returns Updated template
   */
  async updateTemplate(request: UpdateDeviceTemplateRequest): Promise<ApiResponse<DeviceTemplate>> {
    return this.client.put<DeviceTemplate>(
      this.singularUrl(`/templates/${request.id}`),
      request
    );
  }

  /**
   * Delete a device template
   *
   * @param id - Template ID
   * @returns Deletion result
   */
  async deleteTemplate(id: string): Promise<ApiResponse<void>> {
    return this.client.delete(this.singularUrl(`/templates/${id}`));
  }

  /**
   * List device templates
   *
   * @param request - List request with pagination
   * @returns List of templates
   */
  async listTemplates(request?: ListDeviceTemplatesRequest): Promise<ApiResponse<DeviceTemplate[]>> {
    return this.client.get<DeviceTemplate[]>(this.singularUrl('/templates', {
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
      this.singularUrl(`/templates/${request.templateId}/create-profile`),
      request
    );
  }

  // =========================================================================
  // Config Delivery Operations
  // =========================================================================

  /**
   * Find config for a device by EK serial or MAC address
   *
   * Server route: `GET /api/v1/device/profiles/find-config`. This method previously POSTed
   * a JSON body to `/v1/devices/profiles/config`, which the server has never
   * served — wrong prefix, wrong path segment and wrong verb at once (#265).
   *
   * The identifiers travel as QUERY PARAMETERS and the server's names differ
   * from this request type's: `ekSerial` is `ek_serial`, and `macAddress` is
   * `mac` (`pkg/webservice/v1/device/template_handlers.go:302-303`). Nothing
   * in the type system catches that rename, so `findConfigForDevice` is
   * covered by a test asserting the URL that goes out rather than the object
   * that goes in.
   *
   * @param request - Device identifier request; at least one of ekSerial or
   *   macAddress must be set, or the server answers 400.
   * @returns Matching profile; when no profile matches, the server answers
   *   404 and the call fails with that status (it does not resolve to null)
   */
  async findConfigForDevice(
    request: FindConfigForDeviceRequest
  ): Promise<ApiResponse<DeviceProfile | null>> {
    const params = new URLSearchParams();
    if (request.ekSerial !== undefined && request.ekSerial !== '') {
      params.set('ek_serial', request.ekSerial);
    }
    if (request.macAddress !== undefined && request.macAddress !== '') {
      params.set('mac', request.macAddress);
    }
    const query = params.toString();
    const route = this.singularUrl('/profiles/find-config');
    const path = query.length > 0 ? `${route}?${query}` : route;

    return this.client.get<DeviceProfile | null>(path);
  }

  /**
   * Read the calling device's own profile over mTLS
   *
   * Server route: `GET /api/v1/device/profile` (`pkg/webservice/v1/router/device.go`).
   * The device identity comes from the verified client certificate, never from
   * a parameter, so this takes no request. The body is the device-facing
   * shape — `DeviceSelfServiceProfile`, camelCase by contract
   * (`docs/device/api.md` §3.2) — and NOT a `DeviceProfile`; the two are
   * different wires (#402).
   *
   * @returns The device's own profile
   */
  async getDeviceProfile(): Promise<ApiResponse<DeviceSelfServiceProfile>> {
    return this.client.get<DeviceSelfServiceProfile>(this.singularUrl('/profile'));
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
    // The server's AssignProfileToDeviceRequest decodes snake_case names. The
    // profile id travels in the path only: its body field is a plain uint64,
    // so a string fails decoding and a number loses precision above 2^53.
    const body: Record<string, string> = {};
    if (request.ekSerial !== undefined && request.ekSerial !== '') {
      body.ek_serial = request.ekSerial;
    }
    if (request.macAddress !== undefined && request.macAddress !== '') {
      body.mac_address = request.macAddress;
    }
    return this.client.post<DeviceProfile>(
      this.singularUrl(`/profiles/${request.profileId}/assign`),
      body
    );
  }

  /**
   * Unassign a profile from its device
   *
   * Server route: `POST /api/v1/device/profiles/{id}/unassign`. The route
   * reads no body; it clears the profile's device binding and returns the
   * updated profile.
   * @param profileId - Profile ID
   * @returns The updated profile
   */
  async unassignProfileFromDevice(profileId: number | string): Promise<ApiResponse<DeviceProfile>> {
    return this.client.post<DeviceProfile>(
      this.singularUrl(`/profiles/${profileId}/unassign`),
      {}
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
    // Provisioning sessions live under /api/v1/provisioning/sessions on
    // the server (not /api/v1/devices/sessions). Use an absolute path so
    // the device service's /v1/devices base doesn't get prepended.
    return this.client.get<ProvisioningSession[]>('/v1/provisioning/sessions');
  }

  /**
   * Get a provisioning session by ID
   *
   * @param sessionId - Session ID
   * @returns Provisioning session
   */
  async getProvisioningSession(sessionId: string): Promise<ApiResponse<ProvisioningSession>> {
    // Absolute path because provisioning sessions are at /api/v1/provisioning,
    // not /api/v1/devices/.
    return this.client.get<ProvisioningSession>(
      `/v1/provisioning/sessions/${this.encodePathSegment(sessionId)}`
    );
  }

  /**
   * Fulfill a provisioning session by assigning a profile
   *
   * @param request - Fulfill session request
   * @returns Fulfillment result
   */
  async fulfillProvisioningSession(request: FulfillSessionRequest): Promise<ApiResponse<void>> {
    // The request IS the server's FulfillRequest, field for field (pinned by
    // pkg/provisioning/configdelivery/session_wire_parity_test.go). The session
    // id also travels in the path; the body copy is what the handler falls
    // back to when the path segment is empty.
    return this.client.post(
      `/v1/provisioning/sessions/${this.encodePathSegment(request.session_id)}/fulfill`,
      request
    );
  }
}
