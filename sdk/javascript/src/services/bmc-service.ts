/**
 * BMC Service
 *
 * Power control and boot-device selection for a BMC profile.
 * Wire contract: pkg/webservice/v1/bmc/handler.go and types.go
 * (`POST|GET /api/v1/bmc/{profileID}/power`,
 * `POST|GET /api/v1/bmc/{profileID}/boot-device`; profileID is numeric).
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';

/** A power action the BMC power route accepts. */
export type BMCPowerAction = 'on' | 'off' | 'reset' | 'cycle';

/** Answer to `POST /api/v1/bmc/{profileID}/power`. */
export interface BMCPowerActionResponse {
  status: string;
  action: string;
}

/** Answer to `GET /api/v1/bmc/{profileID}/power`. */
export interface BMCPowerStatusResponse {
  state: string;
}

/** Body of `POST /api/v1/bmc/{profileID}/boot-device`. */
export interface BMCSetBootDeviceRequest {
  device: string;
  persistent?: boolean;
}

/** Answer to `POST /api/v1/bmc/{profileID}/boot-device`. */
export interface BMCSetBootDeviceResponse {
  status: string;
  device: string;
}

/** Answer to `GET /api/v1/bmc/{profileID}/boot-device`. */
export interface BMCBootDeviceResponse {
  device: string;
}

/** Answer to `GET /api/v1/bmc/{profileID}/virtual-media` (pkg/bmc VirtualMediaInfo). */
export interface BMCVirtualMediaStatus {
  mounted: boolean;
  image_url?: string;
  media_type?: string;
}

/** Answer to `POST /api/v1/bmc/{profileID}/virtual-media`. */
export interface BMCMountISOResponse {
  status: string;
  iso_url: string;
}

/** A plain `{ status }` answer, as `DELETE .../virtual-media` sends. */
export interface BMCStatusResponse {
  status: string;
}

/** One reading of `GET /api/v1/bmc/{profileID}/sensors`; status ok, warning or critical. */
export interface BMCSensorReading {
  name: string;
  value: number;
  units: string;
  status: string;
}

/** Answer to `GET /api/v1/bmc/{profileID}/system-info`. */
export interface BMCSystemInfo {
  manufacturer: string;
  product: string;
  serial_number: string;
  firmware_version: string;
  bios_version: string;
  power_state: string;
}

/** Answer to `GET /api/v1/bmc/{profileID}/cert`. */
export interface BMCWebCertificate {
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  days_remaining: number;
}

/** Body of `POST /api/v1/bmc/{profileID}/provision`. */
export interface BMCProvisionRequest {
  iso_url?: string;
}

/** Answer to `POST` and `GET /api/v1/bmc/{profileID}/provision`. */
export interface BMCProvisionResult {
  provision_id: string;
  profile_id: number;
  status: string;
  message?: string;
  started_at: string;
  updated_at: string;
}

/**
 * Writes that change host state are never retried: a repeated power off,
 * reset or cycle would stop the host a second time.
 */
const NO_RETRY = { retry: { enabled: false } } as const;

/**
 * BMC Service class
 *
 * @example
 * ```typescript
 * const status = await client.bmc.getPowerStatus(7);
 * await client.bmc.powerCycle(7);
 * await client.bmc.setBootDevice(7, { device: 'pxe', persistent: false });
 * ```
 */
export class BMCService extends BaseService {
  /**
   * Creates a new BMC service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/bmc');
  }

  private profilePath(profileID: string | number, suffix: string): string {
    return this.buildUrl(`/${encodeURIComponent(String(profileID))}${suffix}`);
  }

  /**
   * Run a power action: `POST /api/v1/bmc/{profileID}/power`.
   * off, reset and cycle stop the host; the request is never retried.
   *
   * @param profileID - BMC profile ID
   * @param action - on, off, reset or cycle
   */
  async powerAction(
    profileID: string | number,
    action: BMCPowerAction,
  ): Promise<ApiResponse<BMCPowerActionResponse>> {
    return this.client.post<BMCPowerActionResponse>(
      this.profilePath(profileID, '/power'),
      { action },
      NO_RETRY,
    );
  }

  /** Power the host on (`POST .../power`, action on). */
  async powerOn(profileID: string | number): Promise<ApiResponse<BMCPowerActionResponse>> {
    return this.powerAction(profileID, 'on');
  }

  /** Power the host off (`POST .../power`, action off); stops the host. */
  async powerOff(profileID: string | number): Promise<ApiResponse<BMCPowerActionResponse>> {
    return this.powerAction(profileID, 'off');
  }

  /** Reset the host (`POST .../power`, action reset); stops the host. */
  async powerReset(profileID: string | number): Promise<ApiResponse<BMCPowerActionResponse>> {
    return this.powerAction(profileID, 'reset');
  }

  /** Power-cycle the host (`POST .../power`, action cycle); stops the host. */
  async powerCycle(profileID: string | number): Promise<ApiResponse<BMCPowerActionResponse>> {
    return this.powerAction(profileID, 'cycle');
  }

  /** Read the power state: `GET /api/v1/bmc/{profileID}/power`. */
  async getPowerStatus(profileID: string | number): Promise<ApiResponse<BMCPowerStatusResponse>> {
    return this.client.get<BMCPowerStatusResponse>(this.profilePath(profileID, '/power'));
  }

  /** Read the boot device: `GET /api/v1/bmc/{profileID}/boot-device`. */
  async getBootDevice(profileID: string | number): Promise<ApiResponse<BMCBootDeviceResponse>> {
    return this.client.get<BMCBootDeviceResponse>(this.profilePath(profileID, '/boot-device'));
  }

  /**
   * Set the boot device: `POST /api/v1/bmc/{profileID}/boot-device`.
   * The request is never retried.
   */
  async setBootDevice(
    profileID: string | number,
    request: BMCSetBootDeviceRequest,
  ): Promise<ApiResponse<BMCSetBootDeviceResponse>> {
    return this.client.post<BMCSetBootDeviceResponse>(
      this.profilePath(profileID, '/boot-device'),
      request,
      NO_RETRY,
    );
  }

  /** Read the virtual media: `GET /api/v1/bmc/{profileID}/virtual-media`. */
  async getVirtualMediaStatus(
    profileID: string | number,
  ): Promise<ApiResponse<BMCVirtualMediaStatus>> {
    return this.client.get<BMCVirtualMediaStatus>(this.profilePath(profileID, '/virtual-media'));
  }

  /**
   * Mount an ISO as virtual media: `POST /api/v1/bmc/{profileID}/virtual-media`.
   * The request is never retried.
   */
  async mountISO(
    profileID: string | number,
    isoURL: string,
  ): Promise<ApiResponse<BMCMountISOResponse>> {
    return this.client.post<BMCMountISOResponse>(
      this.profilePath(profileID, '/virtual-media'),
      { iso_url: isoURL },
      NO_RETRY,
    );
  }

  /**
   * Eject the virtual media: `DELETE /api/v1/bmc/{profileID}/virtual-media`.
   * The request is never retried: a late retry could eject media mounted since.
   */
  async unmountISO(profileID: string | number): Promise<ApiResponse<BMCStatusResponse>> {
    return this.client.delete<BMCStatusResponse>(
      this.profilePath(profileID, '/virtual-media'),
      NO_RETRY,
    );
  }

  /** Read the sensors: `GET /api/v1/bmc/{profileID}/sensors`. */
  async getSensors(profileID: string | number): Promise<ApiResponse<BMCSensorReading[]>> {
    return this.client.get<BMCSensorReading[]>(this.profilePath(profileID, '/sensors'));
  }

  /** Read the system info: `GET /api/v1/bmc/{profileID}/system-info`. */
  async getSystemInfo(profileID: string | number): Promise<ApiResponse<BMCSystemInfo>> {
    return this.client.get<BMCSystemInfo>(this.profilePath(profileID, '/system-info'));
  }

  /** Read the BMC web certificate: `GET /api/v1/bmc/{profileID}/cert`. */
  async getWebCertificate(profileID: string | number): Promise<ApiResponse<BMCWebCertificate>> {
    return this.client.get<BMCWebCertificate>(this.profilePath(profileID, '/cert'));
  }

  /**
   * Start a provision: `POST /api/v1/bmc/{profileID}/provision`.
   * It reboots the host into the installer; the request is never retried.
   */
  async provision(
    profileID: string | number,
    request: BMCProvisionRequest = {},
  ): Promise<ApiResponse<BMCProvisionResult>> {
    return this.client.post<BMCProvisionResult>(
      this.profilePath(profileID, '/provision'),
      request,
      NO_RETRY,
    );
  }

  /** Read the provision status: `GET /api/v1/bmc/{profileID}/provision`. */
  async getProvisionStatus(profileID: string | number): Promise<ApiResponse<BMCProvisionResult>> {
    return this.client.get<BMCProvisionResult>(this.profilePath(profileID, '/provision'));
  }
}
