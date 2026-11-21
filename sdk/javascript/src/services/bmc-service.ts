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

  private profilePath(profileID: number, suffix: string): string {
    return this.buildUrl(`/${profileID}${suffix}`);
  }

  /**
   * Run a power action: `POST /api/v1/bmc/{profileID}/power`.
   * off, reset and cycle stop the host; the request is never retried.
   *
   * @param profileID - BMC profile ID
   * @param action - on, off, reset or cycle
   */
  async powerAction(
    profileID: number,
    action: BMCPowerAction,
  ): Promise<ApiResponse<BMCPowerActionResponse>> {
    return this.client.post<BMCPowerActionResponse>(
      this.profilePath(profileID, '/power'),
      { action },
      NO_RETRY,
    );
  }

  /** Power the host on (`POST .../power`, action on). */
  async powerOn(profileID: number): Promise<ApiResponse<BMCPowerActionResponse>> {
    return this.powerAction(profileID, 'on');
  }

  /** Power the host off (`POST .../power`, action off); stops the host. */
  async powerOff(profileID: number): Promise<ApiResponse<BMCPowerActionResponse>> {
    return this.powerAction(profileID, 'off');
  }

  /** Reset the host (`POST .../power`, action reset); stops the host. */
  async powerReset(profileID: number): Promise<ApiResponse<BMCPowerActionResponse>> {
    return this.powerAction(profileID, 'reset');
  }

  /** Power-cycle the host (`POST .../power`, action cycle); stops the host. */
  async powerCycle(profileID: number): Promise<ApiResponse<BMCPowerActionResponse>> {
    return this.powerAction(profileID, 'cycle');
  }

  /** Read the power state: `GET /api/v1/bmc/{profileID}/power`. */
  async getPowerStatus(profileID: number): Promise<ApiResponse<BMCPowerStatusResponse>> {
    return this.client.get<BMCPowerStatusResponse>(this.profilePath(profileID, '/power'));
  }

  /** Read the boot device: `GET /api/v1/bmc/{profileID}/boot-device`. */
  async getBootDevice(profileID: number): Promise<ApiResponse<BMCBootDeviceResponse>> {
    return this.client.get<BMCBootDeviceResponse>(this.profilePath(profileID, '/boot-device'));
  }

  /**
   * Set the boot device: `POST /api/v1/bmc/{profileID}/boot-device`.
   * The request is never retried.
   */
  async setBootDevice(
    profileID: number,
    request: BMCSetBootDeviceRequest,
  ): Promise<ApiResponse<BMCSetBootDeviceResponse>> {
    return this.client.post<BMCSetBootDeviceResponse>(
      this.profilePath(profileID, '/boot-device'),
      request,
      NO_RETRY,
    );
  }
}
