/**
 * BMC Service
 *
 * Out-of-band operations on a server's baseboard management controller,
 * addressed by the BMC profile ID: power status, boot device, virtual
 * media, sensors, system info, provisioning and the BMC's web certificate
 * (#1736). Power on/off/reset/cycle have no REST route and are not here.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';

/** GET /bmc/{profileID}/power */
export interface BMCPowerStatus {
  state: string;
}

/** GET and POST /bmc/{profileID}/boot-device */
export interface BMCBootDevice {
  device: string;
  persistent?: boolean;
}

/** POST /bmc/{profileID}/virtual-media: MountISORequest (400 when iso_url is empty) */
export interface BMCMountISORequest {
  iso_url: string;
}

/** GET /bmc/{profileID}/virtual-media: VirtualMediaInfo */
export interface BMCVirtualMediaStatus {
  mounted: boolean;
  image_url?: string;
  media_type?: string;
}

/** One SensorReading; GET /bmc/{profileID}/sensors returns a plain array of them */
export interface BMCSensor {
  name: string;
  value: number;
  units: string;
  status: string;
}

/** GET /bmc/{profileID}/system-info: SystemInfo */
export interface BMCSystemInfo {
  manufacturer: string;
  product: string;
  serial_number: string;
  firmware_version: string;
  bios_version: string;
  power_state: string;
}

/** POST (201) and GET /bmc/{profileID}/provision: ProvisionResult */
export interface BMCProvisionStatus {
  provision_id: string;
  profile_id: string;
  /** pending, connecting, setting_boot, mounting_iso, powering_on, installing, finalizing, complete or failed */
  status: string;
  message?: string;
  started_at: string;
  updated_at: string;
}

/** GET /bmc/{profileID}/cert: CertificateInfo (metadata, no PEM) */
export interface BMCWebCertificate {
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  days_remaining: number;
  subject_alternative_names?: string[];
  fingerprint: string;
}

/** The result of a mutating BMC call */
export interface BMCOperationResult {
  success?: boolean;
  message?: string;
}

/**
 * BMC Service class
 *
 * @example
 * ```typescript
 * const power = await client.bmc.getPowerStatus('1');
 * await client.bmc.setBootDevice('1', { device: 'pxe' });
 * ```
 */
export class BMCService extends BaseService {
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/bmc');
  }

  private path(profileID: string, op: string): string {
    return this.buildUrl(`/${this.encodePathSegment(profileID)}/${op}`);
  }

  /** PowerStatus: GET /bmc/{profileID}/power */
  async getPowerStatus(profileID: string): Promise<ApiResponse<BMCPowerStatus>> {
    return this.client.get<BMCPowerStatus>(this.path(profileID, 'power'));
  }

  /** GetBootDevice: GET /bmc/{profileID}/boot-device */
  async getBootDevice(profileID: string): Promise<ApiResponse<BMCBootDevice>> {
    return this.client.get<BMCBootDevice>(this.path(profileID, 'boot-device'));
  }

  /** SetBootDevice: POST /bmc/{profileID}/boot-device */
  async setBootDevice(profileID: string, request: BMCBootDevice): Promise<ApiResponse<BMCOperationResult>> {
    return this.client.post<BMCOperationResult>(this.path(profileID, 'boot-device'), request);
  }

  /** VirtualMediaStatus: GET /bmc/{profileID}/virtual-media */
  async getVirtualMediaStatus(profileID: string): Promise<ApiResponse<BMCVirtualMediaStatus>> {
    return this.client.get<BMCVirtualMediaStatus>(this.path(profileID, 'virtual-media'));
  }

  /** MountISO: POST /bmc/{profileID}/virtual-media */
  async mountISO(profileID: string, request: BMCMountISORequest): Promise<ApiResponse<BMCOperationResult>> {
    return this.client.post<BMCOperationResult>(this.path(profileID, 'virtual-media'), request);
  }

  /** UnmountISO: DELETE /bmc/{profileID}/virtual-media */
  async unmountISO(profileID: string): Promise<ApiResponse<BMCOperationResult>> {
    return this.client.delete<BMCOperationResult>(this.path(profileID, 'virtual-media'));
  }

  /** GetSensors: GET /bmc/{profileID}/sensors */
  async getSensors(profileID: string): Promise<ApiResponse<BMCSensor[]>> {
    return this.client.get<BMCSensor[]>(this.path(profileID, 'sensors'));
  }

  /** GetSystemInfo: GET /bmc/{profileID}/system-info */
  async getSystemInfo(profileID: string): Promise<ApiResponse<BMCSystemInfo>> {
    return this.client.get<BMCSystemInfo>(this.path(profileID, 'system-info'));
  }

  /**
   * Provision: POST /bmc/{profileID}/provision. Starts bare-metal host
   * provisioning: the host is powered off, booted once from the network
   * (PXE), an operating system is installed, then disk boot is set and the
   * host power-cycled. The host's disks can be overwritten.
   */
  async provision(profileID: string): Promise<ApiResponse<BMCProvisionStatus>> {
    return this.client.post<BMCProvisionStatus>(this.path(profileID, 'provision'), {});
  }

  /** ProvisionStatus: GET /bmc/{profileID}/provision */
  async getProvisionStatus(profileID: string): Promise<ApiResponse<BMCProvisionStatus>> {
    return this.client.get<BMCProvisionStatus>(this.path(profileID, 'provision'));
  }

  /** GetWebCertificate: GET /bmc/{profileID}/cert */
  async getWebCertificate(profileID: string): Promise<ApiResponse<BMCWebCertificate>> {
    return this.client.get<BMCWebCertificate>(this.path(profileID, 'cert'));
  }
}
