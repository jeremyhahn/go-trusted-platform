/**
 * BMC Service
 *
 * BMC user accounts and the BMC web certificate (#1720).
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';

/**
 * Privilege names the REST surface accepts (pkg/webservice/v1/bmc).
 */
export type BMCPrivilegeName = 'no-access' | 'callback' | 'user' | 'operator' | 'administrator';

/**
 * IPMI privilege codes the REST surface returns in a user listing.
 */
export const BMC_PRIVILEGE_CODES: Readonly<Record<BMCPrivilegeName, number>> = {
  'no-access': 0x0f,
  callback: 0x01,
  user: 0x02,
  operator: 0x03,
  administrator: 0x04,
};

/**
 * Returns the privilege name for an IPMI privilege code, or 'unknown'.
 */
export function bmcPrivilegeName(code: number | string): BMCPrivilegeName | 'unknown' {
  if (typeof code === 'string') {
    return code in BMC_PRIVILEGE_CODES ? (code as BMCPrivilegeName) : 'unknown';
  }
  const entry = Object.entries(BMC_PRIVILEGE_CODES).find(([, v]) => v === code);
  return entry ? (entry[0] as BMCPrivilegeName) : 'unknown';
}

/**
 * A BMC user slot as ListUsers returns it.
 */
export interface BMCUser {
  slot: number;
  username: string;
  enabled: boolean;
  /** IPMI privilege code (see BMC_PRIVILEGE_CODES). */
  privilege: number;
  channel: number;
}

export interface CreateBMCUserRequest {
  /** 1-based slot; 0 asks the BMC for the next free slot where supported. */
  slot: number;
  username: string;
  password: string;
  privilege: BMCPrivilegeName;
  enabled: boolean;
  channel: number;
}

export interface ReplaceBMCWebCertificateRequest {
  certPem: string;
  keyPem: string;
}

export interface BMCStatusResponse {
  status: string;
}

/**
 * BMC Service class
 *
 * @example
 * ```typescript
 * const users = await client.bmc.listUsers(1);
 * await client.bmc.setUserPrivilege(1, 3, 'operator', 1);
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

  private profilePath(profileID: number | string, suffix: string): string {
    return `/${this.encodePathSegment(String(profileID))}${suffix}`;
  }

  /**
   * Replace the BMC web (HTTPS) certificate and its key.
   */
  async replaceWebCertificate(
    profileID: number | string,
    request: ReplaceBMCWebCertificateRequest
  ): Promise<ApiResponse<BMCStatusResponse>> {
    return this.client.put<BMCStatusResponse>(
      this.buildUrl(this.profilePath(profileID, '/cert')),
      { cert_pem: request.certPem, key_pem: request.keyPem }
    );
  }

  /**
   * List the populated user slots of a BMC.
   */
  async listUsers(profileID: number | string): Promise<ApiResponse<BMCUser[]>> {
    return this.client.get<BMCUser[]>(this.buildUrl(this.profilePath(profileID, '/users')));
  }

  /**
   * Create a BMC user.
   */
  async createUser(
    profileID: number | string,
    request: CreateBMCUserRequest
  ): Promise<ApiResponse<BMCUser>> {
    return this.client.post<BMCUser>(this.buildUrl(this.profilePath(profileID, '/users')), {
      slot: request.slot,
      username: request.username,
      password: request.password,
      privilege: request.privilege,
      enabled: request.enabled,
      channel: request.channel,
    });
  }

  /**
   * Delete a BMC user slot.
   */
  async deleteUser(
    profileID: number | string,
    slot: number
  ): Promise<ApiResponse<BMCStatusResponse>> {
    return this.client.delete<BMCStatusResponse>(
      this.buildUrl(this.profilePath(profileID, `/users/${slot}`))
    );
  }

  /**
   * Set the password of a BMC user slot.
   */
  async setUserPassword(
    profileID: number | string,
    slot: number,
    password: string
  ): Promise<ApiResponse<BMCStatusResponse>> {
    return this.client.put<BMCStatusResponse>(
      this.buildUrl(this.profilePath(profileID, `/users/${slot}/password`)),
      { password }
    );
  }

  /**
   * Set the channel privilege of a BMC user slot.
   */
  async setUserPrivilege(
    profileID: number | string,
    slot: number,
    privilege: BMCPrivilegeName,
    channel: number
  ): Promise<ApiResponse<BMCStatusResponse>> {
    return this.client.put<BMCStatusResponse>(
      this.buildUrl(this.profilePath(profileID, `/users/${slot}/privilege`)),
      { privilege, channel }
    );
  }
}
