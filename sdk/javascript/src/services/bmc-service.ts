/**
 * BMC Service
 *
 * IPMI user accounts on a device profile's BMC.
 * Wire contract: pkg/webservice/v1/bmc/handler.go and types.go
 * (`/api/v1/bmc/{profileID}/users...`, plain JSON bodies).
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';

/** IPMI privilege name a request carries. */
export type BMCPrivilegeName = 'no-access' | 'callback' | 'user' | 'operator' | 'administrator';

/** One BMC user slot as the server answers it. */
export interface BMCUser {
  slot: number;
  username: string;
  enabled: boolean;
  /** IPMI level: 1 callback, 2 user, 3 operator, 4 administrator, 15 no-access. */
  privilege: number;
  channel: number;
}

/** Body of a create-user request. */
export interface CreateBMCUserRequest {
  slot: number;
  username: string;
  password: string;
  privilege: BMCPrivilegeName;
  /** Defaults to true. */
  enabled?: boolean;
  /** Defaults to 1. */
  channel?: number;
}

/** `{status: "ok"}` answer of the delete, password and privilege routes. */
export interface BMCStatusOK {
  status: string;
}

/**
 * BMC Service class
 *
 * @example
 * ```typescript
 * const users = await client.bmc.listUsers(profileId);
 * await client.bmc.createUser(profileId, { slot: 3, username: 'ops', password: 'pw', privilege: 'operator' });
 * await client.bmc.setUserPrivilege(profileId, 3, 'user');
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

  /**
   * List the BMC users of a profile.
   * `GET /bmc/{profileID}/users` (handler.go ListUsers)
   */
  async listUsers(profileId: string | number): Promise<ApiResponse<BMCUser[]>> {
    return this.client.get<BMCUser[]>(this.buildUrl(`/${profileId}/users`));
  }

  /**
   * Create a BMC user; enabled defaults to true and channel to 1.
   * `POST /bmc/{profileID}/users` (handler.go CreateUser)
   */
  async createUser(
    profileId: string | number,
    req: CreateBMCUserRequest
  ): Promise<ApiResponse<BMCUser>> {
    const body = {
      slot: req.slot,
      username: req.username,
      password: req.password,
      privilege: req.privilege,
      enabled: req.enabled ?? true,
      channel: req.channel ?? 1,
    };
    return this.client.post<BMCUser>(this.buildUrl(`/${profileId}/users`), body);
  }

  /**
   * Delete the BMC user in a slot.
   * `DELETE /bmc/{profileID}/users/{slot}` (handler.go DeleteUser)
   */
  async deleteUser(profileId: string | number, slot: number): Promise<ApiResponse<BMCStatusOK>> {
    return this.client.delete<BMCStatusOK>(this.buildUrl(`/${profileId}/users/${slot}`));
  }

  /**
   * Set the password of the BMC user in a slot.
   * `PUT /bmc/{profileID}/users/{slot}/password` (handler.go SetUserPassword)
   */
  async setUserPassword(
    profileId: string | number,
    slot: number,
    password: string
  ): Promise<ApiResponse<BMCStatusOK>> {
    return this.client.put<BMCStatusOK>(this.buildUrl(`/${profileId}/users/${slot}/password`), {
      password,
    });
  }

  /**
   * Set the privilege of the BMC user in a slot on a channel (default 1).
   * `PUT /bmc/{profileID}/users/{slot}/privilege` (handler.go SetUserPrivilege)
   */
  async setUserPrivilege(
    profileId: string | number,
    slot: number,
    privilege: BMCPrivilegeName,
    channel = 1
  ): Promise<ApiResponse<BMCStatusOK>> {
    return this.client.put<BMCStatusOK>(this.buildUrl(`/${profileId}/users/${slot}/privilege`), {
      privilege,
      channel,
    });
  }
}
