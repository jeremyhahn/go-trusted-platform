"use client";

/**
 * BMC accounts hook: ListUsers, CreateUser, DeleteUser, SetUserPassword and
 * SetUserPrivilege (pkg/webservice/v1/bmc/handler.go), served under
 * `/api/v1/bmc/{profileID}/users`:
 *
 *   GET    /bmc/{profileID}/users                       ListUsers
 *   POST   /bmc/{profileID}/users                       CreateUser
 *   DELETE /bmc/{profileID}/users/{slot}                DeleteUser
 *   PUT    /bmc/{profileID}/users/{slot}/password       SetUserPassword
 *   PUT    /bmc/{profileID}/users/{slot}/privilege      SetUserPrivilege
 *
 * It calls the SDK BMCService (`client.bmc`), which sends the same requests.
 * ListUsers answers the privilege as the IPMI number; the writes take it as a
 * name.
 */

import { useMemo } from "react";
import { usePlatformClient, type ApiResponse } from "trusted-platform-sdk";

/** A privilege name the BMC handler accepts on CreateUser and SetUserPrivilege. */
export type BMCPrivilegeName = "callback" | "user" | "operator" | "administrator" | "no-access";

/** One BMC user account as ListUsers answers it; privilege is the IPMI number. */
export interface BMCUser {
  slot: number;
  username: string;
  enabled: boolean;
  privilege: number;
  channel: number;
}

/** The CreateUser request; enabled defaults to true and channel to 1. */
export interface CreateBMCUserInput {
  slot: number;
  username: string;
  password: string;
  privilege: BMCPrivilegeName;
  enabled?: boolean;
  channel?: number;
}

/** The `{status: "ok"}` answer of DeleteUser, SetUserPassword and SetUserPrivilege. */
export interface BMCStatusOK {
  status: string;
}

const PRIVILEGE_NAMES: Record<number, BMCPrivilegeName> = {
  1: "callback",
  2: "user",
  3: "operator",
  4: "administrator",
  15: "no-access",
};

/** IPMI privilege number to name: 1 callback, 2 user, 3 operator, 4 administrator, 15 no-access; anything else `unknown(<n>)`. */
export function bmcPrivilegeName(level: number): string {
  return PRIVILEGE_NAMES[level] ?? `unknown(${level})`;
}

/** The users path of a BMC profile, optionally of one slot and one of its operations. */
export function bmcUsersPath(profileID: string, slot?: number, op?: "password" | "privilege"): string {
  return (
    `/v1/bmc/${encodeURIComponent(profileID)}/users` +
    (slot !== undefined ? `/${slot}` : "") +
    (op ? `/${op}` : "")
  );
}

/** useBMCAccounts returns the user-account operations of one BMC profile. */
export function useBMCAccounts(profileID: string) {
  const client = usePlatformClient();
  return useMemo(
    () => ({
      listUsers: (): Promise<ApiResponse<BMCUser[]>> => client.bmc.listUsers(profileID),
      createUser: (input: CreateBMCUserInput): Promise<ApiResponse<BMCUser>> =>
        client.bmc.createUser(profileID, { ...input, username: input.username.trim() }),
      deleteUser: (slot: number): Promise<ApiResponse<BMCStatusOK>> => client.bmc.deleteUser(profileID, slot),
      setPassword: (slot: number, password: string): Promise<ApiResponse<BMCStatusOK>> =>
        client.bmc.setUserPassword(profileID, slot, password),
      setPrivilege: (slot: number, privilege: BMCPrivilegeName, channel = 1): Promise<ApiResponse<BMCStatusOK>> =>
        client.bmc.setUserPrivilege(profileID, slot, privilege, channel),
    }),
    [client, profileID]
  );
}
