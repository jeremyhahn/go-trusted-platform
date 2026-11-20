"use client";
import * as React from 'react';
import { usePlatformClient, type ApiResponse } from 'trusted-platform-sdk';

/**
 * Privilege names the BMC REST surface accepts.
 */
export const BMC_PRIVILEGES = ['no-access', 'callback', 'user', 'operator', 'administrator'] as const;
export type BMCPrivilege = (typeof BMC_PRIVILEGES)[number];

const PRIVILEGE_CODES: Record<BMCPrivilege, number> = {
  'no-access': 0x0f,
  callback: 0x01,
  user: 0x02,
  operator: 0x03,
  administrator: 0x04,
};

/**
 * bmcPrivilegeLabel turns the IPMI privilege code a user listing carries
 * into its REST name ('unknown' for a code the surface does not define).
 */
export function bmcPrivilegeLabel(code: number | string): BMCPrivilege | 'unknown' {
  if (typeof code === 'string') {
    return (BMC_PRIVILEGES as readonly string[]).includes(code) ? (code as BMCPrivilege) : 'unknown';
  }
  const hit = BMC_PRIVILEGES.find((p) => PRIVILEGE_CODES[p] === code);
  return hit ?? 'unknown';
}

export interface BMCUserSlot {
  slot: number;
  username: string;
  enabled: boolean;
  privilege: number | string;
  channel: number;
}

export interface CreateBMCUserInput {
  slot: number;
  username: string;
  password: string;
  privilege: BMCPrivilege;
  enabled: boolean;
  channel: number;
}

export interface UseBMCUsersResult {
  users: BMCUserSlot[];
  isLoading: boolean;
  error: string | null;
  /**
   * True only once a listing of the current profile has succeeded and no
   * reload is in flight. CreateUser writes the slot it is given without an
   * occupancy check, so creation must wait for this.
   */
  listed: boolean;
  refetch: () => Promise<void>;
  createUser: (input: CreateBMCUserInput) => Promise<void>;
  deleteUser: (slot: number) => Promise<void>;
  setUserPassword: (slot: number, password: string) => Promise<void>;
  setUserPrivilege: (slot: number, privilege: BMCPrivilege, channel: number) => Promise<void>;
  replaceWebCertificate: (certPem: string, keyPem: string) => Promise<void>;
}

/** Returns the data of an SDK response, or throws its error message */
async function sdkData<T>(p: Promise<ApiResponse<T>>): Promise<T> {
  const res = await p;
  if (!res.success) {
    throw new Error(res.error?.message || 'BMC request failed');
  }
  return res.data as T;
}

/**
 * useBMCUsers drives the BMC user and web certificate operations of one
 * BMC profile (#1720) through PlatformClient.bmc (BMCService), so the
 * SDK's base URL, auth interceptors and transport apply (#1675 F27).
 */
interface Listing {
  base: string;
  users: BMCUserSlot[];
  error: string | null;
}

const EMPTY_USERS: BMCUserSlot[] = [];

export function useBMCUsers(profileID: string): UseBMCUsersResult {
  const bmc = usePlatformClient().bmc;
  // The listing tag: the profile a listing was read for.
  const base = profileID;
  // The last settled listing, tagged with the base it was read from. Rows
  // and errors of another profile are never shown for this one.
  const [listing, setListing] = React.useState<Listing | null>(null);
  // True while a refetch of the current base is in flight.
  const [refreshing, setRefreshing] = React.useState(false);
  // Each load takes a number; only the newest load may set state, so a
  // superseded request (an earlier profile, an earlier refetch) is dropped.
  const seq = React.useRef(0);

  // load sets state only once the request settles, so the mount effect
  // below never sets state synchronously (react-hooks/set-state-in-effect).
  const load = React.useCallback(async () => {
    const mine = ++seq.current;
    let next: Listing;
    try {
      const list = (await sdkData(bmc.listUsers(profileID))) as unknown as BMCUserSlot[] | undefined;
      next = { base, users: Array.isArray(list) ? list : [], error: null };
    } catch (e: unknown) {
      next = { base, users: [], error: e instanceof Error ? e.message : String(e) };
    }
    if (mine !== seq.current) return;
    setListing(next);
    setRefreshing(false);
  }, [base, bmc, profileID]);

  const refetch = React.useCallback(async () => {
    setRefreshing(true);
    await load();
  }, [load]);

  React.useEffect(() => {
    // An empty ID is the static-export placeholder before the client has
    // read the real profile ID from the URL: there is nothing to fetch yet.
    if (!profileID) {
      return;
    }
    let cancelled = false;
    Promise.resolve().then(() => {
      if (!cancelled) void load();
    });
    return () => {
      cancelled = true;
    };
  }, [load, profileID]);

  const current = listing !== null && listing.base === base ? listing : null;
  const users = current ? current.users : EMPTY_USERS;
  const error = current ? current.error : null;
  const isLoading = current === null || refreshing;
  const listed = current !== null && !refreshing && current.error === null;

  // A slot names a row of the listing on screen. Until the current
  // profile has listed (a profile change or a reload is in flight) the rows
  // may be another profile's, so slot mutations are refused, not sent.
  const requireListed = React.useCallback(() => {
    if (!listed) {
      throw new Error('BMC users are still loading for this profile; try again once they are listed');
    }
  }, [listed]);

  const createUser = React.useCallback(
    async (input: CreateBMCUserInput) => {
      requireListed();
      await sdkData(bmc.createUser(profileID, input));
      await refetch();
    },
    [bmc, profileID, refetch, requireListed]
  );

  const deleteUser = React.useCallback(
    async (slot: number) => {
      requireListed();
      await sdkData(bmc.deleteUser(profileID, slot));
      await refetch();
    },
    [bmc, profileID, refetch, requireListed]
  );

  const setUserPassword = React.useCallback(
    async (slot: number, password: string) => {
      requireListed();
      await sdkData(bmc.setUserPassword(profileID, slot, password));
    },
    [bmc, profileID, requireListed]
  );

  const setUserPrivilege = React.useCallback(
    async (slot: number, privilege: BMCPrivilege, channel: number) => {
      requireListed();
      await sdkData(bmc.setUserPrivilege(profileID, slot, privilege, channel));
      await refetch();
    },
    [bmc, profileID, refetch, requireListed]
  );

  const replaceWebCertificate = React.useCallback(
    async (certPem: string, keyPem: string) => {
      await sdkData(bmc.replaceWebCertificate(profileID, { certPem, keyPem }));
    },
    [bmc, profileID]
  );

  return {
    users,
    isLoading,
    error,
    listed,
    refetch,
    createUser,
    deleteUser,
    setUserPassword,
    setUserPrivilege,
    replaceWebCertificate,
  };
}
