"use client";
import * as React from 'react';

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

async function call(method: string, path: string, body?: unknown): Promise<unknown> {
  const res = await fetch(path, {
    method,
    credentials: 'include',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let parsed: unknown = undefined;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
  }
  if (!res.ok) {
    const env = parsed as { error?: { message?: string } | string; message?: string } | undefined;
    const msg =
      (typeof env?.error === 'object' ? env.error?.message : env?.error) ?? env?.message ?? `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return parsed;
}

function unwrap<T>(body: unknown): T | undefined {
  if (body && typeof body === 'object') {
    const env = body as { payload?: T; data?: T };
    if (env.payload !== undefined) return env.payload;
    if (env.data !== undefined) return env.data;
  }
  return body as T | undefined;
}

/**
 * useBMCUsers drives the BMC user and web certificate operations of one
 * BMC profile (#1720) over /api/v1/bmc/{profileID}/...
 *
 * The SDK carries the same calls as BMCService; the web consumes the
 * SDK's built bundle, so this hook calls the REST routes directly with
 * the session cookie, as useReportedGateways does.
 */
export function useBMCUsers(profileID: string): UseBMCUsersResult {
  const base = `/api/v1/bmc/${encodeURIComponent(profileID)}`;
  const [users, setUsers] = React.useState<BMCUserSlot[]>([]);
  const [isLoading, setIsLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  // The base whose listing last succeeded; null while none has.
  const [listedFor, setListedFor] = React.useState<string | null>(null);

  // load sets state only once the request settles, so the mount effect
  // below never sets state synchronously (react-hooks/set-state-in-effect).
  const load = React.useCallback(async () => {
    try {
      const list = unwrap<BMCUserSlot[]>(await call('GET', `${base}/users`));
      setUsers(Array.isArray(list) ? list : []);
      setError(null);
      setListedFor(base);
    } catch (e: unknown) {
      setUsers([]);
      setListedFor(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setIsLoading(false);
    }
  }, [base]);

  const refetch = React.useCallback(async () => {
    setListedFor(null);
    setIsLoading(true);
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

  const createUser = React.useCallback(
    async (input: CreateBMCUserInput) => {
      await call('POST', `${base}/users`, input);
      await refetch();
    },
    [base, refetch]
  );

  const deleteUser = React.useCallback(
    async (slot: number) => {
      await call('DELETE', `${base}/users/${slot}`);
      await refetch();
    },
    [base, refetch]
  );

  const setUserPassword = React.useCallback(
    async (slot: number, password: string) => {
      await call('PUT', `${base}/users/${slot}/password`, { password });
    },
    [base]
  );

  const setUserPrivilege = React.useCallback(
    async (slot: number, privilege: BMCPrivilege, channel: number) => {
      await call('PUT', `${base}/users/${slot}/privilege`, { privilege, channel });
      await refetch();
    },
    [base, refetch]
  );

  const replaceWebCertificate = React.useCallback(
    async (certPem: string, keyPem: string) => {
      await call('PUT', `${base}/cert`, { cert_pem: certPem, key_pem: keyPem });
    },
    [base]
  );

  return {
    users,
    isLoading,
    error,
    listed: listedFor === base && !isLoading && error === null,
    refetch,
    createUser,
    deleteUser,
    setUserPassword,
    setUserPrivilege,
    replaceWebCertificate,
  };
}
