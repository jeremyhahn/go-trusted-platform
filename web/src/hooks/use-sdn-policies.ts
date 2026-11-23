"use client";

/**
 * useSDNPolicies reads and writes the SDN policies through the SDK
 * SDNService on `/api/v1/sdn/policies`
 * (pkg/webservice/v1/rest/sdn/handlers.go: POST applies, GET lists with the
 * optional ?type= and ?target_id= filters, GET and DELETE on /{id} read and
 * delete one policy). Without an SDN service the server answers 503.
 */

import * as React from 'react';
import { useSDN, type SDNService } from 'trusted-platform-sdk';

type Data<F extends (...args: never[]) => Promise<{ data?: unknown }>> = NonNullable<Awaited<ReturnType<F>>['data']>;

/** SDNPolicyList is the listPolicies response payload. */
export type SDNPolicyList = Data<SDNService['listPolicies']>;
/** SDNPolicy is one policy as the server answers it. */
export type SDNPolicy = SDNPolicyList['policies'][number];
/** SDNPolicyFilter narrows the list by policy type and target. */
export type SDNPolicyFilter = NonNullable<Parameters<SDNService['listPolicies']>[0]>;
/** SDNApplyPolicyRequest is the apply request body. */
export type SDNApplyPolicyRequest = Parameters<SDNService['applyPolicy']>[0];

export interface UseSDNPoliciesResult {
  policies: SDNPolicy[];
  isLoading: boolean;
  error: string | null;
  /** notConfigured is true when the list read was refused with 503 (no SDN service). */
  notConfigured: boolean;
  refetch: () => Promise<void>;
  get: (id: string) => Promise<SDNPolicy | undefined>;
  apply: (request: SDNApplyPolicyRequest) => Promise<SDNPolicy | undefined>;
  remove: (id: string) => Promise<void>;
}

/** apiFailure turns an SDK refusal into the hook's Error, keeping the HTTP status. */
function apiFailure(error: { status?: number; message: string }): Error {
  return new Error(error.status !== undefined ? `HTTP ${error.status}: ${error.message}` : error.message);
}

/**
 * useSDNPolicies lists the policies (narrowed by filter) and reads, applies
 * or deletes one, listing again after each change. A refused read or change
 * rejects with the HTTP status.
 */
export function useSDNPolicies(filter: SDNPolicyFilter = {}): UseSDNPoliciesResult {
  const sdn = useSDN();
  const { type, targetId } = filter;
  const [policies, setPolicies] = React.useState<SDNPolicy[]>([]);
  const [isLoading, setIsLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [notConfigured, setNotConfigured] = React.useState(false);

  // Every read takes a sequence number and publishes only while it is still
  // the newest one, so a read for an old filter never replaces a newer one.
  const seq = React.useRef(0);

  const read = React.useCallback(async () => {
    const id = ++seq.current;
    try {
      const res = await sdn.listPolicies({ type, targetId });
      if (id !== seq.current) return;
      if (res.error) {
        setError(apiFailure(res.error).message);
        setNotConfigured(res.error.status === 503);
        setPolicies([]);
      } else {
        setError(null);
        setNotConfigured(false);
        setPolicies(res.data?.policies ?? []);
      }
    } catch (err) {
      if (id !== seq.current) return;
      setError(err instanceof Error ? err.message : String(err));
      setNotConfigured(false);
      setPolicies([]);
    } finally {
      if (id === seq.current) setIsLoading(false);
    }
  }, [sdn, type, targetId]);

  const latestRead = React.useRef(read);
  React.useLayoutEffect(() => {
    latestRead.current = read;
  }, [read]);
  const refetch = React.useCallback(() => latestRead.current(), []);

  React.useEffect(() => {
    void read();
    return () => {
      seq.current++;
    };
  }, [read]);

  const get = React.useCallback(
    async (id: string) => {
      const res = await sdn.getPolicy(id);
      if (res.error) throw apiFailure(res.error);
      return res.data?.policy;
    },
    [sdn]
  );

  const apply = React.useCallback(
    async (request: SDNApplyPolicyRequest) => {
      const res = await sdn.applyPolicy(request);
      if (res.error) throw apiFailure(res.error);
      await refetch();
      return res.data?.policy;
    },
    [sdn, refetch]
  );

  const remove = React.useCallback(
    async (id: string) => {
      const res = await sdn.deletePolicy(id);
      if (res.error) throw apiFailure(res.error);
      await refetch();
    },
    [sdn, refetch]
  );

  return { policies, isLoading, error, notConfigured, refetch, get, apply, remove };
}
