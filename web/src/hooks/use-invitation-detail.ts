'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useInvitation } from 'trusted-platform-sdk';
import type {
  ApiError,
  ApiResponse,
  Invitation,
  InvitationStatus,
  UseApiResult,
} from 'trusted-platform-sdk';

/**
 * An invitation as the REST endpoint emits it: camelCase or snake_case keys,
 * and the status as an enum name such as "INVITATION_STATUS_PENDING" (#445).
 */
export interface InvitationWire {
  id?: string;
  token?: string;
  email?: string;
  role?: string;
  status?: string;
  tenantId?: string;
  tenant_id?: string;
  tenantName?: string;
  tenant_name?: string;
  expiresAt?: string;
  expires_at?: string;
  createdAt?: string;
  created_at?: string;
  acceptedAt?: string;
  accepted_at?: string;
  invitedById?: string;
  invited_by_id?: string;
}

/** The invitation fields the detail and accept pages show. */
export interface InvitationView {
  id: string;
  email: string;
  role: string;
  status: InvitationStatus;
  tenantId: string;
  tenantName: string;
  expiresAt: string;
  createdAt: string;
  acceptedAt: string;
  invitedById: string;
}

function normalizeStatus(raw: string | undefined): InvitationStatus {
  const s = String(raw || '').toUpperCase();
  if (s.endsWith('ACCEPTED')) return 'accepted';
  if (s.endsWith('REVOKED') || s.endsWith('CANCELLED')) return 'revoked';
  if (s.endsWith('EXPIRED')) return 'expired';
  return 'pending';
}

/**
 * Normalizes a get or get-by-token response: the invitation sits at
 * `.invitation` or is the payload itself.
 */
export function toInvitationView(response: unknown): InvitationView | null {
  if (!response || typeof response !== 'object') return null;
  const envelope = response as { invitation?: InvitationWire } & InvitationWire;
  const inv: InvitationWire = envelope.invitation ?? envelope;
  if (!inv.id && !inv.email) return null;
  return {
    id: inv.id ?? '',
    email: inv.email ?? '',
    role: inv.role ?? 'member',
    status: normalizeStatus(inv.status),
    tenantId: inv.tenantId ?? inv.tenant_id ?? '',
    tenantName: inv.tenantName ?? inv.tenant_name ?? '',
    expiresAt: inv.expiresAt ?? inv.expires_at ?? '',
    createdAt: inv.createdAt ?? inv.created_at ?? '',
    acceptedAt: inv.acceptedAt ?? inv.accepted_at ?? '',
    invitedById: inv.invitedById ?? inv.invited_by_id ?? '',
  };
}

type InvitationReply = { invitation: Invitation };

/** The newest applied reply, tagged with the key and load it answers. */
interface KeyedReply {
  key: string;
  seq: number;
  data?: InvitationReply;
  error?: ApiError;
}

/**
 * Loads the invitation a key names. Unlike SDK useApi, every load is tagged
 * with its key and a sequence number: only the newest load for the current
 * key applies, so a superseded reply (an earlier key, or an older refetch)
 * is dropped, and another key's invitation is never shown (#2125).
 */
function useKeyedInvitation(
  key: string,
  fetch: (key: string) => Promise<ApiResponse<InvitationReply>>
): UseApiResult<InvitationReply> {
  const [reply, setReply] = useState<KeyedReply | null>(null);
  // The seq of the newest refetch(), so isFetching covers it.
  const [refetchSeq, setRefetchSeq] = useState(0);
  // A changed key drops the previous key's reply at once (state adjusted
  // while rendering, not in an effect).
  const [shownKey, setShownKey] = useState(key);
  if (shownKey !== key) {
    setShownKey(key);
    setReply(null);
  }

  const seqRef = useRef(0);
  const keyRef = useRef(key);
  const fetchRef = useRef(fetch);
  const mountedRef = useRef(false);
  useEffect(() => {
    keyRef.current = key;
    fetchRef.current = fetch;
  });
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // setReply runs only in promise callbacks, never synchronously in the
  // effect body (react-hooks/set-state-in-effect).
  const load = useCallback((k: string): { seq: number; done: Promise<void> } => {
    const seq = ++seqRef.current;
    const apply = (next: { data?: InvitationReply; error?: ApiError }) => {
      if (mountedRef.current && seq === seqRef.current && keyRef.current === k) {
        setReply({ key: k, seq, ...next });
      }
    };
    const done = fetchRef
      .current(k)
      .then((response) => {
        if (response.error !== undefined) {
          apply({ error: response.error as unknown as ApiError });
        } else {
          apply({ data: response.data });
        }
      })
      .catch((err: unknown) => {
        apply({ error: err as ApiError });
      });
    return { seq, done };
  }, []);

  useEffect(() => {
    if (key === '') return;
    void load(key).done;
  }, [key, load]);

  const refetch = useCallback(async (): Promise<void> => {
    const k = keyRef.current;
    if (k === '') return;
    const { seq, done } = load(k);
    setRefetchSeq(seq);
    await done;
  }, [load]);

  const mutate = useCallback(
    (next: InvitationReply | ((prev: InvitationReply | undefined) => InvitationReply)) => {
      setReply((prev) => {
        if (prev === null || prev.key !== keyRef.current) return prev;
        const data = typeof next === 'function' ? next(prev.data) : next;
        return { ...prev, data };
      });
    },
    []
  );

  const current = reply !== null && reply.key === key ? reply : null;
  const data = current?.data;
  const error = current?.error;
  const isLoading = key !== '' && current === null;
  const isFetching = isLoading || (current !== null && refetchSeq > current.seq);
  return {
    data,
    error,
    isLoading,
    isFetching,
    isError: error !== undefined,
    isSuccess: data !== undefined && error === undefined,
    refetch,
    mutate,
  };
}

/** Fetches one invitation by id (GetInvitation). */
export function useInvitationById(id: string): UseApiResult<InvitationReply> {
  const { service } = useInvitation();
  return useKeyedInvitation(id, (k) => service.get(k));
}

/** Fetches the invitation a token names (GetInvitationByToken). */
export function useInvitationByToken(token: string): UseApiResult<InvitationReply> {
  const { service } = useInvitation();
  return useKeyedInvitation(token, (k) => service.getByToken(k));
}
