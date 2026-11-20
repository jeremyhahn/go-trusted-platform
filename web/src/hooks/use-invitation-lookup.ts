"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useInvitation } from "trusted-platform-sdk";

/**
 * Invitation detail and lookup by token (#1753, #2056), through the SDK
 * InvitationService, never a hand-written fetch.
 *
 * - GetInvitation         GET  /api/v1/invitations/{id}            (authenticated)
 * - GetInvitationByToken  GET  /api/v1/invitations/token/{token}   (public)
 *
 * AcceptInvitation (POST /api/v1/invitations/accept) is deliberately not
 * offered here: the server marks the invitation accepted without adding the
 * user to the tenant, so joining goes through the passkey sign-up
 * (RegisterInvitedUser) and the accept control is gated off
 * (app/(auth)/invite/[token]/accept-invitation-gate.tsx).
 */

export interface InvitationDetail {
  id: string;
  email: string;
  role: string;
  status: string;
  expires_at?: string;
  created_at?: string;
  tenant_id?: string;
  tenant_name?: string;
}

/**
 * Reads the invitation out of what the SDK returns ({invitation}) or a raw
 * REST envelope ({code, success, payload: {invitation, timestamp}}), and
 * normalizes the protojson camelCase fields to snake_case.
 */
export function toInvitationDetail(body: unknown): InvitationDetail {
  const record = (body ?? {}) as {
    invitation?: Record<string, unknown>;
    payload?: { invitation?: Record<string, unknown> };
  };
  const invitation = record.payload?.invitation ?? record.invitation;
  if (!invitation) {
    throw new Error("The server returned no invitation");
  }
  const { expiresAt, createdAt, tenantId, tenantName, ...rest } = invitation;
  const pick = (snake: unknown, camel: unknown) => (snake ?? camel) as string | undefined;
  const detail = { ...rest } as unknown as InvitationDetail;
  const fields: Array<[keyof InvitationDetail, string | undefined]> = [
    ["expires_at", pick(rest.expires_at, expiresAt)],
    ["created_at", pick(rest.created_at, createdAt)],
    ["tenant_id", pick(rest.tenant_id, tenantId)],
    ["tenant_name", pick(rest.tenant_name, tenantName)],
  ];
  for (const [key, value] of fields) {
    if (value !== undefined) {
      (detail as unknown as Record<string, unknown>)[key] = value;
    }
  }
  return detail;
}

/**
 * True when an invitation can still be accepted. The wire carries the
 * protobuf enum string (INVITATION_STATUS_PENDING); older mocks and views
 * use "pending".
 */
export function isPendingInvitation(status: string | undefined | null): boolean {
  const s = (status ?? "").toLowerCase();
  return s === "pending" || s === "invitation_status_pending";
}

export interface InvitationLookupState {
  invitation: InvitationDetail | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
}

type LookupResponse = {
  success: boolean;
  data?: unknown;
  error?: { message?: string };
};

/**
 * Loads an invitation either by id (`{ id }`, GetInvitation) or by token
 * (`{ token }`, GetInvitationByToken). With neither set it stays idle and
 * reports an error.
 */
export function useInvitationLookup(key: { id?: string | null; token?: string | null }): InvitationLookupState {
  const { id, token } = key;
  const { service } = useInvitation();
  // The service object may be rebuilt per render; the effect reads the
  // latest one without re-running on it.
  const serviceRef = useRef(service);
  useEffect(() => {
    serviceRef.current = service;
  }, [service]);

  const [nonce, setNonce] = useState(0);
  // The settled answer, tagged with the request it answers, so loading is
  // derived (no synchronous setState in the effect).
  const [result, setResult] = useState<{
    requestKey: string;
    invitation: InvitationDetail | null;
    error: string | null;
  } | null>(null);

  const named = Boolean(id || token);
  const requestKey = `${id ?? ""}|${token ?? ""}|${nonce}`;

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    if (!id && !token) {
      return;
    }
    let cancelled = false;
    const svc = serviceRef.current;
    const request = (id ? svc.get(id) : svc.getByToken(token as string)) as Promise<LookupResponse>;
    request
      .then((res) => {
        if (!res.success) {
          throw new Error(res.error?.message || "Failed to load invitation");
        }
        return toInvitationDetail(res.data);
      })
      .then((found) => {
        if (!cancelled) setResult({ requestKey, invitation: found, error: null });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setResult({
            requestKey,
            invitation: null,
            error: err instanceof Error ? err.message : "Failed to load invitation",
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [id, token, requestKey]);

  if (!named) {
    return { invitation: null, loading: false, error: "No invitation was named", reload };
  }
  const settled = result !== null && result.requestKey === requestKey;
  return {
    invitation: settled ? result.invitation : null,
    loading: !settled,
    error: settled ? result.error : null,
    reload,
  };
}
