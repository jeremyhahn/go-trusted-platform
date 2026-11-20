"use client";

import { useCallback, useEffect, useState } from "react";
import { usePlatformClient, type ApiResponse } from "trusted-platform-sdk";

/**
 * Invitation detail, lookup by token and accept (#1753), through
 * `PlatformClient.invitation`, so the SDK's base URL, auth interceptors and
 * transport apply (#1675 F27).
 *
 * - GetInvitation         GET  /api/v1/invitations/{id}            (authenticated)
 * - GetInvitationByToken  GET  /api/v1/invitations/token/{token}   (public)
 * - AcceptInvitation      POST /api/v1/invitations/accept          (public)
 */

export type InvitationClient = ReturnType<typeof usePlatformClient>["invitation"];

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

export interface AcceptInvitationResult {
  success: boolean;
  message?: string;
  tenantId?: string;
  userId?: string;
}

// The SDK client unwraps the {success, payload} envelope and never throws on
// an HTTP error; a failed call becomes an Error with the server's message.
async function sdkData<T>(p: Promise<ApiResponse<T>>): Promise<T> {
  const res = await p;
  if (!res.success) {
    throw new Error(res.error?.message || "invitation request failed");
  }
  return res.data as T;
}

function unwrapInvitation(body: unknown): InvitationDetail {
  // The gateway answers with its REST envelope
  // {code, success, payload: {invitation, timestamp}}; a bare {invitation}
  // is accepted too. The envelope itself is never the invitation.
  const record = (body ?? {}) as {
    invitation?: Record<string, unknown>;
    payload?: { invitation?: Record<string, unknown> };
  };
  const invitation = record.payload?.invitation ?? record.invitation;
  if (!invitation) {
    throw new Error("The server returned no invitation");
  }
  // GetInvitation marshals its protobuf with protojson field names
  // (expiresAt, createdAt, tenantId, tenantName); InvitationDetail and
  // the pages that read it use snake_case.
  const { expiresAt, createdAt, tenantId, tenantName, ...rest } = invitation;
  const pick = (snake: unknown, camel: unknown) =>
    (snake ?? camel) as string | undefined;
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

/** GetInvitation: reads one invitation by its id (the SDK carries the session). */
export async function fetchInvitation(
  invitations: InvitationClient,
  id: string
): Promise<InvitationDetail> {
  return unwrapInvitation(await sdkData(invitations.get(id)));
}

/** GetInvitationByToken: public lookup of the invitation a token names. */
export async function fetchInvitationByToken(
  invitations: InvitationClient,
  token: string
): Promise<InvitationDetail> {
  return unwrapInvitation(await sdkData(invitations.getByToken(token)));
}

/** AcceptInvitation: public accept of the invitation a token names. */
export async function acceptInvitation(
  invitations: InvitationClient,
  token: string,
  userId: string
): Promise<AcceptInvitationResult> {
  return (await sdkData(invitations.accept({ token, userId }))) as AcceptInvitationResult;
}

export interface InvitationLookupState {
  invitation: InvitationDetail | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
}

/**
 * Loads an invitation either by id (`{ id }`) or by token (`{ token }`).
 * With neither set it stays idle and reports an error.
 */
export function useInvitationLookup(key: { id?: string | null; token?: string | null }): InvitationLookupState {
  const { id, token } = key;
  const invitations = usePlatformClient().invitation;
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
    const request = id
      ? fetchInvitation(invitations, id)
      : fetchInvitationByToken(invitations, token as string);
    request
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
  }, [invitations, id, token, requestKey]);

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
