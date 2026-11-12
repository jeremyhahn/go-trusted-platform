"use client";

import { useCallback, useEffect, useState } from "react";
import { getBaseUrl } from "@/utils/getBaseUrl";
import { getCookie } from "@/utils/cookie";

/**
 * Invitation detail, lookup by token and accept (#1753).
 *
 * - GetInvitation         GET  /api/v1/invitations/{id}            (authenticated)
 * - GetInvitationByToken  GET  /api/v1/invitations/token/{token}   (public)
 * - AcceptInvitation      POST /api/v1/invitations/accept          (public)
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

export interface AcceptInvitationResult {
  success: boolean;
  message?: string;
  tenantId?: string;
  userId?: string;
}

async function readError(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { message?: string; error?: string };
    return body.message || body.error || `Request failed (${response.status})`;
  } catch {
    return `Request failed (${response.status})`;
  }
}

function unwrapInvitation(body: unknown): InvitationDetail {
  const record = body as { invitation?: InvitationDetail };
  return record.invitation ?? (body as InvitationDetail);
}

/** GetInvitation: reads one invitation by its id with the session bearer. */
export async function fetchInvitation(id: string): Promise<InvitationDetail> {
  const jwt = getCookie("jwt");
  const response = await fetch(
    `${getBaseUrl()}/api/v1/invitations/${encodeURIComponent(id)}`,
    { headers: jwt ? { Authorization: `Bearer ${jwt}` } : {} }
  );
  if (!response.ok) {
    throw new Error(await readError(response));
  }
  return unwrapInvitation(await response.json());
}

/** GetInvitationByToken: public lookup of the invitation a token names. */
export async function fetchInvitationByToken(token: string): Promise<InvitationDetail> {
  const response = await fetch(
    `${getBaseUrl()}/api/v1/invitations/token/${encodeURIComponent(token)}`
  );
  if (!response.ok) {
    throw new Error(await readError(response));
  }
  return unwrapInvitation(await response.json());
}

/** AcceptInvitation: public accept of the invitation a token names. */
export async function acceptInvitation(
  token: string,
  name?: string
): Promise<AcceptInvitationResult> {
  const body: { token: string; name?: string } = { token };
  if (name) {
    body.name = name;
  }
  const response = await fetch(`${getBaseUrl()}/api/v1/invitations/accept`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(await readError(response));
  }
  return (await response.json()) as AcceptInvitationResult;
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
    const request = id ? fetchInvitation(id) : fetchInvitationByToken(token as string);
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
