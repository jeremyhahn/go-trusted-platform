/**
 * Auth factor API client — wraps /api/v1/users/{id}/factors endpoints.
 * Consumed by the Security page and login screen.
 */

import { getBaseUrl } from "./getBaseUrl";
import { getCookie } from "./cookie";
import type {
  AuthFactor,
  ListAuthFactorsResponse,
  AddAuthFactorRequest,
  AddAuthFactorResponse,
  RotateAuthFactorRequest,
  RelabelAuthFactorRequest,
  MFAPolicyRequest,
} from "@/types/auth-factors";

interface ApiOk<T> {
  ok: true;
  data: T;
}

interface ApiErr {
  ok: false;
  error: string;
  status: number;
}

type ApiResult<T> = ApiOk<T> | ApiErr;

async function factorsFetch<T>(
  path: string,
  options: RequestInit = {}
): Promise<ApiResult<T>> {
  const jwt = getCookie("jwt");
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (jwt) {
    headers["Authorization"] = `Bearer ${jwt}`;
  }

  try {
    const resp = await fetch(`${getBaseUrl()}${path}`, {
      ...options,
      credentials: "same-origin",
      headers,
    });

    if (!resp.ok) {
      let msg = `HTTP ${resp.status}`;
      try {
        const body = (await resp.json()) as { error?: string; message?: string };
        msg = body.error ?? body.message ?? msg;
      } catch {
        /* ignore json parse error */
      }
      return { ok: false, error: msg, status: resp.status };
    }

    const data = (await resp.json()) as T;
    return { ok: true, data };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : "Network error",
      status: 0,
    };
  }
}

export const authFactorsApi = {
  list(userId: string): Promise<ApiResult<ListAuthFactorsResponse>> {
    return factorsFetch<ListAuthFactorsResponse>(
      `/api/v1/users/${encodeURIComponent(userId)}/factors`
    );
  },

  add(
    userId: string,
    req: AddAuthFactorRequest
  ): Promise<ApiResult<AddAuthFactorResponse>> {
    return factorsFetch<AddAuthFactorResponse>(
      `/api/v1/users/${encodeURIComponent(userId)}/factors`,
      { method: "POST", body: JSON.stringify(req) }
    );
  },

  remove(userId: string, factorId: string): Promise<ApiResult<void>> {
    return factorsFetch<void>(
      `/api/v1/users/${encodeURIComponent(userId)}/factors/${encodeURIComponent(factorId)}`,
      { method: "DELETE" }
    );
  },

  rotate(
    userId: string,
    req: RotateAuthFactorRequest
  ): Promise<ApiResult<AddAuthFactorResponse>> {
    return factorsFetch<AddAuthFactorResponse>(
      `/api/v1/users/${encodeURIComponent(userId)}/factors/${encodeURIComponent(req.factor_id)}/rotate`,
      { method: "PUT", body: JSON.stringify(req) }
    );
  },

  relabel(
    userId: string,
    req: RelabelAuthFactorRequest
  ): Promise<ApiResult<void>> {
    return factorsFetch<void>(
      `/api/v1/users/${encodeURIComponent(userId)}/factors/${encodeURIComponent(req.factor_id)}/label`,
      { method: "PATCH", body: JSON.stringify({ label: req.label }) }
    );
  },

  setMFAPolicy(req: MFAPolicyRequest): Promise<ApiResult<void>> {
    return factorsFetch<void>(
      `/api/v1/tenants/${encodeURIComponent(req.tenant_id)}/security/mfa-policy`,
      {
        method: "PUT",
        body: JSON.stringify({
          require_factor_count: req.require_factor_count,
        }),
      }
    );
  },
};

/** Detect whether the browser has the WebAuthn API available. */
export function isFIDO2Available(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential !== "undefined"
  );
}

/** Detect whether a client cert is loaded (server echoes the TLS cert fingerprint). */
export async function isMTLSAvailable(): Promise<boolean> {
  try {
    const resp = await fetch(`${getBaseUrl()}/api/v1/auth/mtls/probe`, {
      method: "HEAD",
      credentials: "same-origin",
    });
    return resp.ok;
  } catch {
    return false;
  }
}
