/**
 * Auth factor API client — wraps /api/v1/users/{id}/factors endpoints.
 * Consumed by the Security page and login screen.
 */

import {
  ErrorCode,
  getErrorCodeFromStatus,
  type ApiResponse,
} from "trusted-platform-sdk";
import { getBaseUrl } from "./getBaseUrl";
import { getCookie } from "./cookie";
import type {
  ListAuthFactorsResponse,
  AddAuthFactorRequest,
  AddAuthFactorResponse,
  RotateAuthFactorRequest,
  RelabelAuthFactorRequest,
  MFAPolicyRequest,
  IssueMTLSCertRequest,
  IssueMTLSCertResponse,
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

/**
 * Convert an ApiResult into the SDK's ApiResponse, so a factor read can be
 * loaded through the SDK's useApi hook like every other console page (#435).
 *
 * Status 0 is how factorsFetch reports a transport failure; it maps to the
 * SDK's NETWORK_ERROR code and carries no status, because no response arrived.
 */
export function toApiResponse<T>(result: ApiResult<T>): ApiResponse<T> {
  if (result.ok) {
    return { success: true, data: result.data };
  }
  if (result.status === 0) {
    return {
      success: false,
      error: { code: ErrorCode.NETWORK_ERROR, message: result.error },
    };
  }
  return {
    success: false,
    error: {
      code: getErrorCodeFromStatus(result.status),
      message: result.error,
      status: result.status,
    },
  };
}

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

  /** Asks the platform CA to sign a client-auth certificate for the CSR. */
  issueMTLSCert(
    userId: string,
    csrPEM: string
  ): Promise<ApiResult<IssueMTLSCertResponse>> {
    const req: IssueMTLSCertRequest = { csr_pem: csrPEM };
    return factorsFetch<IssueMTLSCertResponse>(
      `/api/v1/users/${encodeURIComponent(userId)}/factors/mtls/issue-cert`,
      { method: "POST", body: JSON.stringify(req) }
    );
  },

  setMFAPolicy(req: MFAPolicyRequest): Promise<ApiResult<void>> {
    return factorsFetch<void>(
      `/api/v1/tenants/${encodeURIComponent(req.tenant_id)}/security/mfa-policy`,
      {
        method: "PUT",
        body: JSON.stringify({
          require_multiple_factors: req.require_multiple_factors,
          min_factor_count: req.min_factor_count,
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

/**
 * Why mTLS sign-in is or is not offered.
 *
 * A bare boolean cannot carry this distinction, and the distinction is the
 * whole point: "you have no client certificate" is the operator's problem to
 * fix, and "this platform does not implement mTLS login" is not. Collapsing
 * both to `false` renders an identical disabled button, so an operator holding
 * a perfectly good certificate is told nothing and reasonably concludes their
 * certificate is at fault (#199).
 */
export type MTLSAvailability =
  /** The server accepted the presented client certificate. */
  | { status: "available" }
  /** Reachable, but no acceptable client certificate was presented. */
  | { status: "no-client-certificate" }
  /** No mTLS probe endpoint on this surface — not something the operator can fix. */
  | { status: "not-supported" }
  /** The probe could not be completed; we do not know which of the above holds. */
  | { status: "unknown"; reason: string };

/**
 * Probe whether mTLS sign-in can be used, and why not when it cannot.
 *
 * `404` is treated as "not supported" rather than as a failure to detect a
 * certificate. The probe handler exists (pkg/api/rest/auth_factor_handlers.go)
 * but is registered on the daemon REST server rather than the webservice that
 * serves this console, so it currently answers 404 here. If it later becomes
 * reachable on this surface, the 404 branch simply stops firing and callers
 * begin getting the certificate-based answer with no change here.
 */
export async function probeMTLS(): Promise<MTLSAvailability> {
  let resp: Response;
  try {
    resp = await fetch(`${getBaseUrl()}/api/v1/auth/mtls/probe`, {
      method: "HEAD",
      credentials: "same-origin",
    });
  } catch (err) {
    return {
      status: "unknown",
      reason: err instanceof Error ? err.message : "the probe request failed",
    };
  }

  if (resp.ok) {
    return { status: "available" };
  }
  if (resp.status === 404) {
    return { status: "not-supported" };
  }
  if (resp.status === 401 || resp.status === 403) {
    return { status: "no-client-certificate" };
  }
  return { status: "unknown", reason: `the probe returned HTTP ${resp.status}` };
}

/** Detect whether a client cert is loaded (server echoes the TLS cert fingerprint). */
export async function isMTLSAvailable(): Promise<boolean> {
  return (await probeMTLS()).status === "available";
}
