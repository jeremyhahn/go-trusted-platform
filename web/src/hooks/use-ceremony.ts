"use client";

import * as React from "react";
import { usePlatformClient } from "trusted-platform-sdk";
import type {
  ApiResponse,
  CeremonyCertificateResponse,
  CeremonyClaimCertBeginRequest,
  CeremonyClaimCertBeginResponse,
  CeremonyClaimCertCompleteRequest,
  CeremonyClaimShareBeginRequest,
  CeremonyClaimShareBeginResponse,
  CeremonyClaimShareCompleteRequest,
  CeremonyClaimShareCompleteResponse,
  CeremonyInitRequest,
  CeremonyInitResponse,
  CeremonySignCSRRequest,
  CeremonyStatus,
} from "trusted-platform-sdk";

/** The ceremony step a pending call belongs to */
export type CeremonyStep =
  | "init"
  | "claimCertBegin"
  | "claimCertComplete"
  | "claimShareBegin"
  | "claimShareComplete"
  | "signCSR";

export interface UseCeremonyResult {
  /** The status the server reported, or null before it answered or on refusal */
  status: CeremonyStatus | null;
  /** The server's refusal of the status read (for example no ceremony backend) */
  statusError: string | null;
  loading: boolean;
  /** The step whose call is in flight */
  pending: CeremonyStep | null;
  /** The server's refusal of the last step */
  stepError: string | null;
  refresh: () => Promise<void>;
  init: (req: CeremonyInitRequest) => Promise<CeremonyInitResponse | null>;
  claimCertBegin: (req: CeremonyClaimCertBeginRequest) => Promise<CeremonyClaimCertBeginResponse | null>;
  claimCertComplete: (req: CeremonyClaimCertCompleteRequest) => Promise<CeremonyCertificateResponse | null>;
  claimShareBegin: (req: CeremonyClaimShareBeginRequest) => Promise<CeremonyClaimShareBeginResponse | null>;
  claimShareComplete: (req: CeremonyClaimShareCompleteRequest) => Promise<CeremonyClaimShareCompleteResponse | null>;
  signCSR: (req: CeremonySignCSRRequest) => Promise<CeremonyCertificateResponse | null>;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * The daemon's key ceremony through the SDK's CeremonyService: the status
 * read on mount and every step, each returning the server's answer or null
 * with the server's message in stepError.
 */
export function useCeremony(): UseCeremonyResult {
  const client = usePlatformClient();
  const ceremony = client.ceremony;
  const [status, setStatus] = React.useState<CeremonyStatus | null>(null);
  const [statusError, setStatusError] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [pending, setPending] = React.useState<CeremonyStep | null>(null);
  const [stepError, setStepError] = React.useState<string | null>(null);

  const refresh = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await ceremony.getStatus();
      setStatus(res.data ?? null);
      setStatusError(null);
    } catch (err) {
      setStatus(null);
      setStatusError(message(err));
    } finally {
      setLoading(false);
    }
  }, [ceremony]);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  const run = React.useCallback(
    async <T,>(step: CeremonyStep, call: () => Promise<ApiResponse<T>>): Promise<T | null> => {
      setPending(step);
      setStepError(null);
      try {
        const res = await call();
        return res.data ?? null;
      } catch (err) {
        setStepError(message(err));
        return null;
      } finally {
        setPending(null);
      }
    },
    [],
  );

  const init = React.useCallback(
    async (req: CeremonyInitRequest) => {
      const out = await run("init", () => ceremony.init(req));
      if (out !== null) await refresh();
      return out;
    },
    [ceremony, refresh, run],
  );

  const claimCertBegin = React.useCallback(
    (req: CeremonyClaimCertBeginRequest) => run("claimCertBegin", () => ceremony.claimCertBegin(req)),
    [ceremony, run],
  );
  const claimCertComplete = React.useCallback(
    (req: CeremonyClaimCertCompleteRequest) => run("claimCertComplete", () => ceremony.claimCertComplete(req)),
    [ceremony, run],
  );
  const claimShareBegin = React.useCallback(
    (req: CeremonyClaimShareBeginRequest) => run("claimShareBegin", () => ceremony.claimShareBegin(req)),
    [ceremony, run],
  );
  const claimShareComplete = React.useCallback(
    (req: CeremonyClaimShareCompleteRequest) => run("claimShareComplete", () => ceremony.claimShareComplete(req)),
    [ceremony, run],
  );
  const signCSR = React.useCallback(
    (req: CeremonySignCSRRequest) => run("signCSR", () => ceremony.signCSR(req)),
    [ceremony, run],
  );

  return {
    status,
    statusError,
    loading,
    pending,
    stepError,
    refresh,
    init,
    claimCertBegin,
    claimCertComplete,
    claimShareBegin,
    claimShareComplete,
    signCSR,
  };
}
