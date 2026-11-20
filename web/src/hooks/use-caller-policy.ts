"use client";
import * as React from "react";
import { useAttestation } from "trusted-platform-sdk";
import type { CallerPolicyDescription } from "trusted-platform-sdk";

/** DescribeCallerPolicy (GET /v1/attestation/callers) for the console (#2038). */
export interface UseCallerPolicyResult {
  policy?: CallerPolicyDescription;
  error?: string;
  loading: boolean;
  reload: () => Promise<void>;
}

export function useCallerPolicy(): UseCallerPolicyResult {
  const attestation = useAttestation();
  const [state, setState] = React.useState<Omit<UseCallerPolicyResult, "reload">>({ loading: true });

  const reload = React.useCallback(async () => {
    setState((prev) => ({ ...prev, loading: true }));
    try {
      const response = await attestation.describeCallers();
      if (!response.success) {
        setState({ loading: false, error: response.error?.message ?? "The request failed" });
        return;
      }
      setState({ loading: false, policy: response.data });
    } catch (err) {
      setState({ loading: false, error: err instanceof Error ? err.message : String(err) });
    }
  }, [attestation]);

  React.useEffect(() => {
    void reload();
  }, [reload]);

  return { ...state, reload };
}
