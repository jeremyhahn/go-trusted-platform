"use client";
import * as React from "react";
import { useAttestation } from "trusted-platform-sdk";
import type { DeviceVerdictEvent } from "trusted-platform-sdk";

/**
 * PollDeviceVerdicts (GET /v1/attestation/verdicts) for the console (#2038).
 * Polls once on mount; poll() continues from the last cursor and appends.
 */
export interface UseDeviceVerdictsResult {
  verdicts: DeviceVerdictEvent[];
  cursor?: string;
  error?: string;
  loading: boolean;
  poll: () => Promise<void>;
}

export function useDeviceVerdicts(): UseDeviceVerdictsResult {
  const attestation = useAttestation();
  const [verdicts, setVerdicts] = React.useState<DeviceVerdictEvent[]>([]);
  const [error, setError] = React.useState<string>();
  const [loading, setLoading] = React.useState(true);
  const cursorRef = React.useRef<string | undefined>(undefined);
  const [cursor, setCursor] = React.useState<string>();

  const poll = React.useCallback(async () => {
    setLoading(true);
    const from = cursorRef.current;
    try {
      const response = await attestation.pollDeviceVerdicts(from ? { cursor: from } : {});
      if (!response.success) {
        setError(response.error?.message ?? "The request failed");
        return;
      }
      setError(undefined);
      const page = response.data;
      if (page?.cursor) {
        cursorRef.current = page.cursor;
        setCursor(page.cursor);
      }
      const next = page?.verdicts ?? [];
      if (next.length > 0) setVerdicts((prev) => [...prev, ...next]);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [attestation]);

  React.useEffect(() => {
    void poll();
  }, [poll]);

  return { verdicts, cursor, error, loading, poll };
}
