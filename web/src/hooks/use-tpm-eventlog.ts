"use client";
import { useApi, useTPM } from "trusted-platform-sdk";
import type { GetEventLogResponse } from "trusted-platform-sdk";

/** Summary of a TPM event log for the dashboard cards. */
export interface EventLogSummary {
  /** Events in the log: parsed entries, else the server's count */
  total: number;
  /** Log format, `tcg2` when the server leaves it empty */
  format: string;
  /** Distinct PCRs the parsed entries extend */
  pcrsTouched: number;
  /** The most-extended PCR and its entry count */
  mostMeasured: [number, number] | undefined;
}

const DEFAULT_FORMAT = "tcg2";

/** Raw bytes of the base64 event log; empty for an absent or invalid log. */
export function eventLogBytes(b64: string | undefined | null): Uint8Array<ArrayBuffer> {
  if (!b64) return new Uint8Array(0);
  let bin: string;
  try {
    bin = atob(b64);
  } catch {
    return new Uint8Array(0);
  }
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}

/** Download file name for the raw log of a format. */
export function eventLogFileName(format: string | undefined | null): string {
  return `tpm-eventlog-${format || DEFAULT_FORMAT}.bin`;
}

/** Count and per-PCR summary of an event log response. */
export function summarizeEventLog(
  log: GetEventLogResponse | null | undefined
): EventLogSummary {
  const entries = log?.entries ?? [];
  const byPCR = new Map<number, number>();
  for (const e of entries) {
    byPCR.set(e.pcrIndex, (byPCR.get(e.pcrIndex) ?? 0) + 1);
  }
  const mostMeasured = [...byPCR.entries()].sort((a, b) => b[1] - a[1])[0];
  return {
    total: entries.length || log?.eventCount || 0,
    format: log?.format || DEFAULT_FORMAT,
    pcrsTouched: byPCR.size,
    mostMeasured,
  };
}

/**
 * The TPM event log (TPMService.GetEventLog) and its summary (#2069).
 * The caller passes the TPM client from `useTPM()`.
 */
export function useTPMEventLog(
  tpm: Pick<ReturnType<typeof useTPM>, "getEventLog">,
  onError?: (err: Error) => void
) {
  const query = useApi(() => tpm.getEventLog(), [], { onError });
  const summary = summarizeEventLog(query.data);
  return { ...query, summary };
}
