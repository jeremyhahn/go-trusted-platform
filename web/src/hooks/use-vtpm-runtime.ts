"use client";

/**
 * vTPM bundle runtime hook (#1726).
 *
 * Wraps the SDK's bundle runtime routes (start, stop, quote, seal, unseal,
 * PCR extend and PCR read) for one bundle. IsVTPMRunning has no REST route,
 * so the running state is tracked from the start and stop results.
 */

import * as React from "react";
import { useVTPM, useMutation } from "trusted-platform-sdk";
import type {
  QuoteBundleRequest,
  SealBundleRequest,
  UnsealBundleRequest,
  ExtendBundlePCRRequest,
} from "trusted-platform-sdk";

/** Running state as the last start or stop result left it. */
export type VTPMRunState = "unknown" | "running" | "stopped";

export function useVTPMRuntime(bundleId: string) {
  const vtpm = useVTPM();
  const [runState, setRunState] = React.useState<VTPMRunState>("unknown");
  const [stateError, setStateError] = React.useState<string | null>(null);

  // Every write of the running state (a state read sent, a start or stop
  // reply) takes the next sequence number; a state read applies only when
  // nothing wrote after it was sent, so a late read cannot overwrite a newer
  // start or stop reply.
  const seq = React.useRef(0);
  const alive = React.useRef(true);
  React.useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const writeRunState = (s: VTPMRunState) => {
    seq.current += 1;
    setRunState(s);
  };

  // IsVTPMRunning (GET /bundles/{id}/state).
  const refreshState = React.useCallback(async () => {
    if (bundleId.trim() === "") return;
    seq.current += 1;
    const sent = seq.current;
    try {
      const r = await vtpm.isBundleRunning(bundleId);
      if (!alive.current || seq.current !== sent) return;
      if (!r.success || !r.data) {
        const message = (r as { error?: { message?: string } }).error?.message;
        throw new Error(message || "Failed to read the vTPM state");
      }
      setRunState(r.data.running ? "running" : "stopped");
      setStateError(null);
    } catch (err) {
      if (!alive.current || seq.current !== sent) return;
      setStateError(err instanceof Error ? err.message : String(err));
    }
  }, [vtpm, bundleId]);

  // Read the server state once per bundle; the panel is keyed on the bundle,
  // so a new bundle remounts the hook.
  React.useEffect(() => {
    void refreshState();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bundleId]);

  const start = useMutation(() => vtpm.startBundle(bundleId), {
    onSuccess: (r) => writeRunState(r.running ? "running" : "stopped"),
  });
  const stop = useMutation(() => vtpm.stopBundle(bundleId), {
    onSuccess: (r) => {
      if (r.stopped) writeRunState("stopped");
    },
  });
  const quote = useMutation((req: QuoteBundleRequest) => vtpm.quoteBundle(bundleId, req));
  const seal = useMutation((req: SealBundleRequest) => vtpm.sealBundle(bundleId, req));
  const unseal = useMutation((req: UnsealBundleRequest) => vtpm.unsealBundle(bundleId, req));
  const extendPCR = useMutation((req: ExtendBundlePCRRequest) =>
    vtpm.extendBundlePCR(bundleId, req)
  );
  const readPCR = useMutation((pcrIndex: number) => vtpm.readBundlePCR(bundleId, pcrIndex));

  // Start and stop write the same running state: while either is pending,
  // neither may be sent, so a late reply cannot overwrite a newer one.
  const lifecycleBusy = start.isLoading || stop.isLoading;

  return {
    runState,
    stateError,
    refreshState,
    lifecycleBusy,
    start,
    stop,
    quote,
    seal,
    unseal,
    extendPCR,
    readPCR,
  };
}

/** Text to base64 (UTF-8). */
export function textToBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  bytes.forEach((b) => {
    bin += String.fromCharCode(b);
  });
  return btoa(bin);
}

/** Base64 to text (UTF-8). */
export function base64ToText(b64: string): string {
  const bin = atob(b64);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

/** Hex data to base64; throws on odd length or a non-hex digit. */
export function hexToBase64(hex: string): string {
  const clean = hex.trim().replace(/^0x/i, "");
  if (clean.length === 0 || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    throw new Error("Data must be an even number of hex digits");
  }
  let bin = "";
  for (let i = 0; i < clean.length; i += 2) {
    bin += String.fromCharCode(parseInt(clean.slice(i, i + 2), 16));
  }
  return btoa(bin);
}

/** Base64 to lower-case hex. */
export function base64ToHex(b64: string): string {
  return Array.from(atob(b64), (c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
}
