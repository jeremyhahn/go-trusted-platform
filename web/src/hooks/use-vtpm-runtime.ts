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

  const start = useMutation(() => vtpm.startBundle(bundleId), {
    onSuccess: (r) => setRunState(r.running ? "running" : "stopped"),
  });
  const stop = useMutation(() => vtpm.stopBundle(bundleId), {
    onSuccess: (r) => {
      if (r.stopped) setRunState("stopped");
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

  return { runState, lifecycleBusy, start, stop, quote, seal, unseal, extendPCR, readPCR };
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
