"use client";
import * as React from "react";
import { useAttestation } from "trusted-platform-sdk";
import type {
  ApiResponse,
  AttestationQuoteConfig,
  GetAttestationQuoteResponse,
  HostManifest,
  VerifyAttestationQuoteResponse,
  VerifyManifestResponse,
} from "trusted-platform-sdk";

import { newAttestationNonce } from "./use-attestation-collect";

/**
 * VerifyManifest, GetAttestationQuote and VerifyAttestationQuote for the
 * console (#2038), through the SDK client only.
 */

/** The outcome of one operation. */
export interface AttestationCallState<T> {
  pending: boolean;
  result?: T;
  error?: string;
  /** The server answered 503: the operation is not configured on this node. */
  unavailable?: boolean;
}

export interface UseAttestationVerifyResult {
  manifest: AttestationCallState<VerifyManifestResponse>;
  quote: AttestationCallState<GetAttestationQuoteResponse>;
  verdict: AttestationCallState<VerifyAttestationQuoteResponse>;
  /** The nonce the held quote was requested with. */
  quoteNonce?: string;
  verifyManifest: (manifest: HostManifest) => Promise<boolean>;
  getQuote: (config?: AttestationQuoteConfig) => Promise<boolean>;
  verifyQuote: (akPublicKeyPem: string) => Promise<boolean>;
}

export const QUOTE_REQUIRED = "Get a quote first: there is no quote to verify.";

type WithStatus = { status?: { success: boolean; message?: string; error?: { message: string } } };

async function call<T extends WithStatus>(
  set: (s: AttestationCallState<T>) => void,
  request: () => Promise<ApiResponse<T>>
): Promise<T | undefined> {
  set({ pending: true });
  try {
    const response = await request();
    if (!response.success) {
      set({
        pending: false,
        error: response.error?.message ?? "The request failed",
        unavailable: response.error?.status === 503,
      });
      return undefined;
    }
    const data = response.data as T;
    if (data?.status && data.status.success === false) {
      set({
        pending: false,
        result: data,
        error: data.status.error?.message || data.status.message || "The operation failed",
      });
      return undefined;
    }
    set({ pending: false, result: data });
    return data;
  } catch (err) {
    set({ pending: false, error: err instanceof Error ? err.message : String(err) });
    return undefined;
  }
}

export function useAttestationVerify(): UseAttestationVerifyResult {
  const attestation = useAttestation();
  const [manifest, setManifest] = React.useState<AttestationCallState<VerifyManifestResponse>>({
    pending: false,
  });
  const [quote, setQuote] = React.useState<AttestationCallState<GetAttestationQuoteResponse>>({
    pending: false,
  });
  const [verdict, setVerdict] = React.useState<AttestationCallState<VerifyAttestationQuoteResponse>>({
    pending: false,
  });
  const [quoteNonce, setQuoteNonce] = React.useState<string>();

  const verifyManifest = React.useCallback(
    async (m: HostManifest) =>
      (await call(setManifest, () => attestation.verifyManifest({ manifest: m }))) !== undefined,
    [attestation]
  );

  const getQuote = React.useCallback(
    async (config: AttestationQuoteConfig = {}) => {
      const nonce = newAttestationNonce();
      setVerdict({ pending: false });
      setQuoteNonce(nonce);
      return (await call(setQuote, () => attestation.getQuote({ config, nonce }))) !== undefined;
    },
    [attestation]
  );

  const held = quote.result?.quote;
  const binding = quote.result?.channelBinding;
  const verifyQuote = React.useCallback(
    async (akPublicKeyPem: string) => {
      if (!held || !quoteNonce) {
        setVerdict({ pending: false, error: QUOTE_REQUIRED });
        return false;
      }
      const data = await call(setVerdict, () =>
        attestation.verifyQuote({
          quote: held,
          akPublicKeyPem,
          expectedNonce: quoteNonce,
          ...(binding ? { channelBinding: binding } : {}),
        })
      );
      return data !== undefined;
    },
    [attestation, held, binding, quoteNonce]
  );

  return { manifest, quote, verdict, quoteNonce, verifyManifest, getQuote, verifyQuote };
}
