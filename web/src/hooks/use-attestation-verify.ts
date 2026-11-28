"use client";

/**
 * useAttestationVerify reaches VerifyManifest, GetAttestationQuote and
 * VerifyAttestationQuote through the SDK AttestationService (#2038), never a
 * hand-written fetch. `quoteAndVerify` asks for a quote and verifies it with
 * the nonce and the channel binding the quote came back with: the node quoted
 * SHA-256(nonce || channelBinding), so a bound quote verifies only when that
 * binding is sent back with the nonce.
 */

import { useMemo } from "react";
import {
  useAttestation,
  type ApiResponse,
  type AttestationQuoteConfig,
  type GetAttestationQuoteRequest,
  type GetAttestationQuoteResponse,
  type VerifyAttestationQuoteRequest,
  type VerifyAttestationQuoteResponse,
  type VerifyManifestRequest,
  type VerifyManifestResponse,
} from "trusted-platform-sdk";

export interface QuoteAndVerifyInput {
  config: AttestationQuoteConfig;
  nonce: string;
  akPublicKeyPem: string;
}

export interface QuoteAndVerifyResult {
  quote: ApiResponse<GetAttestationQuoteResponse>;
  verify?: ApiResponse<VerifyAttestationQuoteResponse>;
}

/** "Verified", "Not verified: <message>" (or "Not verified" with no message), or "Unknown" for undefined. */
export function quoteVerdictLabel(r?: VerifyAttestationQuoteResponse): string {
  if (!r) return "Unknown";
  if (r.verified) return "Verified";
  return r.message ? `Not verified: ${r.message}` : "Not verified";
}

export function useAttestationVerify() {
  const attestation = useAttestation();
  return useMemo(
    () => ({
      verifyManifest: (req: VerifyManifestRequest): Promise<ApiResponse<VerifyManifestResponse>> =>
        attestation.verifyManifest(req),
      getQuote: (req: GetAttestationQuoteRequest): Promise<ApiResponse<GetAttestationQuoteResponse>> =>
        attestation.getQuote(req),
      verifyQuote: (req: VerifyAttestationQuoteRequest): Promise<ApiResponse<VerifyAttestationQuoteResponse>> =>
        attestation.verifyQuote(req),
      quoteAndVerify: async (input: QuoteAndVerifyInput): Promise<QuoteAndVerifyResult> => {
        const quote = await attestation.getQuote({ config: input.config, nonce: input.nonce });
        const q = quote.success ? quote.data?.quote : undefined;
        if (!q) return { quote };
        const verify = await attestation.verifyQuote({
          quote: q,
          akPublicKeyPem: input.akPublicKeyPem,
          expectedNonce: input.nonce,
          ...(quote.data?.channelBinding ? { channelBinding: quote.data.channelBinding } : {}),
        });
        return { quote, verify };
      },
    }),
    [attestation]
  );
}
