"use client";

/**
 * The CeremonyService hook (#2042) on the SDK's `client.ceremony`: Init,
 * Status, ClaimCertBegin, ClaimCertComplete, ClaimShareBegin,
 * ClaimShareComplete and SignCSR.
 *
 * Init's reply carries the admin private key and ClaimShareComplete's reply a
 * Shamir share, so the hook keeps no copy of any reply: no state, no cache and
 * no logging. The caller owns what it is handed.
 */

import { useMemo } from "react";
import {
  usePlatformClient,
  type CeremonyClaimCertBeginRequest,
  type CeremonyClaimCertCompleteRequest,
  type CeremonyClaimShareBeginRequest,
  type CeremonyClaimShareCompleteRequest,
  type CeremonyInitRequest,
  type CeremonySignCSRRequest,
} from "trusted-platform-sdk";

export type {
  CeremonyState,
  CeremonyAuthenticatorType,
  CeremonyOfficerRole,
  CeremonyInitRequest,
  CeremonyInitResponse,
  CeremonyStatusResponse,
  CeremonyClaimCertBeginRequest,
  CeremonyClaimCertBeginResponse,
  CeremonyClaimCertCompleteRequest,
  CeremonyClaimCertCompleteResponse,
  CeremonyClaimShareBeginRequest,
  CeremonyClaimShareBeginResponse,
  CeremonyClaimShareCompleteRequest,
  CeremonyClaimShareCompleteResponse,
  CeremonySignCSRRequest,
  CeremonySignCSRResponse,
} from "trusted-platform-sdk";

export function useCeremony() {
  const client = usePlatformClient();
  return useMemo(
    () => ({
      init: (request: CeremonyInitRequest) => client.ceremony.init(request),
      status: () => client.ceremony.status(),
      claimCertBegin: (request: CeremonyClaimCertBeginRequest) =>
        client.ceremony.claimCertBegin(request),
      claimCertComplete: (request: CeremonyClaimCertCompleteRequest) =>
        client.ceremony.claimCertComplete(request),
      claimShareBegin: (request: CeremonyClaimShareBeginRequest) =>
        client.ceremony.claimShareBegin(request),
      claimShareComplete: (request: CeremonyClaimShareCompleteRequest) =>
        client.ceremony.claimShareComplete(request),
      signCSR: (request: CeremonySignCSRRequest) => client.ceremony.signCSR(request),
    }),
    [client]
  );
}
