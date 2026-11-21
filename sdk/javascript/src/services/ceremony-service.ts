/**
 * Ceremony Service
 *
 * The platform bootstrap ceremony: initialise the CA, report its state, let
 * officers claim their certificates and Shamir shares, and sign CSRs with
 * the ceremony CA. Wire contract: pkg/api/grpc/proto/ceremony.proto over
 * the webservice REST binding (`/api/v1/ceremony/*`,
 * pkg/webservice/v1/rest/ceremony). Bodies are protojson (camelCase field
 * names, enums as their proto names, int64/bytes as strings).
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';

/** Life-cycle state of the ceremony. */
export type CeremonyState =
  | 'CEREMONY_STATE_UNSPECIFIED'
  | 'CEREMONY_STATE_UNINITIALIZED'
  | 'CEREMONY_STATE_IN_PROGRESS'
  | 'CEREMONY_STATE_COMPLETE';

/** Officer authenticator backend. */
export type CeremonyAuthenticatorType =
  | 'CEREMONY_AUTHENTICATOR_TYPE_UNSPECIFIED'
  | 'CEREMONY_AUTHENTICATOR_TYPE_PIV'
  | 'CEREMONY_AUTHENTICATOR_TYPE_FIDO2'
  | 'CEREMONY_AUTHENTICATOR_TYPE_SOFTWARE';

/** Officer role. */
export type CeremonyOfficerRole =
  | 'CEREMONY_OFFICER_ROLE_UNSPECIFIED'
  | 'CEREMONY_OFFICER_ROLE_SO'
  | 'CEREMONY_OFFICER_ROLE_ADMIN'
  | 'CEREMONY_OFFICER_ROLE_USER';

/** Seeds a fresh ceremony. */
export interface CeremonyInitRequest {
  soPin?: string;
  userPin?: string;
  /** Threshold descriptor, e.g. "3-of-5". */
  threshold?: string;
  hostname?: string;
  sans?: string[];
  credentialSealStrategy?: string;
}

/**
 * Returned by init. The caller MUST persist adminCertPem and adminKeyPem:
 * the platform keeps no copy.
 */
export interface CeremonyInitResponse {
  ceremonyId: string;
  state: CeremonyState;
  /** RFC 3339 timestamp. */
  initializedAt?: string;
  adminCertPem: string;
  adminKeyPem: string;
  /** SHA-256 SPKI pin of the issuing CA. */
  spkiPin: string;
}

/** The current ceremony state. */
export interface CeremonyStatusResponse {
  ceremonyId: string;
  state: CeremonyState;
  threshold: string;
  officersEnrolled: number;
  officersRequired: number;
  /** RFC 3339 timestamp. */
  initializedAt?: string;
}

/** Requests a claim-cert challenge for an officer. */
export interface CeremonyClaimCertBeginRequest {
  username: string;
  authenticatorType?: CeremonyAuthenticatorType;
  slot?: string;
  credentialId?: string;
}

/** The issued claim-cert challenge. */
export interface CeremonyClaimCertBeginResponse {
  nonce: string;
  challengeId: string;
  /** RFC 3339 timestamp. */
  expiresAt?: string;
}

/** Completes a claim-cert challenge with a signature over the nonce. */
export interface CeremonyClaimCertCompleteRequest {
  username: string;
  nonce: string;
  signature: string;
}

/** The issued officer certificate. */
export interface CeremonyClaimCertCompleteResponse {
  certificatePem: string;
  chainPem: string;
}

/** Requests a claim-share challenge for an officer. */
export interface CeremonyClaimShareBeginRequest {
  username: string;
}

/** The issued claim-share challenge. */
export interface CeremonyClaimShareBeginResponse {
  nonce: string;
  /** RFC 3339 timestamp. */
  expiresAt?: string;
}

/** Completes a claim-share challenge. */
export interface CeremonyClaimShareCompleteRequest {
  username: string;
  nonce: string;
  /** Signature over the nonce, base64. */
  signature: string;
}

/** The officer's Shamir share. */
export interface CeremonyClaimShareCompleteResponse {
  share: string;
  index: number;
}

/** Signs a CSR with the ceremony CA. */
export interface CeremonySignCSRRequest {
  username: string;
  soPin: string;
  csrPem: string;
  role?: CeremonyOfficerRole;
}

/** The signed certificate. */
export interface CeremonySignCSRResponse {
  certificatePem: string;
  chainPem: string;
}

/**
 * Service for the platform bootstrap ceremony.
 */
export class CeremonyService extends BaseService {
  /**
   * Creates a new ceremony service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/ceremony');
  }

  /** Initialise the ceremony. The reply carries the admin private key. */
  async init(request: CeremonyInitRequest): Promise<ApiResponse<CeremonyInitResponse>> {
    return this.client.post<CeremonyInitResponse>(this.buildUrl('/init'), request);
  }

  /** Report the ceremony state. */
  async status(): Promise<ApiResponse<CeremonyStatusResponse>> {
    return this.client.get<CeremonyStatusResponse>(this.buildUrl('/status'));
  }

  /** Request a claim-cert challenge for an officer. */
  async claimCertBegin(
    request: CeremonyClaimCertBeginRequest
  ): Promise<ApiResponse<CeremonyClaimCertBeginResponse>> {
    return this.client.post<CeremonyClaimCertBeginResponse>(this.buildUrl('/claim-cert/begin'), request);
  }

  /** Complete a claim-cert challenge and receive the officer certificate. */
  async claimCertComplete(
    request: CeremonyClaimCertCompleteRequest
  ): Promise<ApiResponse<CeremonyClaimCertCompleteResponse>> {
    return this.client.post<CeremonyClaimCertCompleteResponse>(this.buildUrl('/claim-cert/complete'), request);
  }

  /** Request a claim-share challenge for an officer. */
  async claimShareBegin(
    request: CeremonyClaimShareBeginRequest
  ): Promise<ApiResponse<CeremonyClaimShareBeginResponse>> {
    return this.client.post<CeremonyClaimShareBeginResponse>(this.buildUrl('/claim-share/begin'), request);
  }

  /** Complete a claim-share challenge and receive the officer's share. */
  async claimShareComplete(
    request: CeremonyClaimShareCompleteRequest
  ): Promise<ApiResponse<CeremonyClaimShareCompleteResponse>> {
    return this.client.post<CeremonyClaimShareCompleteResponse>(this.buildUrl('/claim-share/complete'), request);
  }

  /** Sign a CSR with the ceremony CA. */
  async signCSR(request: CeremonySignCSRRequest): Promise<ApiResponse<CeremonySignCSRResponse>> {
    return this.client.post<CeremonySignCSRResponse>(this.buildUrl('/sign-csr'), request);
  }
}
