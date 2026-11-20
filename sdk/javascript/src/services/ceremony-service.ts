/**
 * Ceremony Service
 *
 * The daemon's key ceremony (CeremonyService): initialise the ceremony,
 * read its status, let officers claim their certificate and secret share,
 * and sign an officer CSR. Routes: `/api/v1/ceremony/*` on the daemon REST
 * listener (pkg/api/daemon/ceremony_rest.go); field names are its wire names.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';

/** Body of POST /ceremony/init */
export interface CeremonyInitRequest {
  so_pin?: string;
  user_pin?: string;
  /** Shamir threshold, for example `2-of-3` */
  threshold?: string;
  hostname?: string;
  sans?: string[];
  credential_seal_strategy?: string;
}

/** Answer of POST /ceremony/init */
export interface CeremonyInitResponse {
  ceremony_id: string;
  state: string;
  admin_cert_pem: string;
  admin_key_pem: string;
  spki_pin: string;
  initialized_at?: string;
}

/** Answer of GET /ceremony/status */
export interface CeremonyStatus {
  ceremony_id: string;
  state: string;
  threshold: string;
  officers_enrolled: number;
  officers_required: number;
  initialized_at?: string;
}

/** Body of POST /ceremony/claim-cert/begin */
export interface CeremonyClaimCertBeginRequest {
  username: string;
  authenticator_type?: string;
  slot?: string;
  credential_id?: string;
}

/** Answer of POST /ceremony/claim-cert/begin */
export interface CeremonyClaimCertBeginResponse {
  nonce: string;
  challenge_id: string;
  expires_at?: string;
}

/** Body of POST /ceremony/claim-cert/complete */
export interface CeremonyClaimCertCompleteRequest {
  username: string;
  nonce: string;
  signature: string;
}

/** A certificate the ceremony issued, with its chain */
export interface CeremonyCertificateResponse {
  certificate_pem: string;
  chain_pem: string;
}

/** Body of POST /ceremony/claim-share/begin */
export interface CeremonyClaimShareBeginRequest {
  username: string;
}

/** Answer of POST /ceremony/claim-share/begin */
export interface CeremonyClaimShareBeginResponse {
  nonce: string;
  expires_at?: string;
}

/** Body of POST /ceremony/claim-share/complete */
export interface CeremonyClaimShareCompleteRequest {
  username: string;
  nonce: string;
  /** Base64 of the signature bytes (Go []byte wire form) */
  signature: string;
}

/** Answer of POST /ceremony/claim-share/complete */
export interface CeremonyClaimShareCompleteResponse {
  share: string;
  index: number;
}

/** Body of POST /ceremony/sign-csr */
export interface CeremonySignCSRRequest {
  username: string;
  so_pin: string;
  csr_pem: string;
  role: string;
}

/**
 * Service for the daemon's key ceremony
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

  /** Initialise the ceremony (CeremonyService.Init) */
  async init(request: CeremonyInitRequest): Promise<ApiResponse<CeremonyInitResponse>> {
    return this.client.post<CeremonyInitResponse>(this.buildUrl('/init'), request);
  }

  /** Read the ceremony status (CeremonyService.Status) */
  async getStatus(): Promise<ApiResponse<CeremonyStatus>> {
    return this.client.get<CeremonyStatus>(this.buildUrl('/status'));
  }

  /** Start an officer's certificate claim (CeremonyService.ClaimCertBegin) */
  async claimCertBegin(
    request: CeremonyClaimCertBeginRequest
  ): Promise<ApiResponse<CeremonyClaimCertBeginResponse>> {
    return this.client.post<CeremonyClaimCertBeginResponse>(this.buildUrl('/claim-cert/begin'), request);
  }

  /** Finish an officer's certificate claim (CeremonyService.ClaimCertComplete) */
  async claimCertComplete(
    request: CeremonyClaimCertCompleteRequest
  ): Promise<ApiResponse<CeremonyCertificateResponse>> {
    return this.client.post<CeremonyCertificateResponse>(this.buildUrl('/claim-cert/complete'), request);
  }

  /** Start an officer's share claim (CeremonyService.ClaimShareBegin) */
  async claimShareBegin(
    request: CeremonyClaimShareBeginRequest
  ): Promise<ApiResponse<CeremonyClaimShareBeginResponse>> {
    return this.client.post<CeremonyClaimShareBeginResponse>(this.buildUrl('/claim-share/begin'), request);
  }

  /** Finish an officer's share claim (CeremonyService.ClaimShareComplete) */
  async claimShareComplete(
    request: CeremonyClaimShareCompleteRequest
  ): Promise<ApiResponse<CeremonyClaimShareCompleteResponse>> {
    return this.client.post<CeremonyClaimShareCompleteResponse>(this.buildUrl('/claim-share/complete'), request);
  }

  /** Sign an officer CSR (CeremonyService.SignCSR) */
  async signCSR(request: CeremonySignCSRRequest): Promise<ApiResponse<CeremonyCertificateResponse>> {
    return this.client.post<CeremonyCertificateResponse>(this.buildUrl('/sign-csr'), request);
  }
}
