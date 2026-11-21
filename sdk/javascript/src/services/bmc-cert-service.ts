/**
 * BMC Certificate Service
 *
 * The BMC enrollment ceremony and the factory-certificate restore ceremony.
 * Wire contract: pkg/webservice/v1/bmc/enroll.go (`POST /api/v1/bmc/{profileID}/enroll`,
 * EnrollRequest / EnrollResponse) and pkg/webservice/v1/bmc/cert_restore.go
 * (`POST /api/v1/bmc/{profileID}/cert/restore`, no request body, RestoreResponse).
 * Field names follow the Go encoding/json tags (snake_case).
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';

/** Enrollment options; an option left out keeps the BMC profile's default. */
export interface BMCEnrollOptions {
  replaceCertificate?: boolean;
  rotatePassword?: boolean;
  dnsRegister?: boolean;
  danePublish?: boolean;
}

/** Metadata of a BMC web certificate. */
export interface BMCCertMeta {
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  spki_sha256: string;
  sha256: string;
  captured_at: string;
}

/** One step of a ceremony and its outcome. */
export interface BMCCeremonyStep {
  name: string;
  ok: boolean;
  detail?: string;
}

/** The answer to an enrollment ceremony (EnrollResponse). */
export interface BMCEnrollResult {
  /** The uint64 device ID as a decimal string. */
  device_id: string;
  endpoint: string;
  hostname: string;
  dns_name?: string;
  pin_spki_sha256: string;
  factory_cert_pem?: string;
  factory_cert_meta: BMCCertMeta;
  new_cert_pem?: string;
  ca_cert_pem?: string;
  steps: BMCCeremonyStep[];
}

/** The answer to a factory-certificate restore ceremony (RestoreResponse). */
export interface BMCRestoreResult {
  /** The uint64 device ID as a decimal string. */
  device_id: string;
  endpoint: string;
  hostname: string;
  new_cert_meta: BMCCertMeta;
  new_cert_pem?: string;
  steps: BMCCeremonyStep[];
}

/**
 * BMC Certificate Service class
 *
 * @example
 * ```typescript
 * const bmcCert = new BMCCertService(apiClient);
 * const enrolled = await bmcCert.enrollBMC(7, { danePublish: true });
 * const restored = await bmcCert.restoreFactoryCert(7);
 * ```
 */
export class BMCCertService extends BaseService {
  /**
   * Creates a new BMC certificate service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/bmc');
  }

  /**
   * Run the enrollment ceremony on a BMC profile
   * (`POST /api/v1/bmc/{profileID}/enroll`, handler EnrollBMC in
   * pkg/webservice/v1/bmc/enroll.go).
   *
   * The handler always decodes a JSON body, so `{}` is sent when no option is
   * given. The server answers 503 when the daemon runs without the enroller
   * and 404 for an unknown profile; both answers are returned unchanged.
   *
   * @param profileId - The BMC profile ID
   * @param options - Enrollment options; those left out keep the profile defaults
   * @returns The enrollment result
   */
  async enrollBMC(
    profileId: string | number,
    options?: BMCEnrollOptions
  ): Promise<ApiResponse<BMCEnrollResult>> {
    const body: Record<string, boolean> = {};
    if (options?.replaceCertificate !== undefined) {
      body.replace_certificate = options.replaceCertificate;
    }
    if (options?.rotatePassword !== undefined) {
      body.rotate_password = options.rotatePassword;
    }
    if (options?.dnsRegister !== undefined) {
      body.dns_register = options.dnsRegister;
    }
    if (options?.danePublish !== undefined) {
      body.dane_publish = options.danePublish;
    }
    return this.client.post<BMCEnrollResult>(this.buildUrl(`/${profileId}/enroll`), body);
  }

  /**
   * Restore the BMC's factory web certificate
   * (`POST /api/v1/bmc/{profileID}/cert/restore`, handler RestoreBMC in
   * pkg/webservice/v1/bmc/cert_restore.go).
   *
   * The handler reads no request body, so none is sent. The server answers
   * 503 when the daemon runs without the restorer and 404 for an unknown
   * profile; both answers are returned unchanged.
   *
   * @param profileId - The BMC profile ID
   * @returns The restore result
   */
  async restoreFactoryCert(profileId: string | number): Promise<ApiResponse<BMCRestoreResult>> {
    return this.client.post<BMCRestoreResult>(this.buildUrl(`/${profileId}/cert/restore`));
  }
}
