/**
 * BMC Certificate Service
 *
 * The BMC enrollment ceremony, the factory-certificate restore ceremony and
 * the web-certificate replacement.
 * Wire contract: pkg/webservice/v1/bmc/enroll.go (`POST /api/v1/bmc/{profileID}/enroll`,
 * EnrollRequest / EnrollResponse), pkg/webservice/v1/bmc/cert_restore.go
 * (`POST /api/v1/bmc/{profileID}/cert/restore`, no request body, RestoreResponse)
 * and pkg/webservice/v1/bmc/handler.go ReplaceWebCertificate
 * (`PUT /api/v1/bmc/{profileID}/cert`, `cert_pem` / `key_pem`).
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

/** A replacement web certificate and its private key, both PEM. */
export interface BMCReplaceWebCertRequest {
  certPem: string;
  keyPem: string;
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
const UINT64_MAX_DECIMAL = '18446744073709551615';

/**
 * Validate a BMC profile ID as a decimal uint64 and return it encoded as a
 * URL path segment. The server routes only numeric profile IDs; refusing any
 * other text here keeps a value such as `42/../43` from being normalized by
 * the browser into a request on another BMC.
 *
 * A numeric ID must be a safe integer: past 2^53 a number has already lost
 * precision (9007199254740993 arrives as 9007199254740992), so it would name
 * another BMC. Pass a larger ID as a decimal string.
 *
 * @param profileId - The BMC profile ID
 * @returns The encoded path segment
 * @throws TypeError when the ID is not a decimal uint64, or is a number that
 *   is not a safe integer
 */
export function bmcProfileSegment(profileId: string | number): string {
  if (typeof profileId === 'number' && !Number.isSafeInteger(profileId)) {
    throw new TypeError(
      `invalid BMC profile ID: ${String(profileId)} is not a safe integer; pass a larger ID as a decimal string`
    );
  }
  const text = String(profileId);
  if (
    !/^(0|[1-9][0-9]{0,19})$/.test(text) ||
    (text.length === UINT64_MAX_DECIMAL.length && text > UINT64_MAX_DECIMAL)
  ) {
    throw new TypeError(`invalid BMC profile ID: ${JSON.stringify(text)}`);
  }
  return encodeURIComponent(text);
}

/**
 * Validate a BMC user slot as an integer 0..255 and return it as a URL path
 * segment.
 *
 * @param slot - The user slot
 * @returns The encoded path segment
 * @throws TypeError when the slot is not an integer 0..255
 */
export function bmcSlotSegment(slot: number): string {
  if (!Number.isInteger(slot) || slot < 0 || slot > 255) {
    throw new TypeError(`invalid BMC user slot: ${String(slot)}`);
  }
  return encodeURIComponent(String(slot));
}

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
    return this.client.post<BMCEnrollResult>(this.buildUrl(`/${bmcProfileSegment(profileId)}/enroll`), body);
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
    return this.client.post<BMCRestoreResult>(this.buildUrl(`/${bmcProfileSegment(profileId)}/cert/restore`));
  }

  /**
   * Replace the BMC's web certificate with a given certificate and key
   * (`PUT /api/v1/bmc/{profileID}/cert`, handler ReplaceWebCertificate in
   * pkg/webservice/v1/bmc/handler.go).
   *
   * The server answers 400 when either PEM is blank; the answer is returned
   * unchanged.
   *
   * @param profileId - The BMC profile ID
   * @param req - The certificate and private key PEM
   * @returns The server's status answer
   */
  async replaceWebCertificate(
    profileId: string | number,
    req: BMCReplaceWebCertRequest
  ): Promise<ApiResponse<{ status: string }>> {
    return this.client.put<{ status: string }>(this.buildUrl(`/${bmcProfileSegment(profileId)}/cert`), {
      cert_pem: req.certPem,
      key_pem: req.keyPem,
    });
  }
}
