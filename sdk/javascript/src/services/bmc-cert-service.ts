/**
 * BMC Certificate Service
 *
 * The types and path helpers of the BMC certificate ceremonies. The service
 * offers none of them (#2199): `POST /api/v1/bmc/{profileID}/enroll` on a
 * profile cannot capture a trust pin (the profile config has no certificate,
 * so enrolment can succeed with an empty pin), `POST
 * /api/v1/bmc/{profileID}/cert/restore` verifies the regenerated certificate
 * against the old pin and leaves pin and TLSA stale, and `PUT
 * /api/v1/bmc/{profileID}/cert` rotates no pin or TLSA record.
 * Field names follow the Go encoding/json tags (snake_case).
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
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

/**
 * BMC Certificate Service, wired on the platform client as `client.bmcCert`.
 *
 * It offers no ceremony until the server carries the BMC trust pin across a
 * certificate change (#2199).
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
}
