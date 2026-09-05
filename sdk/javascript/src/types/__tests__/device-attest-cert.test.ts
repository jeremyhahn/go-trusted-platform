/**
 * The enrolled attestation certificate and the profile PCR baseline on the
 * wire (#404).
 *
 * `attest_cert` is the only trust anchor the quote verifier accepts (#374):
 * the console must be able to see whether a device has one, so the SDK's
 * Device declares it under its wire name. The profile baseline reaches the
 * client read-only, hex digests keyed by PCR index as strings, and
 * `pcrBaselineIndices` turns that into the register list a console renders.
 */

import { describe, it, expect } from 'vitest';
import { pcrBaselineIndices } from '../device.js';
import type { Device, DeviceProfile, DeviceAttestResponse, PCRBaseline } from '../device.js';

const ATTEST_CERT = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';

/** A device exactly as `GET /api/v1/devices/{id}` emits it after enrollment. */
const WIRE_DEVICE = `{
  "id": "9007199254740993",
  "serial": "SN-404",
  "model": "X10SDV",
  "hash_algo_id": 11,
  "attest_pub": "0102",
  "attest_cert": ${JSON.stringify(ATTEST_CERT)},
  "created_at": "2026-09-01T12:00:00Z",
  "updated_at": "2026-09-01T12:00:00Z"
}`;

/** A profile after the verifier captured a trust-on-first-use baseline. */
const WIRE_PROFILE = `{
  "id": "7",
  "name": "workers",
  "role": "worker",
  "pcr_baseline": {
    "values": { "7": "aabb", "0": "0102", "14": "ff" },
    "source": "tofu",
    "recorded_at": "2026-09-01T12:00:00Z",
    "recorded_from_device_id": "9007199254740993"
  },
  "assigned": false,
  "created_at": "2026-09-01T12:00:00Z",
  "updated_at": "2026-09-01T12:00:00Z"
}`;

describe('Device.attest_cert', () => {
  it('is read under its wire name, beside attest_pub', () => {
    const device = JSON.parse(WIRE_DEVICE) as Device;
    expect(device.attest_cert).toBe(ATTEST_CERT);
    expect(device.attest_pub).toBe('0102');
  });

  it('is absent, not empty, for a device enrolled before certificates were recorded', () => {
    const device = JSON.parse('{"id": "1", "serial": "SN", "hash_algo_id": 11, "created_at": "", "updated_at": ""}') as Device;
    expect(device.attest_cert).toBeUndefined();
    expect(Boolean(device.attest_cert)).toBe(false);
  });
});

describe('DeviceProfile.pcr_baseline', () => {
  it('round-trips the read-only baseline with its source, age and seeding device', () => {
    const profile = JSON.parse(WIRE_PROFILE) as DeviceProfile;
    expect(profile.pcr_baseline?.source).toBe('tofu');
    expect(profile.pcr_baseline?.recorded_at).toBe('2026-09-01T12:00:00Z');
    expect(profile.pcr_baseline?.recorded_from_device_id).toBe('9007199254740993');
    expect(profile.pcr_baseline?.values['7']).toBe('aabb');
  });

  it('pcrBaselineIndices lists the covered registers in register order, not key order', () => {
    const profile = JSON.parse(WIRE_PROFILE) as DeviceProfile;
    expect(pcrBaselineIndices(profile.pcr_baseline as PCRBaseline)).toEqual([0, 7, 14]);
  });

  it('pcrBaselineIndices drops keys that are not PCR indices and tolerates no values', () => {
    expect(pcrBaselineIndices({ values: { '0': 'aa', 'x': 'bb', '-1': 'cc', '3.5': 'dd' } })).toEqual([0]);
    expect(pcrBaselineIndices({ values: undefined as unknown as Record<string, string> })).toEqual([]);
  });
});

describe('DeviceAttestResponse', () => {
  it('carries the certificate check and the baseline provenance beside the verdict', () => {
    const wire = `{
      "device_id": "1", "verified": false,
      "signature_valid": true, "nonce_valid": true, "pcrs_valid": true,
      "ak_certificate_verified": false,
      "pcr_baseline_source": "signed", "pcr_baseline_recorded_at": "2026-08-30T00:00:00Z",
      "pcr_baseline_captured": false,
      "attestation_status": "registered", "attested_at": "2026-09-01T12:00:00Z",
      "message": "no attestation certificate enrolled for device"
    }`;
    const result = JSON.parse(wire) as DeviceAttestResponse;
    expect(result.verified).toBe(false);
    expect(result.ak_certificate_verified).toBe(false);
    expect(result.pcr_baseline_source).toBe('signed');
    expect(result.pcr_baseline_recorded_at).toBe('2026-08-30T00:00:00Z');
  });
});
