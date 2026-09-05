/**
 * Device reports on the wire and the response-shape gate (#428).
 *
 * The server answers one shape on every transport (docs/attestation/api.md
 * §5.3) and three non-report outcomes a console must keep apart: 404 never
 * collected, 503 not configured, anything else an error. `classifyDeviceReport`
 * is where that branch lives, so these pin it against the envelopes the
 * platform actually emits rather than what a page assumes.
 */

import { describe, it, expect } from 'vitest';
import { classifyDeviceReport } from '../attestation.js';
import type { DeviceReport } from '../attestation.js';

/** A stale TOFU pass exactly as the fleet route emits it. */
const WIRE_REPORT = `{
  "device_id": "9007199254740993",
  "serial": "SN-428",
  "model": "X10SDV",
  "verified": true,
  "ak_certificate_verified": true,
  "signature_valid": true,
  "nonce_valid": true,
  "pcrs_valid": true,
  "cryptographic_failure": false,
  "pcr_baseline_source": "tofu",
  "pcr_baseline_recorded_at": "2026-08-30T00:00:00Z",
  "pcr_baseline_captured": false,
  "status": "attested",
  "attested_at": "2026-09-05T10:00:00Z",
  "collected_at": "2026-09-05T10:00:01Z",
  "fresh": false,
  "age_seconds": 5400,
  "as_of": "2026-09-05T11:30:01Z"
}`;

describe('DeviceReport wire shape', () => {
  it('carries the verdict, every check, the baseline provenance and the age together', () => {
    const report = JSON.parse(WIRE_REPORT) as DeviceReport;
    expect(report.verified).toBe(true);
    expect(report.fresh).toBe(false);
    expect(report.age_seconds).toBe(5400);
    expect(report.pcr_baseline_source).toBe('tofu');
    expect(report.cryptographic_failure).toBe(false);
    expect(report.device_id).toBe('9007199254740993');
  });
});

describe('classifyDeviceReport', () => {
  it('returns the report on a 200', () => {
    const report = JSON.parse(WIRE_REPORT) as DeviceReport;
    const state = classifyDeviceReport({ success: true, data: report });
    expect(state.kind).toBe('report');
    if (state.kind === 'report') {
      expect(state.report.age_seconds).toBe(5400);
    }
  });

  it('keeps a failed verdict as a report — a 200 with verified:false is evidence, not absence', () => {
    const failed = { ...(JSON.parse(WIRE_REPORT) as DeviceReport), verified: false, pcrs_valid: false, cryptographic_failure: true };
    const state = classifyDeviceReport({ success: true, data: failed });
    expect(state).toEqual({ kind: 'report', report: failed });
  });

  it('maps a 404 to never-collected, distinct from a failed verdict', () => {
    expect(
      classifyDeviceReport({ success: false, error: { status: 404, message: 'attestation: no report has been collected for device 7' } })
    ).toEqual({ kind: 'never-collected' });
  });

  it('maps a 503 to not-configured', () => {
    expect(
      classifyDeviceReport({ success: false, error: { status: 503, message: 'attestation: the reporting service is not configured on this node' } })
    ).toEqual({ kind: 'not-configured' });
  });

  it('reports every other failure as an error with its status and message', () => {
    expect(classifyDeviceReport({ success: false, error: { status: 403, message: 'forbidden' } })).toEqual({
      kind: 'error', status: 403, message: 'forbidden',
    });
    expect(classifyDeviceReport({ success: false })).toEqual({
      kind: 'error', status: undefined, message: 'attestation report unavailable',
    });
  });

  it('does not mistake a success without a report body for a report', () => {
    const state = classifyDeviceReport({ success: true, data: {} as DeviceReport });
    expect(state.kind).toBe('error');
  });
});
