/**
 * Presentation of a device attestation report (#428).
 *
 * The collector serves a cached verdict WITH its age (`reporting.View`,
 * docs/attestation/api.md §5.3). The rules a console must keep are the
 * acceptance list on #226/#428: never show a verdict without its age; render
 * stale distinctly from fresh but still show it; render "never collected"
 * (a 404) distinctly from a failed verdict (a 200 with `verified: false`);
 * render a TOFU baseline distinctly from a signed one; show WHICH check
 * failed and whether it failed cryptographically or could not run. These
 * helpers hold that mapping in one place so the fleet table and the detail
 * page cannot drift.
 */

import { formatDistanceStrict } from 'date-fns';
import type { DeviceReport, DeviceReportState } from 'trusted-platform-sdk';

/** A badge the console can render: text plus a shadcn Badge variant. */
export interface VerdictBadge {
  label: string;
  variant: 'default' | 'secondary' | 'destructive' | 'outline';
  /** Longer explanation for a title attribute */
  title: string;
}

/** The age of the evidence as "5 minutes" / "2 hours", from `age_seconds`. */
export function reportAge(report: Pick<DeviceReport, 'age_seconds'>): string {
  const seconds = Math.max(0, Math.floor(report.age_seconds));
  const now = new Date(0);
  return formatDistanceStrict(new Date(-seconds * 1000), now);
}

/** "5 minutes old" or "5 minutes old (stale)" — the age always travels with the verdict. */
export function reportAgeLabel(report: Pick<DeviceReport, 'age_seconds' | 'fresh'>): string {
  const age = `${reportAge(report)} old`;
  return report.fresh ? age : `${age} (stale)`;
}

/**
 * The verdict badge for a report. Verified is green; a cryptographic failure
 * is red; a verdict that could not be reached (a check could not run) is a
 * neutral "Not verified", because absence of evidence is not evidence of
 * compromise (the quarantine rule the verifier itself applies).
 */
export function verdictBadge(report: Pick<DeviceReport, 'verified' | 'cryptographic_failure' | 'message'>): VerdictBadge {
  if (report.verified) {
    return { label: 'Verified', variant: 'default', title: 'Every check passed against the profile baseline' };
  }
  if (report.cryptographic_failure) {
    return {
      label: 'Failed',
      variant: 'destructive',
      title: report.message || 'A check ran and failed: the quote does not prove the expected state',
    };
  }
  return {
    label: 'Not verified',
    variant: 'secondary',
    title: report.message || 'A check could not run (no certificate, CA or baseline); denied but not quarantined',
  };
}

/** Fresh vs stale, rendered as a distinct badge beside the verdict. */
export function freshnessBadge(report: Pick<DeviceReport, 'fresh' | 'age_seconds'>): VerdictBadge {
  const age = reportAge(report);
  return report.fresh
    ? { label: `${age} old`, variant: 'outline', title: 'Evidence is within the collector TTL' }
    : { label: `stale · ${age} old`, variant: 'secondary', title: 'Evidence is past the collector TTL; it is old, not absent' };
}

/** The badge for a report route that returned no report at all. */
export function reportStateBadge(state: Exclude<DeviceReportState, { kind: 'report' }>): VerdictBadge {
  switch (state.kind) {
    case 'never-collected':
      return {
        label: 'Never collected',
        variant: 'outline',
        title: 'The collector has not reached this device yet: check it has a dialable address and admits this control plane',
      };
    case 'not-configured':
      return {
        label: 'Reporting not configured',
        variant: 'outline',
        title: 'The attestation reporting service is not configured on this node',
      };
    default:
      return { label: 'Unavailable', variant: 'secondary', title: state.message };
  }
}

/** One row of the per-check list. */
export interface CheckRow {
  key: 'ak_certificate_verified' | 'signature_valid' | 'nonce_valid' | 'pcrs_valid';
  label: string;
  passed: boolean;
  /** What a false value means for this check */
  hint: string;
}

/** The four checks, in the order the verifier runs them. */
export function checkRows(report: Pick<DeviceReport, 'ak_certificate_verified' | 'signature_valid' | 'nonce_valid' | 'pcrs_valid'>): CheckRow[] {
  return [
    {
      key: 'ak_certificate_verified',
      label: 'AK certificate',
      passed: report.ak_certificate_verified,
      hint: 'The enrolled attestation certificate chains to the platform CA and carries verifiedTPMRestricted (TCG DevID §8.2)',
    },
    { key: 'signature_valid', label: 'Quote signature', passed: report.signature_valid, hint: 'The certified key signed the quote' },
    { key: 'nonce_valid', label: 'Nonce', passed: report.nonce_valid, hint: "The quote's extraData is the collector's nonce" },
    { key: 'pcrs_valid', label: 'PCRs', passed: report.pcrs_valid, hint: 'Reported PCRs hash to the signed digest and equal the profile baseline' },
  ];
}

/** The baseline source as a badge: a TOFU pass is a weaker claim than a signed one and must not look the same. */
export function baselineSourceBadge(report: Pick<DeviceReport, 'pcr_baseline_source' | 'pcr_baseline_recorded_at'>): VerdictBadge | undefined {
  if (!report.pcr_baseline_source) return undefined;
  const recorded = report.pcr_baseline_recorded_at ? `recorded ${report.pcr_baseline_recorded_at}` : '';
  if (report.pcr_baseline_source === 'signed') {
    return { label: 'Signed baseline', variant: 'default', title: `Compared against a signed-manifest baseline ${recorded}`.trim() };
  }
  return {
    label: 'TOFU baseline',
    variant: 'outline',
    title: `Compared against a trust-on-first-use baseline ${recorded}; a weaker claim than a signed manifest`.trim(),
  };
}

/** Age of the baseline itself, or undefined when none was evaluated. */
export function baselineAge(report: Pick<DeviceReport, 'pcr_baseline_recorded_at'>, now: Date = new Date()): string | undefined {
  if (!report.pcr_baseline_recorded_at) return undefined;
  const recorded = new Date(report.pcr_baseline_recorded_at);
  if (!Number.isFinite(recorded.getTime())) return undefined;
  return formatDistanceStrict(recorded, now);
}
