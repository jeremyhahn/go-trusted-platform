/**
 * Presentation of a device profile's PCR baseline (#404).
 *
 * The verifier compares every quote against the baseline on the device's
 * profile (`pcr_baseline`: hex digests keyed by PCR index, a `source` of
 * `signed` or `tofu`, when it was recorded and, for a trust-on-first-use
 * baseline, which device seeded it). An operator deciding whether to trust a
 * green verdict needs to know which kind of baseline produced it and how old
 * it is, so the console shows those beside the profile rather than only the
 * verdict.
 */

import { formatDistanceStrict } from 'date-fns';
import { pcrBaselineIndices } from 'trusted-platform-sdk';
import type { PCRBaseline, PCRBaselineSource } from 'trusted-platform-sdk';

/** Operator-facing label for a baseline source. */
export const BASELINE_SOURCE_LABELS: Record<PCRBaselineSource, string> = {
  signed: 'Signed manifest',
  tofu: 'Trust on first use',
};

/** How the baseline was established, as a short label; the raw source when unknown. */
export function baselineSourceLabel(source: string): string {
  return Object.prototype.hasOwnProperty.call(BASELINE_SOURCE_LABELS, source)
    ? BASELINE_SOURCE_LABELS[source as PCRBaselineSource]
    : source;
}

/**
 * The age of a baseline as "3 days" / "2 hours"; an em dash when the recorded
 * time is missing or unparseable rather than a NaN the operator would read as
 * a value.
 */
export function baselineAge(recordedAt: string | undefined, now: Date = new Date()): string {
  if (!recordedAt) return '—';
  const recorded = new Date(recordedAt);
  if (!Number.isFinite(recorded.getTime())) return '—';
  return formatDistanceStrict(recorded, now);
}

/**
 * The covered registers as "PCR 0, 7, 14" or "no PCRs" for an empty set.
 */
export function baselineRegisters(baseline: Pick<PCRBaseline, 'values'>): string {
  const indices = pcrBaselineIndices(baseline);
  if (indices.length === 0) return 'no PCRs';
  return `PCR ${indices.join(', ')}`;
}
