import { describe, expect, it } from "vitest";

import {
  fleetAttestationProblems,
  fleetReportsState,
  summarizeReports,
  type FleetVerdictSummary,
} from "./attestation-report";

// #643: the Attestation page counted manifests (documents) and called every
// one without a host section "pending", so a fleet the verifier had never
// verdicted read as a clean dashboard. The summary now counts the verifier's
// own verdicts, and the states nobody is acting on are problems.

const verifiedFresh = { verified: true, cryptographic_failure: false, fresh: true };
const failedFresh = { verified: false, cryptographic_failure: true, fresh: true };
const notVerifiedStale = { verified: false, cryptographic_failure: false, fresh: false };
const verifiedStale = { verified: true, cryptographic_failure: false, fresh: false };

const allClear: FleetVerdictSummary = { total: 2, verified: 2, failed: 0, notVerified: 0, stale: 0 };

describe("summarizeReports", () => {
  it("counts verdicts the way the verdict badge labels them", () => {
    expect(summarizeReports([verifiedFresh, failedFresh, notVerifiedStale, verifiedStale])).toEqual({
      total: 4,
      verified: 2,
      failed: 1,
      notVerified: 1,
      stale: 2,
    });
  });

  it("returns zeros for a fleet with no reports", () => {
    expect(summarizeReports([])).toEqual({ total: 0, verified: 0, failed: 0, notVerified: 0, stale: 0 });
  });
});

describe("fleetReportsState", () => {
  it("is ready once the read succeeded", () => {
    expect(fleetReportsState(false, null)).toBe("ready");
    expect(fleetReportsState(true, null)).toBe("loading");
  });

  it("names a 503 not-configured and any other failure an error", () => {
    expect(fleetReportsState(false, { status: 503 })).toBe("not-configured");
    expect(fleetReportsState(false, { status: 403 })).toBe("error");
    expect(fleetReportsState(false, {})).toBe("error");
  });
});

describe("fleetAttestationProblems", () => {
  it("reports nothing when every device is verified on fresh evidence", () => {
    expect(fleetAttestationProblems(allClear, "ready")).toEqual([]);
  });

  it("treats no verdicts at all as a problem, not an idle fleet", () => {
    const empty = summarizeReports([]);
    expect(fleetAttestationProblems(empty, "ready")).toEqual([
      "No device has an attestation verdict: the collector has not reported on any device.",
    ]);
  });

  it("names stale, unverdicted and failed devices", () => {
    const summary = summarizeReports([verifiedFresh, failedFresh, notVerifiedStale, verifiedStale]);
    expect(fleetAttestationProblems(summary, "ready")).toEqual([
      "1 device failed attestation: a check ran and failed.",
      "1 device reached no verdict: a check could not run (no AK certificate, CA or PCR baseline).",
      "2 devices past the collector TTL: the collector has not re-attested on schedule.",
    ]);
  });

  it("reports a missing reporting service and stays quiet while loading or on a read error", () => {
    expect(fleetAttestationProblems(allClear, "not-configured")).toEqual([
      "Attestation reporting is not configured on this node: no device is being verified.",
    ]);
    expect(fleetAttestationProblems(allClear, "loading")).toEqual([]);
    expect(fleetAttestationProblems(allClear, "error")).toEqual([]);
  });
});
