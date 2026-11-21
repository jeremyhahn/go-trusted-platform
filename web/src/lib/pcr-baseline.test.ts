import { describe, expect, it } from "vitest";

import {
  BASELINE_SOURCE_LABELS,
  baselineAge,
  baselineRegisters,
  baselineSourceLabel,
} from "./pcr-baseline";

// #1795: the profile page shows which kind of PCR baseline produced a verdict,
// how old it is and which registers it covers. These pin that presentation,
// including the missing and malformed inputs a profile can carry.

const NOW = new Date("2026-11-12T12:00:00.000Z");

describe("baselineSourceLabel", () => {
  it("labels both known sources", () => {
    expect(BASELINE_SOURCE_LABELS).toEqual({
      signed: "Signed manifest",
      tofu: "Trust on first use",
    });
    expect(baselineSourceLabel("signed")).toBe("Signed manifest");
    expect(baselineSourceLabel("tofu")).toBe("Trust on first use");
  });

  it("shows an unknown source as given", () => {
    expect(baselineSourceLabel("manual")).toBe("manual");
    expect(baselineSourceLabel("Signed")).toBe("Signed");
    expect(baselineSourceLabel("")).toBe("");
  });

  it("does not read inherited object keys as labels", () => {
    expect(baselineSourceLabel("toString")).toBe("toString");
    expect(baselineSourceLabel("constructor")).toBe("constructor");
    expect(baselineSourceLabel("__proto__")).toBe("__proto__");
  });
});

describe("baselineAge", () => {
  it("shows the distance from the recorded time", () => {
    expect(baselineAge("2026-11-09T12:00:00.000Z", NOW)).toBe("3 days");
    expect(baselineAge("2026-11-12T10:00:00.000Z", NOW)).toBe("2 hours");
    expect(baselineAge("2026-11-12T11:59:30.000Z", NOW)).toBe("30 seconds");
  });

  it("shows an em dash for a missing time", () => {
    expect(baselineAge(undefined, NOW)).toBe("—");
    expect(baselineAge("", NOW)).toBe("—");
  });

  it("shows an em dash for an unparseable time", () => {
    expect(baselineAge("not a date", NOW)).toBe("—");
    expect(baselineAge("2026-13-45T99:00:00Z", NOW)).toBe("—");
  });

  it("measures against the current time by default", () => {
    expect(baselineAge(new Date().toISOString())).toBe("0 seconds");
  });
});

describe("baselineRegisters", () => {
  it("lists the covered registers in register order", () => {
    expect(baselineRegisters({ values: { "14": "aa", "0": "bb", "7": "cc" } })).toBe(
      "PCR 0, 7, 14",
    );
  });

  it("lists a single register", () => {
    expect(baselineRegisters({ values: { "23": "aa" } })).toBe("PCR 23");
  });

  it("shows no PCRs for an empty or missing set", () => {
    expect(baselineRegisters({ values: {} })).toBe("no PCRs");
    expect(
      baselineRegisters({ values: undefined } as unknown as Parameters<typeof baselineRegisters>[0]),
    ).toBe("no PCRs");
  });

  it("skips keys that are not register indices", () => {
    expect(baselineRegisters({ values: { sha256: "aa", "-1": "bb", "1.5": "cc", "2": "dd" } })).toBe(
      "PCR 2",
    );
    expect(baselineRegisters({ values: { bank: "aa" } })).toBe("no PCRs");
  });
});
