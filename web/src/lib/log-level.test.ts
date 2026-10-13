import { describe, expect, it } from "vitest";

import { LOG_LEVELS, toLogLevel } from "./log-level";

// #169: the admin claim's re-claim alert is a SECURITY-level record. The Logs
// page offered no SECURITY filter, and its row renderer crashed on a level it
// did not know. These pin the console to the levels the store writes.

describe("log levels", () => {
  it("lists every stored level, SECURITY highest", () => {
    expect(LOG_LEVELS).toEqual(["DEBUG", "INFO", "WARN", "ERROR", "FATAL", "SECURITY"]);
  });

  it("reads the stored levels case-insensitively", () => {
    expect(toLogLevel("SECURITY")).toBe("SECURITY");
    expect(toLogLevel("security")).toBe("SECURITY");
    expect(toLogLevel(" fatal ")).toBe("FATAL");
  });

  it("shows an slog offset level as its base level", () => {
    expect(toLogLevel("WARN+1")).toBe("WARN");
    expect(toLogLevel("DEBUG-4")).toBe("DEBUG");
  });

  it("shows an unreadable level as INFO instead of failing", () => {
    expect(toLogLevel(undefined)).toBe("INFO");
    expect(toLogLevel("")).toBe("INFO");
    expect(toLogLevel("NOTICE")).toBe("INFO");
  });
});
