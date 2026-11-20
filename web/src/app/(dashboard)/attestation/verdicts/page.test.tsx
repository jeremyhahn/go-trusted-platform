import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import DeviceVerdictsPage from "./page";

// useDeviceVerdicts is driven by hand so each test sets the exact state the
// page renders; poll is a spy so the "Poll again" button can be checked.
const poll = vi.fn();
const hook: {
  state: { verdicts: unknown[]; error?: string; loading: boolean };
} = { state: { verdicts: [], loading: false } };

vi.mock("@/hooks/use-device-verdicts", () => ({
  useDeviceVerdicts: () => ({ ...hook.state, poll }),
}));

function verdict(eventId: string, passed: boolean, cryptographic = false) {
  return {
    eventId,
    recordedAt: "2026-11-20T10:00:00Z",
    deviceId: `dev-${eventId}`,
    serial: `SN-${eventId}`,
    hostId: `host-${eventId}`,
    passed,
    cryptographic,
    reason: passed ? "" : `reason-${eventId}`,
  };
}

describe("DeviceVerdictsPage", () => {
  beforeEach(() => {
    hook.state = { verdicts: [], loading: false };
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("shows the loading state while the first poll runs", () => {
    hook.state = { verdicts: [], loading: true };
    render(<DeviceVerdictsPage />);

    expect(screen.getByText(/Polling verdicts/)).toBeTruthy();
    expect(screen.queryByText("No verdicts recorded yet.")).toBeNull();
    expect(screen.getByRole("button", { name: /Poll again/ }).hasAttribute("disabled")).toBe(true);
  });

  it("shows the error alert and no loading or empty state", () => {
    hook.state = { verdicts: [], loading: false, error: "feed down" };
    render(<DeviceVerdictsPage />);

    expect(screen.getByText("Verdict feed unavailable")).toBeTruthy();
    expect(screen.getByText("feed down")).toBeTruthy();
    expect(screen.queryByText(/Polling verdicts/)).toBeNull();
    expect(screen.queryByText("No verdicts recorded yet.")).toBeNull();
  });

  it("shows the empty state when no verdict is recorded", () => {
    render(<DeviceVerdictsPage />);

    expect(screen.getByText("No verdicts recorded yet.")).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("lists each verdict with its badge", () => {
    hook.state = {
      verdicts: [verdict("e1", true), verdict("e2", false), verdict("e3", false, true)],
      loading: false,
    };
    render(<DeviceVerdictsPage />);

    expect(screen.getByRole("table")).toBeTruthy();
    expect(screen.getByText("dev-e1")).toBeTruthy();
    expect(screen.getByText("SN-e2")).toBeTruthy();
    expect(screen.getByText("host-e3")).toBeTruthy();
    expect(screen.getByText("passed")).toBeTruthy();
    expect(screen.getByText("failed")).toBeTruthy();
    expect(screen.getByText("compromised")).toBeTruthy();
    expect(screen.getByText("reason-e3")).toBeTruthy();
    expect(screen.queryByText("No verdicts recorded yet.")).toBeNull();
  });

  it("polls again when Poll again is clicked", () => {
    hook.state = { verdicts: [verdict("e1", true)], loading: false };
    render(<DeviceVerdictsPage />);

    fireEvent.click(screen.getByRole("button", { name: /Poll again/ }));
    expect(poll).toHaveBeenCalledTimes(1);
  });
});
