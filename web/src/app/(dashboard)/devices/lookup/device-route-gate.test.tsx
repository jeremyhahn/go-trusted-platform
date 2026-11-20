import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { DeviceRouteGate, deviceRouteReason, type DeviceGatedOperation } from "./device-route-gate";

// #2048: device operations an operator session cannot perform render as a
// disabled control with the reason, never as a live call.

const operations: DeviceGatedOperation[] = ["AttestDevice"];

describe("DeviceRouteGate", () => {
  afterEach(() => {
    cleanup();
  });

  it.each(operations)("renders %s disabled with its reason", (operation) => {
    render(<DeviceRouteGate operation={operation}>Run {operation}</DeviceRouteGate>);

    const button = screen.getByRole("button", { name: `Run ${operation}` });
    expect(button).toHaveProperty("disabled", true);
    const reasonId = button.getAttribute("aria-describedby");
    expect(reasonId).toBeTruthy();
    expect(document.getElementById(String(reasonId))?.textContent).toBe(deviceRouteReason(operation));
    fireEvent.click(button);
  });

  it("gives every operation a reason that names why", () => {
    expect(deviceRouteReason("AttestDevice")).toMatch(/replay/i);
    expect(deviceRouteReason("AttestDevice")).toMatch(/#2134/);
  });
});
