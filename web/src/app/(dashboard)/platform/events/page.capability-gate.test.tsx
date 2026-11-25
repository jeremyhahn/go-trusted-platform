import * as React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2033 item 5: the platform events page builds its events from
// GET /api/v1/platform/health through usePlatform (network boundary, mocked
// here) only when the server offers it, and gates Retry, the stream toggle and
// Refresh on that op. Export is client-only and stays as it was.

const { platform, toast, capability, caps } = vi.hoisted(() => ({
  platform: { getHealth: vi.fn() },
  toast: vi.fn(),
  capability: vi.fn(),
  caps: { loading: false },
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  usePlatform: () => platform,
  useToast: () => ({ toast }),
}));

// #2033 item 5: Gated and the page read the server's capabilities through this hook.
vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({ loading: caps.loading, error: undefined, capability }),
}));

import PlatformEventsPage from "./page";

const HEALTH_OP = "GET /api/v1/platform/health";
const REASON = "blocked: integration";

function offExcept(off: string[]) {
  capability.mockImplementation((op: string) => (off.includes(op) ? { enabled: false, reason: REASON } : { enabled: true }));
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole("button", { name }) as HTMLButtonElement;
}

function expectWithheld(el: HTMLElement, op?: string) {
  expect((el as HTMLButtonElement).disabled).toBe(true);
  expect(el.getAttribute("title")).toBe(REASON);
  if (op) {
    expect(el.getAttribute("data-capability-op")).toBe(op);
    expect(el.getAttribute("data-capability-enabled")).toBe("false");
  }
}

beforeEach(() => {
  platform.getHealth.mockReset();
  platform.getHealth.mockResolvedValue({
    data: {
      health: {
        timestamp: "2026-11-01T00:00:00Z",
        services: [{ name: "ca-service", healthy: true, latencyMs: 2, lastCheck: "2026-11-01T00:00:00Z" }],
      },
    },
  });
  toast.mockReset();
  caps.loading = false;
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
});

afterEach(() => {
  cleanup();
});

describe("PlatformEventsPage capability gate", () => {
  it("shows the not-enabled card with the server's reason and does not read when GET /api/v1/platform/health is not offered", async () => {
    offExcept([HEALTH_OP]);
    render(<PlatformEventsPage />);

    const card = await screen.findByTestId("platform-events-not-enabled");
    expect(card.textContent).toContain(REASON);
    expect(platform.getHealth).not.toHaveBeenCalled();
    expect(screen.queryByText("Loading events...")).toBeNull();
    expectWithheld(button("Start Stream"), HEALTH_OP);
    expectWithheld(button("Refresh"), HEALTH_OP);
    expect(button("Export").getAttribute("data-capability-op")).toBeNull();
  });

  it("shows the loading state and does not read while the capabilities load", async () => {
    caps.loading = true;
    offExcept([HEALTH_OP]);
    render(<PlatformEventsPage />);

    expect(await screen.findByText("Loading events...")).toBeTruthy();
    expect(screen.queryByTestId("platform-events-not-enabled")).toBeNull();
    expect(screen.queryByText("No events found")).toBeNull();
    expect(platform.getHealth).not.toHaveBeenCalled();
  });

  it("renders the events and leaves the stream toggle and Refresh enabled when the server offers the read", async () => {
    render(<PlatformEventsPage />);

    expect((await screen.findAllByText(/Service Healthy: ca-service/)).length).toBeGreaterThan(0);
    expect(capability).toHaveBeenCalledWith(HEALTH_OP);
    expect(platform.getHealth).toHaveBeenCalled();
    expect(screen.queryByTestId("platform-events-not-enabled")).toBeNull();
    for (const name of ["Start Stream", "Refresh"]) {
      const el = button(name);
      expect(el.disabled).toBe(false);
      expect(el.getAttribute("data-capability-enabled")).toBe("true");
    }
  });
});
