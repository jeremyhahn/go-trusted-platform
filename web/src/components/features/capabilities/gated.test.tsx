import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import { Gated } from "./gated";

// #2058 / #2033 item 4: <Gated op> disables its child, never hides it.

function ok(payload: unknown): Response {
  return new Response(JSON.stringify({ code: 200, error: "", success: true, payload }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

const capabilities = {
  capabilities: [
    { op: "POST /api/v1/ntp/step", kind: "route", enabled: true },
    { op: "POST /api/v1/ntp/other", kind: "route", enabled: false, reason: "unimplemented" },
  ],
  total: 2,
  enabled: 1,
};

describe("Gated", () => {
  const fetchMock = vi.fn<typeof fetch>();

  function renderGated(op: string) {
    const client = new PlatformClient({
      baseUrl: "https://platform.test/api",
      fetch: fetchMock,
      retry: { maxRetries: 0 },
    });
    return render(
      <PlatformProvider client={client}>
        <Gated op={op}>
          <button type="button">Act</button>
        </Gated>
      </PlatformProvider>
    );
  }

  function button() {
    return screen.getByRole("button", { name: "Act" }) as HTMLButtonElement;
  }

  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockImplementation(() => Promise.resolve(ok(capabilities)));
  });

  afterEach(() => {
    cleanup();
  });

  it("an enabled op leaves the button enabled", async () => {
    renderGated("POST /api/v1/ntp/step");

    await waitFor(() => expect(button().getAttribute("data-capability-enabled")).toBe("true"));
    expect(button().disabled).toBe(false);
  });

  it("a disabled op disables the button and sets its title to the reason", async () => {
    renderGated("POST /api/v1/ntp/other");

    await waitFor(() => expect(button().title).toBe("unimplemented"));
    expect(button().disabled).toBe(true);
    expect(button().getAttribute("data-capability-enabled")).toBe("false");
  });

  it("the clone carries data-capability-op", async () => {
    renderGated("POST /api/v1/ntp/step");

    expect(button().getAttribute("data-capability-op")).toBe("POST /api/v1/ntp/step");
    await waitFor(() => expect(button().getAttribute("data-capability-enabled")).toBe("true"));
  });
});
