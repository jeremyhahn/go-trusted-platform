import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { UseRegistryResult } from "@/hooks";

// #2063: the registry page's Inspect control follows GET /api/v1/capabilities
// through the Gated component (#2058): disabled when the server does not
// offer the inspect route, enabled when it does.

const INSPECT_OP = "GET /api/v1/compute/images/{repository:.+}";

let registry: UseRegistryResult;
let disabledOps: string[] = [];

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useRegistry: () => registry,
  useToast: () => ({ toast: vi.fn() }),
}));

vi.mock("@/hooks/use-capabilities", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks/use-capabilities")>()),
  useCapabilities: () => ({
    loading: false,
    error: null,
    capability: (op: string) =>
      disabledOps.includes(op)
        ? { enabled: false, reason: "The server does not offer this operation." }
        : { enabled: true },
  }),
}));

import RegistryPage from "./page";

beforeEach(() => {
  disabledOps = [];
  registry = {
    status: { Health: 1, Version: "3.0.0", ReadOnly: false, Components: [] },
    statusError: null,
    isStatusLoading: false,
    refetchStatus: vi.fn(),
    tags: { name: "team/app", tags: ["v1", "v2"] },
    tagsError: null,
    isTagsLoading: false,
    listTags: vi.fn(),
    deleteManifest: vi.fn(),
    inspect: vi.fn(),
  };
});

afterEach(() => {
  cleanup();
});

describe("RegistryPage capability gate", () => {
  it("disables Inspect when the server does not offer GET /api/v1/compute/images/{repository:.+}", () => {
    disabledOps = [INSPECT_OP];
    render(<RegistryPage />);

    const button = screen.getByRole("button", { name: "Inspect v1" });
    expect(button.getAttribute("data-capability-op")).toBe(INSPECT_OP);
    expect(button.getAttribute("data-capability-enabled")).toBe("false");
    expect((button as HTMLButtonElement).disabled).toBe(true);
  });

  it("enables Inspect when the server offers it", () => {
    render(<RegistryPage />);

    const button = screen.getByRole("button", { name: "Inspect v1" });
    expect(button.getAttribute("data-capability-op")).toBe(INSPECT_OP);
    expect(button.getAttribute("data-capability-enabled")).toBe("true");
    expect((button as HTMLButtonElement).disabled).toBe(false);
  });
});
