import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { UseRegistryResult } from "@/hooks";

// #2063: the registry page's List tags and Delete controls follow
// GET /api/v1/capabilities through the Gated component (#2058): each is
// disabled when the server does not offer its OCI distribution route.

const LIST_OP = "GET /v2/{name:.+}/tags/list";
const DELETE_OP = "DELETE /v2/{name:.+}/manifests/{reference}";
const REASON = "The server does not offer this operation.";

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
        ? { enabled: false, reason: REASON }
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

function typeRepository() {
  fireEvent.change(screen.getByRole("textbox", { name: "Repository" }), {
    target: { value: "team/app" },
  });
}

describe("RegistryPage OCI capability gates", () => {
  it("disables List tags when the server does not offer the tags/list route", () => {
    disabledOps = [LIST_OP];
    render(<RegistryPage />);
    typeRepository();

    const button = screen.getByRole("button", { name: "List tags" });
    expect(button.getAttribute("data-capability-op")).toBe(LIST_OP);
    expect(button.getAttribute("data-capability-enabled")).toBe("false");
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(button.getAttribute("title")).toBe(REASON);
  });

  it("enables List tags when the server offers it", () => {
    render(<RegistryPage />);
    typeRepository();

    const button = screen.getByRole("button", { name: "List tags" });
    expect(button.getAttribute("data-capability-op")).toBe(LIST_OP);
    expect(button.getAttribute("data-capability-enabled")).toBe("true");
    expect((button as HTMLButtonElement).disabled).toBe(false);
  });

  it("disables Delete when the server does not offer the manifest delete route", () => {
    disabledOps = [DELETE_OP];
    render(<RegistryPage />);

    const button = screen.getByRole("button", { name: "Delete v1" });
    expect(button.getAttribute("data-capability-op")).toBe(DELETE_OP);
    expect(button.getAttribute("data-capability-enabled")).toBe("false");
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(button.getAttribute("title")).toBe(REASON);

    fireEvent.click(button);
    expect(screen.queryByRole("dialog", { name: "Delete manifest" })).toBeNull();
  });

  it("a read-only registry keeps Delete disabled even when the route is offered", () => {
    registry = {
      ...registry,
      status: { Health: 1, Version: "3.0.0", ReadOnly: true, Components: [] },
    };
    render(<RegistryPage />);

    const button = screen.getByRole("button", { name: "Delete v1" });
    expect(button.getAttribute("data-capability-op")).toBe(DELETE_OP);
    expect(button.getAttribute("data-capability-enabled")).toBe("true");
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(button.getAttribute("title")).toBe("Registry is read-only");
  });
});
