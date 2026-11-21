import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { UseRegistryResult } from "@/hooks";

// #2063: the registry page Status card lists each registry component with its
// health and message, and the time of the status report.

let registry: UseRegistryResult;

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useRegistry: () => registry,
  useToast: () => ({ toast: vi.fn() }),
}));

import RegistryPage from "./page";

beforeEach(() => {
  registry = {
    status: {
      Health: 2,
      Version: "3.0.0",
      ReadOnly: false,
      Components: [
        { Name: "storage", Status: 1, Message: "ok" },
        { Name: "scanner", Status: 3, Message: "unreachable" },
      ],
    },
    statusError: null,
    isStatusLoading: false,
    refetchStatus: vi.fn(),
    tags: { name: "team/app", tags: ["v1"] },
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

describe("RegistryPage status components", () => {
  it("lists each component with its health label and message", () => {
    render(<RegistryPage />);
    const card = screen.getByTestId("registry-status");
    const list = within(card).getByTestId("registry-components");
    const items = within(list).getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(items[0].textContent).toContain("storage");
    expect(items[0].textContent).toContain("Healthy");
    expect(items[0].textContent).toContain("ok");
    expect(items[1].textContent).toContain("scanner");
    expect(items[1].textContent).toContain("Unhealthy");
    expect(items[1].textContent).toContain("unreachable");
  });

  it("shows a dash for a missing component field", () => {
    registry.status = {
      Health: 1,
      Components: [{ Name: "cache", Status: 1 }],
    };
    render(<RegistryPage />);
    const list = screen.getByTestId("registry-components");
    const item = within(list).getByRole("listitem");
    expect(item.textContent).toContain("cache");
    expect(item.textContent).toContain("-");
  });

  it.each([[[]], [null]])("shows No components reported for %j", (components) => {
    registry.status = { Health: 1, Components: components };
    render(<RegistryPage />);
    const list = screen.getByTestId("registry-components");
    expect(list.textContent).toContain("No components reported");
    expect(within(list).queryAllByRole("listitem")).toHaveLength(0);
  });

  it("shows the Last updated row with the status timestamp", () => {
    registry.status = {
      Health: 1,
      Components: [],
      Timestamp: "2026-11-20T10:00:00Z",
    };
    render(<RegistryPage />);
    const card = screen.getByTestId("registry-status");
    const label = within(card).getByText("Last updated");
    expect(label.nextElementSibling?.textContent).toContain("2026-11-20T10:00:00Z");
  });
});
