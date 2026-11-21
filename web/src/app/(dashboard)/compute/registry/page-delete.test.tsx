import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { UseRegistryResult } from "@/hooks";

// #2063: the registry page shows the registry status, deletes a tag through
// useRegistry().deleteManifest after a confirm, and offers no Delete on a
// read-only registry (the server refuses it).

let registry: UseRegistryResult;

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useRegistry: () => registry,
  useToast: () => ({ toast: vi.fn() }),
}));

import RegistryPage from "./page";

beforeEach(() => {
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

describe("RegistryPage delete and status", () => {
  it("shows the status card", () => {
    render(<RegistryPage />);

    const card = screen.getByTestId("registry-status");
    expect(card.textContent).toContain("Healthy");
    expect(card.textContent).toContain("3.0.0");
    expect(card.textContent).toContain("Read-write");
  });

  it("confirms and deletes a tag", async () => {
    vi.mocked(registry.deleteManifest).mockResolvedValue(undefined);
    render(<RegistryPage />);

    fireEvent.click(screen.getByRole("button", { name: "Delete v1" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/Delete team\/app:v1\?/)).toBeTruthy();

    fireEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(registry.deleteManifest).toHaveBeenCalledTimes(1));
    expect(registry.deleteManifest).toHaveBeenCalledWith("team/app", "v1");
  });

  it("Cancel leaves the tag", async () => {
    render(<RegistryPage />);

    fireEvent.click(screen.getByRole("button", { name: "Delete v2" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/Delete team\/app:v2\?/)).toBeTruthy();

    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(registry.deleteManifest).not.toHaveBeenCalled();
  });

  it("a read-only registry disables Delete", () => {
    registry.status = { Health: 1, Version: "3.0.0", ReadOnly: true, Components: [] };
    render(<RegistryPage />);

    for (const name of ["Delete v1", "Delete v2"]) {
      const button = screen.getByRole("button", { name });
      expect(button).toHaveProperty("disabled", true);
    }
    expect(screen.getByRole("button", { name: "Inspect v1" })).toHaveProperty("disabled", false);

    fireEvent.click(screen.getByRole("button", { name: "Delete v1" }));
    expect(screen.queryByText("Delete manifest", { selector: "h2" })).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(registry.deleteManifest).not.toHaveBeenCalled();
  });
});
