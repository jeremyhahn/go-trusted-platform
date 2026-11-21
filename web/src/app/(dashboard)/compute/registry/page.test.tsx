import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { RegistryTags, UseRegistryResult } from "@/hooks";
import RegistryPage from "./page";

// #1665: unit tests for the container registry dashboard page. The page reads
// the registry status and a repository's tags through useRegistry, the hook
// that carries the network calls, and deletes a manifest by tag after a
// confirmation dialog. These tests stub that hook.

const toast = vi.fn();
let registry: UseRegistryResult;

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useRegistry: () => registry,
  useToast: () => ({ toast }),
}));

function base(over: Partial<UseRegistryResult> = {}): UseRegistryResult {
  return {
    status: { Health: 1, Version: "3.0.0", ReadOnly: false, Components: [{ Name: "storage" }, { Name: "db" }] },
    statusError: null,
    isStatusLoading: false,
    refetchStatus: vi.fn().mockResolvedValue(undefined),
    tags: null,
    tagsError: null,
    isTagsLoading: false,
    listTags: vi.fn().mockResolvedValue(undefined),
    deleteManifest: vi.fn().mockResolvedValue(undefined),
    ...over,
  };
}

const appTags: RegistryTags = { name: "team/app", tags: ["v1", "latest"] };

function statusCard(): HTMLElement {
  return screen.getByTestId("registry-status");
}

function listButton(): HTMLButtonElement {
  return screen.getByText("List tags").closest("button") as HTMLButtonElement;
}

describe("RegistryPage", () => {
  beforeEach(() => {
    registry = base();
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("shows the health, version, mode and component count", () => {
    render(<RegistryPage />);

    const card = statusCard();
    expect(card.textContent).toContain("Healthy");
    expect(card.textContent).toContain("3.0.0");
    expect(card.textContent).toContain("Read-write");
    expect(card.textContent).toMatch(/Components\s*2/);
  });

  it.each([
    [0, "Unknown"],
    [2, "Degraded"],
    [3, "Unhealthy"],
  ] as const)("labels health code %i as %s", (health, label) => {
    registry = base({ status: { Health: health } });
    render(<RegistryPage />);

    expect(statusCard().textContent).toContain(label);
  });

  it("falls back for an unknown health code, a missing version and no components", () => {
    registry = base({
      status: { Health: 7 as unknown as 0, ReadOnly: true, Components: null },
    });
    render(<RegistryPage />);

    const card = statusCard();
    expect(card.textContent).toContain("Unknown");
    expect(card.textContent).toContain("—");
    expect(card.textContent).toContain("Read-only");
    expect(card.textContent).toMatch(/Components\s*0/);
  });

  it("shows a spinner and disables Refresh while the status loads", () => {
    registry = base({ status: null, isStatusLoading: true });
    render(<RegistryPage />);

    expect(statusCard().querySelector(".animate-spin")).not.toBeNull();
    expect(statusCard().textContent).not.toContain("Health");
    expect((screen.getByText("Refresh").closest("button") as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows the status error", () => {
    registry = base({ status: null, statusError: "HTTP 502: bad gateway" });
    render(<RegistryPage />);

    expect(screen.getByText("Failed to load status: HTTP 502: bad gateway")).toBeTruthy();
  });

  it("renders an empty status card when there is no status and no error", () => {
    registry = base({ status: null });
    render(<RegistryPage />);

    expect(statusCard().querySelector("dl")).toBeNull();
    expect(statusCard().textContent).toBe("Status");
  });

  it("refetches the status from Refresh", () => {
    render(<RegistryPage />);

    fireEvent.click(screen.getByText("Refresh"));
    expect(registry.refetchStatus).toHaveBeenCalledTimes(1);
  });

  it("lists the tags of the trimmed repository name", () => {
    render(<RegistryPage />);

    expect(listButton().disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "  team/app " } });
    expect(listButton().disabled).toBe(false);
    fireEvent.click(listButton());

    expect(registry.listTags).toHaveBeenCalledWith("team/app");
  });

  it("does not list tags for a blank repository name", () => {
    render(<RegistryPage />);

    fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "   " } });
    expect(listButton().disabled).toBe(true);
    fireEvent.submit(listButton().closest("form") as HTMLFormElement);

    expect(registry.listTags).not.toHaveBeenCalled();
  });

  it("shows a spinner and disables List tags while the tags load", () => {
    registry = base({ isTagsLoading: true });
    const { container } = render(<RegistryPage />);

    fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "team/app" } });
    expect(listButton().disabled).toBe(true);
    expect(container.querySelectorAll(".animate-spin")).toHaveLength(1);
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("shows the tag listing error", () => {
    registry = base({ tagsError: "HTTP 404: repository unknown" });
    render(<RegistryPage />);

    expect(screen.getByText("Failed to list tags: HTTP 404: repository unknown")).toBeTruthy();
  });

  it("says a repository has no tags", () => {
    registry = base({ tags: { name: "team/empty", tags: [] } });
    render(<RegistryPage />);

    expect(screen.getByText("team/empty has no tags.")).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("shows nothing in the tags card before the first listing", () => {
    render(<RegistryPage />);

    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.queryByText(/has no tags/)).toBeNull();
  });

  it("lists one row per tag", () => {
    registry = base({ tags: appTags });
    render(<RegistryPage />);

    const rows = screen.getAllByRole("row").slice(1);
    expect(rows.map((r) => r.textContent)).toEqual(["team/appv1", "team/applatest"]);
  });

  it("deletes a manifest after confirmation and reports it", async () => {
    registry = base({ tags: appTags });
    render(<RegistryPage />);

    fireEvent.click(screen.getByLabelText("Delete latest"));
    expect(await screen.findByText("Delete team/app:latest? This cannot be undone.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Manifest deleted", description: "team/app:latest" }),
    );
    expect(registry.deleteManifest).toHaveBeenCalledWith("team/app", "latest");
    await waitFor(() => expect(screen.queryByText("Delete manifest", { selector: "h2" })).toBeNull());
  });

  it("does not delete when the operator cancels", async () => {
    registry = base({ tags: appTags });
    render(<RegistryPage />);

    fireEvent.click(screen.getByLabelText("Delete v1"));
    await screen.findByText("Delete team/app:v1? This cannot be undone.");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    await waitFor(() => expect(screen.queryByText(/This cannot be undone/)).toBeNull());
    expect(registry.deleteManifest).not.toHaveBeenCalled();
  });

  it("reports a failed delete as a destructive toast", async () => {
    registry = base({
      tags: appTags,
      deleteManifest: vi.fn().mockRejectedValue(new Error("HTTP 405: deletes disabled")),
    });
    render(<RegistryPage />);

    fireEvent.click(screen.getByLabelText("Delete v1"));
    await screen.findByText(/This cannot be undone/);
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Delete failed",
        description: "HTTP 405: deletes disabled",
        variant: "destructive",
      }),
    );
    await waitFor(() => expect(screen.queryByText(/This cannot be undone/)).toBeNull());
  });

  it("reports a non-Error rejection as its string", async () => {
    registry = base({ tags: appTags, deleteManifest: vi.fn().mockRejectedValue("refused") });
    render(<RegistryPage />);

    fireEvent.click(screen.getByLabelText("Delete v1"));
    await screen.findByText(/This cannot be undone/);
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Delete failed", description: "refused" })),
    );
  });
});
