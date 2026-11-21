import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { UseRegistryResult } from "@/hooks";

// #2063: the registry page inspects a tag through useRegistry().inspect
// (SDK RegistryService.inspect) and shows its detail in a panel.

let registry: UseRegistryResult;

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useRegistry: () => registry,
  useToast: () => ({ toast: vi.fn() }),
}));

import RegistryPage from "./page";

const DIGEST = "sha256:" + "a".repeat(64);

const detail = {
  Artifact: {
    Repository: "team/app",
    Tag: "v1",
    Digest: DIGEST,
    Size: 2048,
    Manifest: {
      MediaType: "application/vnd.oci.image.manifest.v1+json",
      Layers: [{ Digest: "sha256:" + "b".repeat(64), Size: 1024 }],
    },
  },
  Signatures: [{ Signer: "release-key" }],
  ScanResult: { CriticalCount: 1, HighCount: 2, MediumCount: 0, LowCount: 3 },
  Tags: ["v1", "latest"],
};

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

describe("RegistryPage inspect", () => {
  it("inspects a tag and shows its detail", async () => {
    vi.mocked(registry.inspect).mockResolvedValue(detail);
    render(<RegistryPage />);

    fireEvent.click(screen.getByRole("button", { name: "Inspect v1" }));

    const panel = await screen.findByTestId("registry-inspect-panel");
    expect(registry.inspect).toHaveBeenCalledWith("team/app", "v1");
    expect(panel.textContent).toContain("team/app:v1");
    expect(panel.textContent).toContain(DIGEST);
    expect(screen.getByTestId("registry-inspect-layers").textContent).toBe("1");
    expect(panel.textContent).toContain("v1, latest");
    expect(panel.textContent).toContain("release-key");
    expect(panel.textContent).toContain("Critical 1, High 2, Medium 0, Low 3");

    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByTestId("registry-inspect-panel")).toBeNull());
  });

  it("shows Not scanned and dashes for a sparse detail", async () => {
    vi.mocked(registry.inspect).mockResolvedValue({ Tags: ["v2"] });
    render(<RegistryPage />);

    fireEvent.click(screen.getByRole("button", { name: "Inspect v2" }));

    const panel = await screen.findByTestId("registry-inspect-panel");
    expect(panel.textContent).toContain("team/app:v2");
    expect(panel.textContent).toContain("Not scanned");
    expect(screen.getByTestId("registry-inspect-digest").textContent).toBe("-");
  });

  it("a refused inspect shows the server message", async () => {
    vi.mocked(registry.inspect).mockRejectedValue(new Error("HTTP 404: image not found"));
    render(<RegistryPage />);

    fireEvent.click(screen.getByRole("button", { name: "Inspect v1" }));

    const err = await screen.findByTestId("registry-inspect-error");
    expect(err.textContent).toContain("team/app:v1");
    expect(err.textContent).toContain("image not found");
    expect(screen.queryByTestId("registry-inspect-panel")).toBeNull();
  });

  it("the Delete button still opens its confirm", async () => {
    render(<RegistryPage />);

    fireEvent.click(screen.getByRole("button", { name: "Delete v1" }));

    expect(await screen.findByText(/Delete team\/app:v1\?/)).toBeTruthy();
    expect(registry.inspect).not.toHaveBeenCalled();
  });
});
