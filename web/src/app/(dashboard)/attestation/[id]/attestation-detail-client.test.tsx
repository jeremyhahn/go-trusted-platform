import { Suspense } from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import AttestationDetailPage from "./attestation-detail-client";

// #2038: the manifest detail page showed a manifest but could not delete it,
// although the SDK has attestation.deleteManifest (DELETE /manifests/{id}).

const { service, push } = vi.hoisted(() => ({
  service: {
    getManifest: vi.fn(),
    deleteManifest: vi.fn(),
  },
  push: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push }),
  usePathname: () => "/attestation/m-1",
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useAttestation: () => service,
  useToast: () => ({ toast: vi.fn() }),
}));

const manifest = {
  success: true,
  data: {
    manifest: { id: "m-1", hostId: "lab-node-1", timestamp: "2026-08-31T00:00:00Z" },
  },
};

async function renderPage() {
  await act(async () => {
    render(
      <Suspense fallback={null}>
        <AttestationDetailPage params={Promise.resolve({ id: "m-1" })} />
      </Suspense>
    );
  });
  return screen.findByRole("button", { name: /delete manifest/i });
}

describe("AttestationDetailPage delete", () => {
  beforeEach(() => {
    service.getManifest.mockResolvedValue(manifest);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.clearAllMocks();
  });

  it("shows a Delete manifest button", async () => {
    expect(await renderPage()).toBeTruthy();
  });

  it("deletes the manifest through the SDK after a confirm and returns to the list", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    service.deleteManifest.mockResolvedValue({ success: true, data: { status: "SUCCESS" } });
    const button = await renderPage();

    await act(async () => {
      fireEvent.click(button);
    });

    await vi.waitFor(() => expect(push).toHaveBeenCalledWith("/attestation"));
    expect(service.deleteManifest).toHaveBeenCalledTimes(1);
    expect(service.deleteManifest).toHaveBeenCalledWith("m-1");
  });

  it("does not delete when the confirm is declined", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    const button = await renderPage();

    await act(async () => {
      fireEvent.click(button);
    });

    expect(service.deleteManifest).not.toHaveBeenCalled();
  });
});
