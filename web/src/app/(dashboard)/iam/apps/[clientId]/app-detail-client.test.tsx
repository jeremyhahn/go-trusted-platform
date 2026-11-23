import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import AppDetailClient from "./app-detail-client";

// #2024 Codex: the embedded IAM backend has no App.Update handler, so the
// app edit control is gated off with the reason shown and never reaches the
// SDK. The read-only view stays.

const iam = vi.hoisted(() => ({
  getApp: vi.fn(),
  updateApp: vi.fn(),
  deleteApp: vi.fn(),
}));

const caps = vi.hoisted(() => ({ capability: vi.fn() }));

vi.mock("next/navigation", () => ({
  useParams: () => ({ clientId: "c1" }),
  usePathname: () => "/iam/apps/c1",
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("@/contexts/AuthContext", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/contexts/AuthContext")>()),
  useAuth: () => ({ tenantId: "t1" }),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useIAM: () => iam,
  useToast: () => ({ toast: vi.fn() }),
  useApi: () => ({
    data: { app: { name: "portal", redirect_uris: ["https://x/cb"], grant_types: ["authorization_code"] } },
    isLoading: false,
    error: null,
    refetch: vi.fn(),
  }),
  useMutation: (fn: (v: unknown) => unknown) => ({
    mutate: (v: unknown) => fn(v),
    isLoading: false,
  }),
}));

vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({ loading: false, error: undefined, capability: caps.capability }),
}));

const DELETE_OP = "DELETE /api/v1/iam/apps/{id}";

describe("AppDetailClient on the embedded IAM backend", () => {
  beforeEach(() => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    caps.capability.mockImplementation(() => ({ enabled: true }));
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    iam.updateApp.mockReset();
    iam.deleteApp.mockReset();
  });

  it("disables Edit with the App.Update reason and never calls the SDK", () => {
    render(<AppDetailClient />);
    const edit = screen.getByRole("button", { name: /Edit/ }) as HTMLButtonElement;
    expect(edit.disabled).toBe(true);
    expect(
      screen.getByText("Not available: the embedded IAM backend does not implement App.Update yet"),
    ).toBeTruthy();
    fireEvent.click(edit);
    expect(screen.queryByText("Edit Application")).toBeNull();
    expect(screen.queryByRole("button", { name: /Save/ })).toBeNull();
    expect(iam.updateApp).not.toHaveBeenCalled();
  });

  it("keeps the read-only view", () => {
    render(<AppDetailClient />);
    expect(screen.getByText("https://x/cb")).toBeTruthy();
    expect(screen.getByText("authorization_code")).toBeTruthy();
  });
});

// #2054: the Delete control carries its server op and is disabled with the
// server's reason when the server does not offer DeleteApp.
describe("AppDetailClient Delete capability gate", () => {
  let confirmSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    caps.capability.mockImplementation(() => ({ enabled: true }));
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    iam.deleteApp.mockReset();
  });

  it("withholds Delete when the server does not offer DELETE /api/v1/iam/apps/{id}", () => {
    caps.capability.mockImplementation((op: string) =>
      op === DELETE_OP ? { enabled: false, reason: "not offered by this server" } : { enabled: true },
    );
    render(<AppDetailClient />);
    const del = screen.getByRole("button", { name: /Delete/ }) as HTMLButtonElement;
    expect(del.disabled).toBe(true);
    expect(del.getAttribute("title")).toBe("not offered by this server");
    expect(del.getAttribute("data-capability-op")).toBe(DELETE_OP);
    expect(del.getAttribute("data-capability-enabled")).toBe("false");
    fireEvent.click(del);
    expect(confirmSpy).not.toHaveBeenCalled();
    expect(iam.deleteApp).not.toHaveBeenCalled();
  });

  it("deletes through the SDK after the confirm when the op is offered", () => {
    render(<AppDetailClient />);
    const del = screen.getByRole("button", { name: /Delete/ }) as HTMLButtonElement;
    expect(del.getAttribute("data-capability-enabled")).toBe("true");
    fireEvent.click(del);
    expect(confirmSpy).toHaveBeenCalledTimes(1);
    expect(iam.deleteApp).toHaveBeenCalledWith("t1", "c1");
  });
});
