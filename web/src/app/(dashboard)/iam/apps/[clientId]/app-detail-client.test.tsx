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

// The page's useAppDetail hook reads the SDK hooks directly.
vi.mock("trusted-platform-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("trusted-platform-sdk")>()),
  useIAM: () => iam,
  useApi: () => ({
    data: { app: { name: "portal", redirect_uris: ["https://x/cb"], grant_types: ["authorization_code"] } },
    isLoading: false,
    error: null,
    refetch: vi.fn(),
  }),
}));

describe("AppDetailClient on the embedded IAM backend", () => {
  beforeEach(() => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    iam.updateApp.mockReset();
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
