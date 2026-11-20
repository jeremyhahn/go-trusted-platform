import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import PolicyDetailClient from "./policy-detail-client";

// #2024 Codex: the embedded IAM backend has no Policy.Update handler, so the
// policy edit control is gated off with the reason shown and never reaches
// the SDK. The read-only view stays.

const iam = vi.hoisted(() => ({
  getPolicy: vi.fn(),
  updatePolicy: vi.fn(),
  deletePolicy: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useParams: () => ({ name: "allow-read" }),
  usePathname: () => "/iam/policies/allow-read",
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
    data: { policy: { name: "allow-read", description: "d", priority: 3, spec_yaml: "kind: Policy" } },
    isLoading: false,
    error: null,
    refetch: vi.fn(),
  }),
  useMutation: (fn: (v: unknown) => unknown) => ({
    mutate: (v: unknown) => fn(v),
    isLoading: false,
  }),
}));

// The page's usePolicyDetail hook reads the SDK hooks directly.
vi.mock("trusted-platform-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("trusted-platform-sdk")>()),
  useIAM: () => iam,
  useApi: () => ({
    data: { policy: { name: "allow-read", description: "d", priority: 3, spec_yaml: "kind: Policy" } },
    isLoading: false,
    error: null,
    refetch: vi.fn(),
  }),
}));

describe("PolicyDetailClient on the embedded IAM backend", () => {
  beforeEach(() => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    iam.updatePolicy.mockReset();
  });

  it("disables Edit with the Policy.Update reason and never calls the SDK", () => {
    render(<PolicyDetailClient />);
    const edit = screen.getByRole("button", { name: /Edit/ }) as HTMLButtonElement;
    expect(edit.disabled).toBe(true);
    expect(
      screen.getByText("Not available: the embedded IAM backend does not implement Policy.Update yet"),
    ).toBeTruthy();
    fireEvent.click(edit);
    expect(screen.queryByLabelText("Description")).toBeNull();
    expect(screen.queryByRole("button", { name: /Save/ })).toBeNull();
    expect(iam.updatePolicy).not.toHaveBeenCalled();
  });

  it("keeps the read-only view", () => {
    render(<PolicyDetailClient />);
    expect(screen.getByText("kind: Policy")).toBeTruthy();
    expect(screen.getByText("priority 3")).toBeTruthy();
  });
});
