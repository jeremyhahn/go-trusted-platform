import * as React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import PoliciesPage from "./page";

const iam = {
  listPolicies: vi.fn(async () => ({ success: true, data: { policies: [] } })),
  deletePolicy: vi.fn(async () => ({ success: true, data: {} })),
  testPolicy: vi.fn(async () => ({ success: true, data: {} })),
};
const toastResult = { toast: vi.fn() };
const routerResult = { push: vi.fn() };
const authResult = { tenantId: "t1", isLoading: false };
const apiResult = {
  data: { policies: [] },
  isLoading: false,
  error: null,
  refetch: vi.fn(),
};
const mutationResult = { mutate: vi.fn(), isLoading: false };

vi.mock("next/navigation", () => ({
  useRouter: () => routerResult,
}));

vi.mock("@/contexts/AuthContext", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/contexts/AuthContext")>()),
  useAuth: () => authResult,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useIAM: () => iam,
  useApi: () => apiResult,
  useMutation: () => mutationResult,
  useToast: () => toastResult,
}));

vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: () => ({ enabled: true }),
  }),
}));

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("PoliciesPage", () => {
  // The IAM service answers TestPolicy 501 until it can evaluate a request,
  // so the page offers no policy test.
  it("offers no policy test while the server cannot evaluate one", () => {
    render(<PoliciesPage />);

    expect(screen.getByRole("heading", { name: "Policies" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Run test" })).toBeNull();
    expect(iam.testPolicy).not.toHaveBeenCalled();
  });
});
