import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import PolicyDetailClient from "./policy-detail-client";

// QuicBaaSIAMAdapter.UpdatePolicy answers 400 to any non-empty spec_yaml, so
// the detail page saves a policy's description and priority only (#1965).
const iam = {
  getPolicy: vi.fn(),
  deletePolicy: vi.fn(async () => ({ success: true, data: {} })),
  updatePolicy: vi.fn(async (_req: Record<string, unknown>) => ({ success: true, data: {} })),
  validatePolicy: vi.fn(async () => ({ success: true, data: { valid: true } })),
};
const toastResult = { toast: vi.fn() };
const routerResult = { push: vi.fn() };
const authResult = { tenantId: "t1", isLoading: false };
const apiResult = {
  data: { policy: { description: "old desc", priority: 3, spec_yaml: "spec:\n  rules: []\n" } },
  isLoading: false,
  error: null,
  refetch: vi.fn(),
};
const mutationResult = { mutate: vi.fn(), isLoading: false };

vi.mock("next/navigation", () => ({
  useRouter: () => routerResult,
  useParams: () => ({ name: "p1" }),
  usePathname: () => "/iam/policies/p1",
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

describe("PolicyDetailClient edit", () => {
  it("saves a description-only change with no spec_yaml in the update", async () => {
    render(<PolicyDetailClient />);
    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    fireEvent.change(screen.getByLabelText("Description"), { target: { value: "new desc" } });
    const save = screen.getByRole("button", { name: "Save" }) as HTMLButtonElement;
    expect(save.disabled).toBe(false);
    fireEvent.click(save);

    await waitFor(() => expect(iam.updatePolicy).toHaveBeenCalledTimes(1));
    const req = iam.updatePolicy.mock.calls[0][0];
    expect(req).toEqual({ tenantId: "t1", policyName: "p1", description: "new desc", priority: 3 });
    expect(req).not.toHaveProperty("spec_yaml");
    expect(req).not.toHaveProperty("specYaml");
    expect(req).not.toHaveProperty("spec");
  });
});
