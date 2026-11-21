import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import NewPolicyPage from "./page";

const iam = {
  createPolicy: vi.fn(async () => ({ success: true, data: {} })),
};
const toastResult = { toast: vi.fn() };
const routerResult = { push: vi.fn() };
const authResult = { tenantId: "t1", isLoading: false };

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
  useToast: () => toastResult,
}));

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("NewPolicyPage", () => {
  it("sends a policy YAML whose scalars are quoted", async () => {
    render(<NewPolicyPage />);

    fireEvent.change(screen.getByLabelText("Name *"), { target: { value: "allow-read" } });
    fireEvent.change(screen.getByLabelText("Description"), { target: { value: "Allow: reads" } });
    fireEvent.change(screen.getByLabelText("Actions (comma-separated)"), {
      target: { value: "read, write" },
    });
    fireEvent.change(screen.getByLabelText("Resources (comma-separated)"), {
      target: { value: '*, kv://a"b' },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create Policy" }));

    await waitFor(() => expect(iam.createPolicy).toHaveBeenCalledTimes(1));
    const calls = iam.createPolicy.mock.calls as unknown as Array<[{ specYaml: string }]>;
    const lines = calls[0][0].specYaml.split("\n");
    expect(lines).toContain('  name: "allow-read"');
    expect(lines).toContain('  tenant: "t1"');
    expect(lines).toContain('  description: "Allow: reads"');
    expect(lines).toContain('      actions: ["read", "write"]');
    expect(lines).toContain('      resources: ["*", "kv://a\\"b"]');
  });

  it("disables Create Policy while the name is empty", () => {
    render(<NewPolicyPage />);

    const button = screen.getByRole("button", { name: "Create Policy" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
  });
});
