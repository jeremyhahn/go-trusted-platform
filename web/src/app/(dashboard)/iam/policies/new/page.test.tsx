/* eslint-disable @typescript-eslint/no-explicit-any */
import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import NewPolicyPage from "./page";

const router = { push: vi.fn() };
const toast = vi.fn();
const iam = { createPolicy: vi.fn() };

let authResult: { tenantId?: string; isLoading: boolean };
let mutationLoading: boolean;
let mutationCall: { fn: () => Promise<unknown>; opts: any };

// useMutation runs the page's function and then its onSuccess or onError,
// the way the real hook does.
const mutate = vi.fn(async () => {
  try {
    const r = await mutationCall.fn();
    mutationCall.opts?.onSuccess?.(r);
  } catch (e) {
    mutationCall.opts?.onError?.(e);
  }
});

vi.mock("next/navigation", () => ({ useRouter: () => router }));

vi.mock("@/contexts/AuthContext", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/contexts/AuthContext")>()),
  useAuth: () => authResult,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useIAM: () => iam,
  useToast: () => ({ toast }),
  useMutation: (fn: () => Promise<unknown>, opts: unknown) => {
    mutationCall = { fn, opts };
    return { mutate, isLoading: mutationLoading };
  },
}));

// The Radix select does not open in jsdom: a native select keeps the page's
// value and onValueChange wiring.
vi.mock("@/components/ui/select", () => ({
  Select: ({ value, onValueChange, children }: any) => (
    <select aria-label="Effect" value={value} onChange={(e) => onValueChange(e.target.value)}>
      {children}
    </select>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: any) => <>{children}</>,
  SelectItem: ({ value, children }: any) => <option value={value}>{children}</option>,
}));

const type = (label: string, value: string) =>
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
const createButton = () => screen.getByRole("button", { name: "Create Policy" }) as HTMLButtonElement;

beforeEach(() => {
  authResult = { tenantId: "t1", isLoading: false };
  mutationLoading = false;
  iam.createPolicy.mockResolvedValue({});
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("NewPolicyPage", () => {
  it("shows only a spinner while auth loads", () => {
    authResult = { tenantId: "t1", isLoading: true };
    render(<NewPolicyPage />);
    expect(screen.queryByText("Create Policy")).toBeNull();
  });

  it("keeps Create disabled until a name is entered", () => {
    render(<NewPolicyPage />);
    expect(createButton().disabled).toBe(true);
    type("Name *", "allow-read");
    expect(createButton().disabled).toBe(false);
    type("Name *", "");
    expect(createButton().disabled).toBe(true);
  });

  it("keeps Create disabled while the create runs", () => {
    mutationLoading = true;
    render(<NewPolicyPage />);
    type("Name *", "allow-read");
    expect(createButton().disabled).toBe(true);
  });

  it("builds the policy YAML from the form and routes back on success", async () => {
    render(<NewPolicyPage />);
    type("Name *", "deny-writes");
    type("Description", "No writes");
    fireEvent.change(screen.getByLabelText("Effect"), { target: { value: "deny" } });
    // Blank entries and padding are dropped from both lists.
    type("Actions (comma-separated)", " write , ,delete ");
    type("Resources (comma-separated)", "kv://a/*, , *");
    fireEvent.click(createButton());
    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/iam/policies"));
    const yaml = [
      "apiVersion: v1",
      "kind: Policy",
      "metadata:",
      "  name: deny-writes",
      "  tenant: t1",
      "  description: No writes",
      "spec:",
      "  rules:",
      "    - name: rule-1",
      "      effect: deny",
      "      actions: [write, delete]",
      '      resources: ["kv://a/*", "*"]',
    ].join("\n");
    expect(iam.createPolicy).toHaveBeenCalledWith({
      tenantId: "t1",
      name: "deny-writes",
      description: "No writes",
      specYaml: yaml,
      spec: yaml,
      spec_yaml: yaml,
    });
    expect(toast).toHaveBeenCalledWith({ title: "Policy created", variant: "success" });
  });

  it("uses the defaults and an empty description", async () => {
    render(<NewPolicyPage />);
    type("Name *", "p");
    fireEvent.click(createButton());
    await waitFor(() => expect(iam.createPolicy).toHaveBeenCalledTimes(1));
    const spec: string = iam.createPolicy.mock.calls[0][0].specYaml;
    expect(spec).toContain("  description: \n");
    expect(spec).toContain("      effect: allow\n");
    expect(spec).toContain("      actions: [read]\n");
    expect(spec.endsWith('      resources: ["*"]')).toBe(true);
  });

  it("toasts the error and stays on the page when the create fails", async () => {
    iam.createPolicy.mockRejectedValue(new Error("conflict"));
    render(<NewPolicyPage />);
    type("Name *", "p");
    fireEvent.click(createButton());
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Failed to create policy",
        description: "conflict",
        variant: "destructive",
      }),
    );
    expect(router.push).not.toHaveBeenCalled();
  });

  it("reports a non-Error failure as unknown", () => {
    render(<NewPolicyPage />);
    mutationCall.opts.onError("bad");
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "Unknown error" }));
  });

  it("refuses to create without a tenant", async () => {
    authResult = { tenantId: undefined, isLoading: false };
    render(<NewPolicyPage />);
    await expect(mutationCall.fn()).rejects.toThrow("No tenant available");
    expect(iam.createPolicy).not.toHaveBeenCalled();
  });

  it("goes back to the list on Cancel", () => {
    render(<NewPolicyPage />);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(router.push).toHaveBeenCalledWith("/iam/policies");
    expect(mutate).not.toHaveBeenCalled();
  });
});
