/* eslint-disable @typescript-eslint/no-explicit-any */
import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import NewRolePage from "./page";

const router = { push: vi.fn() };
const toast = vi.fn();
const iam = { createRole: vi.fn() };

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

const type = (label: string, value: string) =>
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
const createButton = () => screen.getByRole("button", { name: "Create Role" }) as HTMLButtonElement;

beforeEach(() => {
  authResult = { tenantId: "t1", isLoading: false };
  mutationLoading = false;
  iam.createRole.mockResolvedValue({});
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("NewRolePage", () => {
  it("shows only a spinner while auth loads", () => {
    authResult = { tenantId: "t1", isLoading: true };
    render(<NewRolePage />);
    expect(screen.queryByText("Create Role")).toBeNull();
  });

  it("keeps Create disabled without a name or while the create runs", () => {
    render(<NewRolePage />);
    expect(createButton().disabled).toBe(true);
    type("Name *", "admin");
    expect(createButton().disabled).toBe(false);
    cleanup();
    mutationLoading = true;
    render(<NewRolePage />);
    type("Name *", "admin");
    expect(createButton().disabled).toBe(true);
  });

  it("slugs the name into the id, trims the permissions and routes back", async () => {
    render(<NewRolePage />);
    type("Name *", "Key Admins / EU");
    type("Description", "Admins");
    type("Permissions (comma-separated)", " kv:read, ,kv:write ,* ");
    fireEvent.click(createButton());
    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/iam/roles"));
    expect(iam.createRole).toHaveBeenCalledWith({
      tenantId: "t1",
      id: "key-admins-eu",
      name: "Key Admins / EU",
      description: "Admins",
      permissions: ["kv:read", "kv:write", "*"],
    });
    expect(toast).toHaveBeenCalledWith({ title: "Role created", variant: "success" });
  });

  it("sends an empty permission list when none are entered", async () => {
    render(<NewRolePage />);
    type("Name *", "viewer-1");
    fireEvent.click(createButton());
    await waitFor(() => expect(iam.createRole).toHaveBeenCalledTimes(1));
    expect(iam.createRole.mock.calls[0][0]).toMatchObject({ id: "viewer-1", description: "", permissions: [] });
  });

  it("toasts the error and stays on the page when the create fails", async () => {
    iam.createRole.mockRejectedValue(new Error("exists"));
    render(<NewRolePage />);
    type("Name *", "admin");
    fireEvent.click(createButton());
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Failed to create role",
        description: "exists",
        variant: "destructive",
      }),
    );
    expect(router.push).not.toHaveBeenCalled();
  });

  it("reports a non-Error failure as unknown", () => {
    render(<NewRolePage />);
    mutationCall.opts.onError({ code: 1 });
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "Unknown error" }));
  });

  it("refuses to create without a tenant", async () => {
    authResult = { tenantId: undefined, isLoading: false };
    render(<NewRolePage />);
    await expect(mutationCall.fn()).rejects.toThrow("No tenant available");
    expect(iam.createRole).not.toHaveBeenCalled();
  });

  it("goes back to the list on Cancel", () => {
    render(<NewRolePage />);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(router.push).toHaveBeenCalledWith("/iam/roles");
    expect(mutate).not.toHaveBeenCalled();
  });
});
