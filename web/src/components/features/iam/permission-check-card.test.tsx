import React from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * PermissionCheckCard shows a verdict only for the tenant and the inputs
 * that were checked, and never a previous verdict while a new check runs.
 */

const checkPermission = vi.fn();

vi.mock("@/hooks", () => ({
  useIAM: () => ({ checkPermission }),
  // Mirrors the SDK's useMutation: data is kept while the next call loads.
  useMutation: <V, R>(fn: (vars: V) => Promise<R>) => {
    const [state, setState] = React.useState<{
      data: R | undefined;
      error: Error | null;
      isLoading: boolean;
    }>({ data: undefined, error: null, isLoading: false });
    const mutate = (vars: V) => {
      setState((s) => ({ ...s, error: null, isLoading: true }));
      return fn(vars).then(
        (data) => setState({ data, error: null, isLoading: false }),
        (error: Error) => setState((s) => ({ ...s, error, isLoading: false }))
      );
    };
    return { ...state, mutate, mutateAsync: mutate };
  },
}));

import { PermissionCheckCard } from "./permission-check-card";

function fill(subject: string, action: string, resource: string) {
  fireEvent.change(screen.getByLabelText("Subject ID"), { target: { value: subject } });
  fireEvent.change(screen.getByLabelText("Action"), { target: { value: action } });
  fireEvent.change(screen.getByLabelText("Resource"), { target: { value: resource } });
}

async function submit() {
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /Check/ }));
  });
}

describe("PermissionCheckCard", () => {
  beforeEach(() => {
    checkPermission.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("shows the verdict for the inputs that were checked", async () => {
    checkPermission.mockResolvedValue({ allowed: true, matchedPolicy: "p-1" });
    render(<PermissionCheckCard tenantId="t-1" />);

    fill("u-1", "read", "fleet");
    await submit();

    expect(checkPermission).toHaveBeenCalledWith({
      tenantId: "t-1",
      subjectId: "u-1",
      action: "read",
      resource: "fleet",
    });
    expect(screen.getByText("Allowed")).toBeDefined();
  });

  it("hides the verdict once an input changes", async () => {
    checkPermission.mockResolvedValue({ allowed: true });
    render(<PermissionCheckCard tenantId="t-1" />);

    fill("u-1", "read", "fleet");
    await submit();
    expect(screen.getByText("Allowed")).toBeDefined();

    fireEvent.change(screen.getByLabelText("Resource"), { target: { value: "secrets" } });
    expect(screen.queryByText("Allowed")).toBeNull();

    fireEvent.change(screen.getByLabelText("Resource"), { target: { value: "fleet" } });
    expect(screen.getByText("Allowed")).toBeDefined();
  });

  it("hides the verdict when the tenant changes", async () => {
    checkPermission.mockResolvedValue({ allowed: false });
    const { rerender } = render(<PermissionCheckCard tenantId="t-1" />);

    fill("u-1", "read", "fleet");
    await submit();
    expect(screen.getByText("Denied")).toBeDefined();

    rerender(<PermissionCheckCard tenantId="t-2" />);
    expect(screen.queryByText("Denied")).toBeNull();
  });

  it("does not show the previous verdict while another check runs", async () => {
    checkPermission.mockResolvedValueOnce({ allowed: true });
    render(<PermissionCheckCard tenantId="t-1" />);

    fill("u-1", "read", "fleet");
    await submit();
    expect(screen.getByText("Allowed")).toBeDefined();

    let resolve!: (v: unknown) => void;
    checkPermission.mockReturnValueOnce(new Promise((r) => (resolve = r)));
    fill("u-1", "write", "fleet");
    fireEvent.change(screen.getByLabelText("Action"), { target: { value: "read" } });
    await submit();
    expect(screen.queryByText("Allowed")).toBeNull();
    expect(screen.queryByText("Denied")).toBeNull();

    await act(async () => {
      resolve({ allowed: false });
    });
    expect(screen.getByText("Denied")).toBeDefined();
  });

  it("sends the roles and groups typed for the subject", async () => {
    checkPermission.mockResolvedValue({ allowed: true });
    render(<PermissionCheckCard tenantId="t-1" />);

    fill("u-1", "read", "fleet");
    fireEvent.change(screen.getByLabelText("Roles"), { target: { value: " admin, ops ," } });
    fireEvent.change(screen.getByLabelText("Groups"), { target: { value: "g-1" } });
    await submit();

    expect(checkPermission).toHaveBeenCalledWith({
      tenantId: "t-1",
      subjectId: "u-1",
      action: "read",
      resource: "fleet",
      roles: ["admin", "ops"],
      groups: ["g-1"],
    });
  });

  it("hides the verdict once the roles change", async () => {
    checkPermission.mockResolvedValue({ allowed: true });
    render(<PermissionCheckCard tenantId="t-1" />);

    fill("u-1", "read", "fleet");
    fireEvent.change(screen.getByLabelText("Roles"), { target: { value: "admin" } });
    await submit();
    expect(screen.getByText("Allowed")).toBeDefined();

    fireEvent.change(screen.getByLabelText("Roles"), { target: { value: "viewer" } });
    expect(screen.queryByText("Allowed")).toBeNull();

    fireEvent.change(screen.getByLabelText("Roles"), { target: { value: "admin" } });
    expect(screen.getByText("Allowed")).toBeDefined();
  });
});
