import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import GroupDetailClient from "./group-detail-client";

// #2024 Codex: the embedded IAM backend has no Group.AddMember or
// Group.RemoveMember handler, so the membership controls are gated off with
// the reason shown and never reach the SDK. The read-only view stays.

const iam = vi.hoisted(() => ({
  getGroup: vi.fn(),
  updateGroup: vi.fn(),
  deleteGroup: vi.fn(),
  addGroupMember: vi.fn(),
  removeGroupMember: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useParams: () => ({ id: "g1" }),
  usePathname: () => "/iam/groups/g1",
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
    data: { group: { name: "ops", member_ids: ["u1"], role_ids: [] } },
    isLoading: false,
    error: null,
    refetch: vi.fn(),
  }),
  useMutation: (fn: (v: unknown) => unknown) => ({
    mutate: (v: unknown) => fn(v),
    isLoading: false,
  }),
}));

describe("GroupDetailClient on the embedded IAM backend", () => {
  afterEach(() => {
    cleanup();
    iam.addGroupMember.mockReset();
    iam.removeGroupMember.mockReset();
  });

  it("disables Add member with the Group.AddMember reason and never calls the SDK", () => {
    render(<GroupDetailClient />);
    fireEvent.change(screen.getByLabelText("User ID"), { target: { value: "u2" } });
    const add = screen.getByRole("button", { name: /Add member/ }) as HTMLButtonElement;
    expect(add.disabled).toBe(true);
    expect(
      screen.getByText("Not available: the embedded IAM backend does not implement Group.AddMember yet"),
    ).toBeTruthy();
    fireEvent.click(add);
    fireEvent.submit(add.closest("form")!);
    expect(iam.addGroupMember).not.toHaveBeenCalled();
  });

  it("disables both remove controls with the Group.RemoveMember reason and never calls the SDK", () => {
    render(<GroupDetailClient />);
    const perMember = screen.getByRole("button", { name: "Remove member u1" }) as HTMLButtonElement;
    expect(perMember.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("User ID to remove"), { target: { value: "u1" } });
    const byId = screen.getByRole("button", { name: /Remove by user ID/ }) as HTMLButtonElement;
    expect(byId.disabled).toBe(true);
    expect(
      screen.getByText("Not available: the embedded IAM backend does not implement Group.RemoveMember yet"),
    ).toBeTruthy();
    fireEvent.click(perMember);
    fireEvent.click(byId);
    fireEvent.submit(byId.closest("form")!);
    expect(screen.queryByText("Remove member?")).toBeNull();
    expect(iam.removeGroupMember).not.toHaveBeenCalled();
  });

  it("keeps the read-only member list", () => {
    render(<GroupDetailClient />);
    expect(screen.getByText("u1")).toBeTruthy();
  });
});
