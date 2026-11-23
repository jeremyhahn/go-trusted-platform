import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

const caps = vi.hoisted(() => ({ capability: vi.fn() }));

vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({ loading: false, error: undefined, capability: caps.capability }),
}));

const PUT_GROUP = "PUT /api/v1/iam/groups/{id}";
const DELETE_GROUP = "DELETE /api/v1/iam/groups/{id}";
const REASON = "not-configured: iam";

function offExcept(off: string) {
  caps.capability.mockImplementation((op: string) =>
    op === off ? { enabled: false, reason: REASON } : { enabled: true },
  );
}

describe("GroupDetailClient on the embedded IAM backend", () => {
  beforeEach(() => {
    caps.capability.mockImplementation(() => ({ enabled: true }));
    iam.updateGroup.mockReset();
    iam.deleteGroup.mockReset();
  });

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

describe("GroupDetailClient capability gating", () => {
  beforeEach(() => {
    caps.capability.mockImplementation(() => ({ enabled: true }));
    iam.updateGroup.mockReset();
    iam.deleteGroup.mockReset();
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("gates Save group on PUT /api/v1/iam/groups/{id}", () => {
    offExcept(PUT_GROUP);
    render(<GroupDetailClient />);
    const save = screen.getByRole("button", { name: "Save group" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    expect(save.title).toBe(REASON);
    expect(save.getAttribute("data-capability-op")).toBe(PUT_GROUP);
    expect(save.getAttribute("data-capability-enabled")).toBe("false");
    fireEvent.submit(save.closest("form")!);
    expect(iam.updateGroup).not.toHaveBeenCalled();
  });

  it("gates Delete on DELETE /api/v1/iam/groups/{id}", () => {
    offExcept(DELETE_GROUP);
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<GroupDetailClient />);
    const del = screen.getByRole("button", { name: "Delete" }) as HTMLButtonElement;
    expect(del.disabled).toBe(true);
    expect(del.title).toBe(REASON);
    expect(del.getAttribute("data-capability-op")).toBe(DELETE_GROUP);
    expect(del.getAttribute("data-capability-enabled")).toBe("false");
    fireEvent.click(del);
    expect(iam.deleteGroup).not.toHaveBeenCalled();
  });

  it("saves through the SDK when the server offers it", () => {
    render(<GroupDetailClient />);
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "ops2" } });
    const save = screen.getByRole("button", { name: "Save group" }) as HTMLButtonElement;
    fireEvent.submit(save.closest("form")!);
    expect(iam.updateGroup).toHaveBeenCalledTimes(1);
    expect(iam.updateGroup).toHaveBeenCalledWith({
      tenantId: "t1",
      groupId: "g1",
      name: "ops2",
      description: "",
    });
  });

  it("deletes through the SDK after the confirm when offered", () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<GroupDetailClient />);
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(iam.deleteGroup).toHaveBeenCalledWith("t1", "g1");
  });
});
