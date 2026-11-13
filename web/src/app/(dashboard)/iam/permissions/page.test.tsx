import * as React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import PermissionsPage from "./page";

// The page calls useApi three times per render, in a fixed order: groups,
// policies, roles. The mock records each fetcher and hands back the result
// for that slot. Results are stable objects: a fresh `data` per render would
// re-run the page's memoised permission derivation on every pass.
type ApiResult = { data: unknown; isLoading: boolean; error: unknown };

const iam = {
  listGroups: vi.fn(),
  listPolicies: vi.fn(),
  listRoles: vi.fn(),
};

let authResult: { tenantId?: string; isLoading: boolean; user?: unknown };
let results: ApiResult[];
let fetchers: Array<() => Promise<unknown>>;

const ok = (data: unknown): ApiResult => ({ data, isLoading: false, error: null });

const groupsData = {
  groups: [
    { id: "g-ops", name: "Operators", description: "Ops team", members: ["u1", "u2"], tenantId: "t1" },
    { id: "g-bare", name: "", description: "", tenantId: "t1" },
  ],
};
const policiesData = {
  policies: [{ name: "allow-read", description: "Reads", priority: 5, tenantId: "t1" }],
};
const rolesData = {
  roles: [
    { id: "r1", permissions: ["kv:read", "kv:write"] },
    { id: "r2", permissions: ["kv:read", "admin"] },
    { id: "r3" },
  ],
};

vi.mock("@/contexts/AuthContext", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/contexts/AuthContext")>()),
  useAuth: () => authResult,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useIAM: () => iam,
  useApi: (fn: () => Promise<unknown>) => {
    const slot = fetchers.length % 3;
    fetchers.push(fn);
    return results[slot];
  },
}));

// Radix tabs render only the active panel in jsdom; render every panel
// inline so the policies and permissions panels can be asserted too.
vi.mock("@/components/ui/tabs", async (importOriginal) => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <div>{children}</div>;
  const Trigger = ({ children }: { children?: React.ReactNode }) => (
    <button type="button">{children}</button>
  );
  return {
    ...(await importOriginal<typeof import("@/components/ui/tabs")>()),
    Tabs: Pass,
    TabsList: Pass,
    TabsContent: Pass,
    TabsTrigger: Trigger,
  };
});

beforeEach(() => {
  authResult = { tenantId: "t1", isLoading: false };
  results = [ok(groupsData), ok(policiesData), ok(rolesData)];
  fetchers = [];
  iam.listGroups.mockResolvedValue(groupsData);
  iam.listPolicies.mockResolvedValue(policiesData);
  iam.listRoles.mockResolvedValue(rolesData);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("PermissionsPage", () => {
  it("shows the auth loading state while auth resolves", () => {
    authResult = { tenantId: "t1", isLoading: true };
    render(<PermissionsPage />);
    expect(screen.getByText("Loading authentication...")).toBeTruthy();
    expect(screen.queryByText("Access Control")).toBeNull();
  });

  it("asks to log in again when there is no tenant, and its fetchers reject", async () => {
    authResult = { tenantId: undefined, isLoading: false };
    render(<PermissionsPage />);
    expect(screen.getByText("Authentication Required")).toBeTruthy();
    expect(fetchers.length).toBeGreaterThanOrEqual(3);
    for (const fetch of fetchers.slice(0, 3)) {
      await expect(fetch()).rejects.toThrow("No tenant ID");
    }
    expect(iam.listGroups).not.toHaveBeenCalled();
    expect(iam.listPolicies).not.toHaveBeenCalled();
    expect(iam.listRoles).not.toHaveBeenCalled();
  });

  it("fetches groups, policies and roles for the tenant", async () => {
    render(<PermissionsPage />);
    const [groups, policies, roles] = fetchers;
    await expect(groups()).resolves.toBe(groupsData);
    await expect(policies()).resolves.toBe(policiesData);
    await expect(roles()).resolves.toBe(rolesData);
    expect(iam.listGroups).toHaveBeenCalledWith({ tenantId: "t1" });
    expect(iam.listPolicies).toHaveBeenCalledWith({ tenantId: "t1" });
    expect(iam.listRoles).toHaveBeenCalledWith({ tenantId: "t1" });
  });

  it.each([0, 1, 2])("shows the error message when fetch %i fails", (slot) => {
    results[slot] = { data: undefined, isLoading: false, error: new Error(`boom-${slot}`) };
    render(<PermissionsPage />);
    expect(screen.getByText("Error Loading Data")).toBeTruthy();
    expect(screen.getByText(`boom-${slot}`)).toBeTruthy();
  });

  it("falls back to a generic message for a non-Error failure", () => {
    results[2] = { data: undefined, isLoading: false, error: "nope" };
    render(<PermissionsPage />);
    expect(screen.getByText("Failed to load data")).toBeTruthy();
  });

  it("derives unique permissions from the roles and groups them by resource", () => {
    render(<PermissionsPage />);
    expect(screen.getByText("Access Control")).toBeTruthy();
    expect(screen.getByText("Groups (2)")).toBeTruthy();
    expect(screen.getByText("Policies (1)")).toBeTruthy();
    // kv:read appears in two roles but counts once; a role without
    // permissions adds none.
    expect(screen.getByText("Permissions (3)")).toBeTruthy();
    expect(screen.getByText("2 permissions")).toBeTruthy();
    expect(screen.getByText("1 permission")).toBeTruthy();
    // A permission without a colon is its own resource with action "*".
    expect(screen.getAllByText("Permission: admin").length).toBeGreaterThan(0);
    expect(screen.getAllByText("*").length).toBeGreaterThan(0);
    expect(screen.getAllByText("kv:write").length).toBeGreaterThan(0);
  });

  it("renders group and policy rows with their fallbacks", () => {
    render(<PermissionsPage />);
    expect(screen.getByText("Operators")).toBeTruthy();
    expect(screen.getByText("2 members")).toBeTruthy();
    // A group without a name shows its id in the name column, no members
    // and a dash for the description.
    expect(screen.getAllByText("g-bare").length).toBe(2);
    expect(screen.getByText("0 members")).toBeTruthy();
    expect(screen.getAllByText("-").length).toBeGreaterThan(0);
    expect(screen.getByText("allow-read")).toBeTruthy();
    expect(screen.getByText("5")).toBeTruthy();
  });

  it("renders empty lists when the replies carry no items", () => {
    results = [ok({}), ok(undefined), ok({ roles: [] })];
    render(<PermissionsPage />);
    expect(screen.getByText("Groups (0)")).toBeTruthy();
    expect(screen.getByText("Policies (0)")).toBeTruthy();
    expect(screen.getByText("Permissions (0)")).toBeTruthy();
  });
});
