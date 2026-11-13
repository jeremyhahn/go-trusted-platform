import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import TenantPage from "./page";

// The page reads the user from the JWT, fetches the tenant when the user has
// one, and offers navigation and logout. The token, cookie, base URL, router,
// logout hook and fetch are stubbed so each path can be driven.

type User = { tenantId?: string; isTenantOwner: boolean } | null;

const router = { push: vi.fn() };
const logout = vi.fn();
const getUserFromToken = vi.fn<() => User>();
const fetchMock = vi.fn();

vi.mock("next/navigation", () => ({ useRouter: () => router }));
vi.mock("@/utils/jwt", () => ({ getUserFromToken: () => getUserFromToken() }));
vi.mock("@/utils/getBaseUrl", () => ({ getBaseUrl: () => "base" }));
vi.mock("@/utils/cookie", () => ({ getCookie: (name: string) => `cookie-${name}` }));
vi.mock("@/hooks/use-logout", () => ({ useLogout: () => logout }));

function respond(ok: boolean, body: unknown) {
  fetchMock.mockResolvedValue({ ok, json: () => Promise.resolve(body) });
}

// The value cell next to an info label.
function info(label: string): string | null | undefined {
  return screen.getByText(label).nextElementSibling?.textContent;
}

async function settled() {
  await waitFor(() => expect(screen.queryByText("Loading tenant information...")).toBeNull());
}

beforeEach(() => {
  router.push.mockReset();
  logout.mockReset();
  getUserFromToken.mockReset();
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("admin TenantPage", () => {
  it("redirects to sign-in without a user and never fetches", async () => {
    getUserFromToken.mockReturnValue(null);
    render(<TenantPage />);
    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/auth/webauthn"));
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.getByText("Loading tenant information...")).toBeTruthy();
  });

  it("shows the empty workspace without a tenant", async () => {
    getUserFromToken.mockReturnValue({ isTenantOwner: false });
    render(<TenantPage />);
    await settled();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(info("Workspace ID")).toBe("N/A");
    expect(info("Members")).toBe("0");
    expect(screen.queryByText("Workspace Name")).toBeNull();
  });

  it("fetches the tenant with the JWT and shows its name and members", async () => {
    getUserFromToken.mockReturnValue({ tenantId: "tenant-1", isTenantOwner: true });
    respond(true, { name: "Acme", member_count: 7 });
    render(<TenantPage />);
    await settled();
    expect(fetchMock).toHaveBeenCalledWith("base/api/v1/tenant", {
      headers: { Authorization: "Bearer cookie-jwt" },
    });
    expect(info("Workspace ID")).toBe("tenant-1");
    expect(info("Workspace Name")).toBe("Acme");
    expect(info("Members")).toBe("7");
  });

  it("defaults a missing name and member count", async () => {
    getUserFromToken.mockReturnValue({ tenantId: "tenant-1", isTenantOwner: false });
    respond(true, {});
    render(<TenantPage />);
    await settled();
    expect(info("Workspace ID")).toBe("tenant-1");
    expect(screen.queryByText("Workspace Name")).toBeNull();
    expect(info("Members")).toBe("0");
  });

  it("shows an error and keeps the tenant id when the response is not ok", async () => {
    getUserFromToken.mockReturnValue({ tenantId: "tenant-1", isTenantOwner: false });
    respond(false, {});
    render(<TenantPage />);
    await settled();
    expect(screen.getByText("Failed to fetch tenant information")).toBeTruthy();
    expect(info("Workspace ID")).toBe("tenant-1");
    expect(info("Members")).toBe("0");
  });

  it("shows the thrown error message when fetch rejects", async () => {
    getUserFromToken.mockReturnValue({ tenantId: "tenant-1", isTenantOwner: false });
    fetchMock.mockRejectedValue(new Error("network down"));
    render(<TenantPage />);
    await settled();
    expect(screen.getByText("network down")).toBeTruthy();
    expect(info("Workspace ID")).toBe("tenant-1");
  });

  it("shows a generic message when something other than an Error is thrown", async () => {
    getUserFromToken.mockReturnValue({ tenantId: "tenant-1", isTenantOwner: false });
    fetchMock.mockRejectedValue("not an error");
    render(<TenantPage />);
    await settled();
    expect(screen.getByText("Failed to fetch tenant info")).toBeTruthy();
  });

  it("shows N/A when the user loses the tenant before a failed fetch completes", async () => {
    getUserFromToken
      .mockReturnValueOnce({ tenantId: "tenant-1", isTenantOwner: false })
      .mockReturnValue(null);
    respond(false, {});
    render(<TenantPage />);
    await settled();
    expect(info("Workspace ID")).toBe("N/A");
  });

  it("offers invitations only to the tenant owner", async () => {
    getUserFromToken.mockReturnValue({ isTenantOwner: true });
    render(<TenantPage />);
    await settled();
    fireEvent.click(screen.getByText("Manage Invitations"));
    expect(router.push).toHaveBeenCalledWith("/admin/invitations");
  });

  it("hides invitations from a non-owner", async () => {
    getUserFromToken.mockReturnValue({ isTenantOwner: false });
    render(<TenantPage />);
    await settled();
    expect(screen.queryByText("Manage Invitations")).toBeNull();
  });

  it.each([
    ["View Members", "/admin/members"],
    ["Dashboard", "/dashboard"],
  ])("navigates from %s to %s", async (title, path) => {
    getUserFromToken.mockReturnValue({ isTenantOwner: false });
    render(<TenantPage />);
    await settled();
    fireEvent.click(screen.getByText(title));
    expect(router.push).toHaveBeenCalledWith(path);
  });

  it("logs out from the header", async () => {
    getUserFromToken.mockReturnValue({ isTenantOwner: false });
    render(<TenantPage />);
    await settled();
    fireEvent.click(screen.getByRole("button", { name: "Logout" }));
    expect(logout).toHaveBeenCalledTimes(1);
  });
});
