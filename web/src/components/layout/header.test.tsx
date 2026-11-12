import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SidebarProvider } from "@/components/ui/sidebar";
import { Header } from "./header";

const nav = vi.hoisted(() => ({ pathname: "/iam/users" }));
const push = vi.hoisted(() => vi.fn());
const logout = vi.hoisted(() => vi.fn());
const identity = vi.hoisted(() => ({
  value: { email: "ops@example.test", initial: "O", tenantId: "tenant-a" } as {
    email: string;
    initial: string;
    tenantId?: string;
  } | null,
}));

vi.mock("next/navigation", () => ({
  usePathname: () => nav.pathname,
  useRouter: () => ({ push, replace: vi.fn() }),
}));

vi.mock("@/hooks/use-logout", () => ({
  useLogout: () => logout,
}));

vi.mock("@/hooks/use-signed-in-identity", () => ({
  useSignedInIdentity: () => identity.value,
}));

function renderHeader() {
  return render(
    <SidebarProvider>
      <Header />
    </SidebarProvider>,
  );
}

function openAccountMenu() {
  fireEvent.keyDown(screen.getByTestId("header-account-menu"), { key: "Enter" });
}

describe("Header", () => {
  beforeEach(() => {
    nav.pathname = "/iam/users";
    identity.value = { email: "ops@example.test", initial: "O", tenantId: "tenant-a" };
    push.mockReset();
    logout.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("renders a banner with the breadcrumbs of the current path", () => {
    renderHeader();
    expect(screen.getByRole("banner")).toBeTruthy();
    expect(screen.getByRole("navigation", { name: "Breadcrumb" })).toBeTruthy();
    expect(screen.getByText("IAM").closest("a")?.getAttribute("href")).toBe("/iam");
  });

  it("renders no breadcrumbs on the home page", () => {
    nav.pathname = "/";
    renderHeader();
    expect(screen.queryByRole("navigation", { name: "Breadcrumb" })).toBeNull();
  });

  it("renders the search input", () => {
    renderHeader();
    const search = screen.getByPlaceholderText("Search...") as HTMLInputElement;
    expect(search.type).toBe("search");
    fireEvent.change(search, { target: { value: "tpm" } });
    expect(search.value).toBe("tpm");
  });

  it("shows the signed-in initial on the account button", () => {
    renderHeader();
    const trigger = screen.getByTestId("header-account-menu");
    expect(trigger.getAttribute("aria-label")).toBe("Account menu");
    expect(trigger.textContent).toBe("O");
  });

  it("shows the account email and tenant in the open menu", () => {
    renderHeader();
    openAccountMenu();
    expect(screen.getByTestId("header-account-email").textContent).toBe("ops@example.test");
    expect(screen.getByText("tenant-a")).toBeTruthy();
  });

  it("omits the tenant line when the identity has no tenant", () => {
    identity.value = { email: "solo@example.test", initial: "S" };
    renderHeader();
    openAccountMenu();
    expect(screen.getByTestId("header-account-email").textContent).toBe("solo@example.test");
    expect(screen.queryByText("tenant-a")).toBeNull();
  });

  it("renders an empty account when nobody is signed in", () => {
    identity.value = null;
    renderHeader();
    expect(screen.getByTestId("header-account-menu").textContent).toBe("");
    openAccountMenu();
    expect(screen.getByTestId("header-account-email").textContent).toBe("");
  });

  it("navigates to the profile page", () => {
    renderHeader();
    openAccountMenu();
    fireEvent.click(screen.getByText("Profile"));
    expect(push).toHaveBeenCalledWith("/profile");
  });

  it("navigates to the settings page", () => {
    renderHeader();
    openAccountMenu();
    fireEvent.click(screen.getByText("Settings"));
    expect(push).toHaveBeenCalledWith("/settings");
  });

  it("calls the logout handler when log out is chosen", () => {
    renderHeader();
    openAccountMenu();
    fireEvent.click(screen.getByText("Log out"));
    expect(logout).toHaveBeenCalledTimes(1);
    expect(push).not.toHaveBeenCalled();
  });
});
