import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "./app-sidebar";

const nav = vi.hoisted(() => ({ pathname: "/dashboard" as string | null }));
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
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}));

vi.mock("@/hooks/use-logout", () => ({
  useLogout: () => logout,
}));

vi.mock("@/hooks/use-signed-in-identity", () => ({
  useSignedInIdentity: () => identity.value,
}));

function renderSidebar(props: React.ComponentProps<typeof AppSidebar> = {}) {
  return render(
    <SidebarProvider>
      <AppSidebar {...props} />
    </SidebarProvider>,
  );
}

function openAccountMenu() {
  const trigger = screen.getByTestId("sidebar-account-menu");
  fireEvent.keyDown(trigger, { key: "Enter" });
}

describe("AppSidebar", () => {
  beforeEach(() => {
    nav.pathname = "/dashboard";
    identity.value = { email: "ops@example.test", initial: "O", tenantId: "tenant-a" };
    logout.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("renders the brand and every top-level navigation group", () => {
    renderSidebar();
    expect(screen.getByText("Trusted Platform")).toBeTruthy();
    for (const title of [
      "Dashboard",
      "Identity & Access",
      "Tenant",
      "Security",
      "Attestation",
      "TPM",
      "Devices",
      "Provisioning",
      "Compute",
      "Networking",
      "Data Storage",
      "Platform",
    ]) {
      expect(screen.getByText(title)).toBeTruthy();
    }
  });

  it("links the dashboard entry and marks it active on its own path", () => {
    renderSidebar();
    const link = screen.getByText("Dashboard").closest("a");
    expect(link?.getAttribute("href")).toBe("/dashboard");
    expect(link?.getAttribute("data-active")).toBe("true");
  });

  it("does not mark the dashboard active on another path", () => {
    nav.pathname = "/tenant";
    renderSidebar();
    const link = screen.getByText("Dashboard").closest("a");
    expect(link?.getAttribute("data-active")).toBe("false");
  });

  it("opens the group holding the active child and marks only that child active", () => {
    nav.pathname = "/iam/roles";
    renderSidebar();
    const roles = screen.getByText("Roles").closest("a");
    expect(roles?.getAttribute("href")).toBe("/iam/roles");
    expect(roles?.getAttribute("data-active")).toBe("true");
    const users = screen.getByText("Users").closest("a");
    expect(users?.getAttribute("href")).toBe("/iam/users");
    expect(users?.getAttribute("data-active")).toBe("false");
  });

  it("keeps groups without an active child closed", () => {
    nav.pathname = "/iam/roles";
    renderSidebar();
    expect(screen.queryByText("Virtual Machines")).toBeNull();
    expect(screen.queryByText("PXE Boot")).toBeNull();
  });

  it("opens a closed group when its trigger is clicked", () => {
    renderSidebar();
    expect(screen.queryByText("Virtual Machines")).toBeNull();
    fireEvent.click(screen.getByText("Compute"));
    const vms = screen.getByText("Virtual Machines").closest("a");
    expect(vms?.getAttribute("href")).toBe("/compute/vms");
  });

  it("opens no group for an unknown or missing path", () => {
    nav.pathname = "/no/such/page";
    const { unmount } = renderSidebar();
    expect(screen.queryByText("Users")).toBeNull();
    expect(screen.getByText("Dashboard").closest("a")?.getAttribute("data-active")).toBe("false");
    unmount();

    nav.pathname = null;
    renderSidebar();
    expect(screen.queryByText("Users")).toBeNull();
    expect(screen.getByText("Dashboard").closest("a")?.getAttribute("data-active")).toBe("false");
  });

  it("shows the signed-in account and its tenant in the footer", () => {
    renderSidebar();
    expect(screen.getByTestId("sidebar-account-email").textContent).toBe("ops@example.test");
    expect(screen.getByText("tenant-a")).toBeTruthy();
    expect(screen.getByText("O")).toBeTruthy();
  });

  it("omits the tenant line when the identity has no tenant", () => {
    identity.value = { email: "solo@example.test", initial: "S" };
    renderSidebar();
    expect(screen.getByTestId("sidebar-account-email").textContent).toBe("solo@example.test");
    expect(screen.queryByText("tenant-a")).toBeNull();
  });

  it("renders an empty account button when nobody is signed in", () => {
    identity.value = null;
    renderSidebar();
    expect(screen.getByTestId("sidebar-account-email").textContent).toBe("");
    expect(screen.getByLabelText("Account menu")).toBeTruthy();
  });

  it("opens the account menu with profile, settings and log out entries", () => {
    renderSidebar();
    openAccountMenu();
    expect(screen.getByText("My Account")).toBeTruthy();
    expect(screen.getByText("Profile").closest("a")?.getAttribute("href")).toBe("/profile");
    expect(screen.getByText("Settings").closest("a")?.getAttribute("href")).toBe("/settings");
    expect(screen.getByText("Log out")).toBeTruthy();
  });

  it("calls the logout handler when log out is chosen", () => {
    renderSidebar();
    openAccountMenu();
    fireEvent.click(screen.getByText("Log out"));
    expect(logout).toHaveBeenCalledTimes(1);
  });

  it("passes its props through to the sidebar", () => {
    renderSidebar({ className: "custom-sidebar-class" } as React.ComponentProps<typeof AppSidebar>);
    expect(document.querySelector(".custom-sidebar-class")).not.toBeNull();
  });
});
