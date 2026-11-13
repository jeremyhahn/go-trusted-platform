import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { SidebarProvider } from "@/components/ui/sidebar";
import type { SignedInIdentity } from "@/hooks/use-signed-in-identity";
import { AppSidebar } from "./app-sidebar";

// #1819: unit tests for the console sidebar: navigation, active state,
// collapsible groups and the account menu in the footer.

const nav = vi.hoisted(() => ({ pathname: "/dashboard" }));
const logout = vi.hoisted(() => vi.fn());
const identity = vi.hoisted(() => ({
  current: null as SignedInIdentity | null,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => nav.pathname,
}));

vi.mock("@/hooks/use-logout", () => ({
  useLogout: () => logout,
}));

vi.mock("@/hooks/use-signed-in-identity", () => ({
  useSignedInIdentity: () => identity.current,
}));

function renderSidebar(props: React.ComponentProps<typeof AppSidebar> = {}) {
  return render(
    <SidebarProvider>
      <AppSidebar {...props} />
    </SidebarProvider>
  );
}

// The menu buttons mark the active entry with the highlight class, not a
// data attribute.
function activeOf(el: Element | null): boolean {
  if (!el) throw new Error("navigation link not found");
  return el.classList.contains("bg-neutral-200");
}

function openAccountMenu() {
  const trigger = screen.getByTestId("sidebar-account-menu");
  fireEvent.keyDown(trigger, { key: "Enter" });
}

// floating-ui probes `matches(":modal")` on every ancestor of an open menu,
// which jsdom answers very slowly; nothing is ever modal in jsdom.
const nativeMatches = Element.prototype.matches;

describe("AppSidebar", () => {
  beforeAll(() => {
    Element.prototype.matches = function (this: Element, selector: string) {
      return selector === ":modal" ? false : nativeMatches.call(this, selector);
    };
  });

  afterAll(() => {
    Element.prototype.matches = nativeMatches;
  });

  beforeEach(() => {
    nav.pathname = "/dashboard";
    identity.current = {
      email: "operator@example.com",
      tenantId: "tenant-42",
      initial: "O",
    };
    logout.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("renders the brand and every top-level navigation entry", () => {
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

  it("links the single Dashboard entry and marks it active on its path", () => {
    renderSidebar();

    const link = screen.getByText("Dashboard").closest("a");
    expect(link?.getAttribute("href")).toBe("/dashboard");
    expect(activeOf(link)).toBe(true);
  });

  it("does not mark Dashboard active on another path", () => {
    nav.pathname = "/iam/users";
    renderSidebar();

    const link = screen.getByText("Dashboard").closest("a");
    expect(activeOf(link)).toBe(false);
  });

  it("keeps groups closed when no child is active", () => {
    renderSidebar();

    expect(screen.queryByText("Users")).toBeNull();
    expect(screen.queryByText("Certificates")).toBeNull();
  });

  it("opens the group holding the active child and marks only that child", () => {
    nav.pathname = "/iam/users";
    renderSidebar();

    const users = screen.getByText("Users").closest("a");
    expect(users?.getAttribute("href")).toBe("/iam/users");
    expect(activeOf(users)).toBe(true);

    const roles = screen.getByText("Roles").closest("a");
    expect(roles?.getAttribute("href")).toBe("/iam/roles");
    expect(activeOf(roles)).toBe(false);

    // Other groups stay closed.
    expect(screen.queryByText("Certificates")).toBeNull();
  });

  it("matches the active path exactly, not by prefix", () => {
    nav.pathname = "/networking/overlays/vteps";
    renderSidebar();

    const vteps = screen.getByText("VTEPs").closest("a");
    expect(activeOf(vteps)).toBe(true);
    const overlays = screen.getByText("Overlays").closest("a");
    expect(activeOf(overlays)).toBe(false);
  });

  it("opens no group for an unknown path", () => {
    nav.pathname = "/no/such/page";
    renderSidebar();

    expect(screen.queryByText("Users")).toBeNull();
    expect(activeOf(screen.getByText("Dashboard").closest("a"))).toBe(false);
  });

  it("opens a closed group when its trigger is clicked", () => {
    renderSidebar();

    fireEvent.click(screen.getByText("Security"));

    expect(
      screen.getByText("Certificates").closest("a")?.getAttribute("href")
    ).toBe("/ca/certificates");
    expect(
      screen.getByText("Key Management").closest("a")?.getAttribute("href")
    ).toBe("/kms");
  });

  it("shows the signed-in account in the footer", () => {
    renderSidebar();

    expect(screen.getByTestId("sidebar-account-email").textContent).toBe(
      "operator@example.com"
    );
    expect(screen.getByText("tenant-42")).toBeTruthy();
    expect(screen.getByText("O")).toBeTruthy();
  });

  it("omits the tenant line when the identity has no tenant", () => {
    identity.current = { email: "solo@example.com", tenantId: null, initial: "S" };
    renderSidebar();

    expect(screen.getByTestId("sidebar-account-email").textContent).toBe(
      "solo@example.com"
    );
    expect(screen.queryByText("tenant-42")).toBeNull();
  });

  it("renders an empty account line when nobody is signed in", () => {
    identity.current = null;
    renderSidebar();

    expect(screen.getByTestId("sidebar-account-email").textContent).toBe("");
    expect(screen.queryByText("tenant-42")).toBeNull();
  });

  it("offers profile, settings and log out in the account menu", () => {
    renderSidebar();
    openAccountMenu();

    expect(screen.getByText("My Account")).toBeTruthy();
    expect(screen.getByText("Profile").closest("a")?.getAttribute("href")).toBe(
      "/profile"
    );
    expect(
      screen.getByText("Settings").closest("a")?.getAttribute("href")
    ).toBe("/settings");
  });

  it("logs out from the account menu", () => {
    renderSidebar();
    openAccountMenu();

    fireEvent.click(screen.getByText("Log out"));
    expect(logout).toHaveBeenCalledTimes(1);
  });

  it("passes extra props through to the sidebar", () => {
    renderSidebar({ className: "custom-sidebar" });

    expect(document.querySelector(".custom-sidebar")).not.toBeNull();
  });
});
