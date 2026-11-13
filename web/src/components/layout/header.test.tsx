import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { SidebarProvider } from "@/components/ui/sidebar";
import type { SignedInIdentity } from "@/hooks/use-signed-in-identity";
import { Header } from "./header";

// #1819: unit tests for the console header: breadcrumbs, search, theme
// toggle and the account menu with its navigation and log out.

const nav = vi.hoisted(() => ({ pathname: "/dashboard", push: vi.fn() }));
const logout = vi.hoisted(() => vi.fn());
const identity = vi.hoisted(() => ({
  current: null as SignedInIdentity | null,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: nav.push, replace: vi.fn() }),
  usePathname: () => nav.pathname,
}));

vi.mock("@/hooks/use-logout", () => ({
  useLogout: () => logout,
}));

vi.mock("@/hooks/use-signed-in-identity", () => ({
  useSignedInIdentity: () => identity.current,
}));

function renderHeader() {
  return render(
    <SidebarProvider>
      <Header />
    </SidebarProvider>
  );
}

function openAccountMenu() {
  fireEvent.keyDown(screen.getByTestId("header-account-menu"), {
    key: "Enter",
  });
}

// floating-ui probes `matches(":modal")` on every ancestor of an open menu,
// which jsdom answers very slowly; nothing is ever modal in jsdom.
const nativeMatches = Element.prototype.matches;

describe("Header", () => {
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
    nav.push.mockReset();
    logout.mockReset();
    identity.current = {
      email: "operator@example.com",
      tenantId: "tenant-42",
      initial: "O",
    };
  });

  afterEach(() => {
    cleanup();
  });

  it("renders a banner with the breadcrumbs of the current path", () => {
    nav.pathname = "/iam/users";
    renderHeader();

    expect(screen.getByRole("banner")).toBeTruthy();
    expect(screen.getByRole("navigation", { name: "Breadcrumb" })).toBeTruthy();
    expect(screen.getByText("IAM").getAttribute("href")).toBe("/iam");
    expect(screen.getByText("Users").tagName).toBe("SPAN");
  });

  it("renders no breadcrumbs on the home page", () => {
    nav.pathname = "/";
    renderHeader();

    expect(screen.queryByRole("navigation", { name: "Breadcrumb" })).toBeNull();
  });

  it("offers a search box that accepts input", () => {
    renderHeader();

    const search = screen.getByPlaceholderText("Search...") as HTMLInputElement;
    expect(search.type).toBe("search");
    fireEvent.change(search, { target: { value: "tpm" } });
    expect(search.value).toBe("tpm");
  });

  it("renders the sidebar trigger and the theme toggle", () => {
    renderHeader();

    expect(screen.getByText("Toggle Sidebar")).toBeTruthy();
    expect(screen.getAllByText("Toggle theme").length).toBeGreaterThan(0);
  });

  it("shows the account initial on the menu button", () => {
    renderHeader();

    const button = screen.getByTestId("header-account-menu");
    expect(button.getAttribute("aria-label")).toBe("Account menu");
    expect(button.textContent).toBe("O");
  });

  it("shows the account email and tenant in the open menu", () => {
    renderHeader();
    openAccountMenu();

    expect(screen.getByTestId("header-account-email").textContent).toBe(
      "operator@example.com"
    );
    expect(screen.getByText("tenant-42")).toBeTruthy();
  });

  it("omits the tenant line when the identity has no tenant", () => {
    identity.current = { email: "solo@example.com", tenantId: null, initial: "S" };
    renderHeader();
    openAccountMenu();

    expect(screen.getByTestId("header-account-email").textContent).toBe(
      "solo@example.com"
    );
    expect(screen.queryByText("tenant-42")).toBeNull();
  });

  it("renders an empty account when nobody is signed in", () => {
    identity.current = null;
    renderHeader();

    expect(screen.getByTestId("header-account-menu").textContent).toBe("");
    openAccountMenu();
    expect(screen.getByTestId("header-account-email").textContent).toBe("");
  });

  it("navigates to the profile page", () => {
    renderHeader();
    openAccountMenu();

    fireEvent.click(screen.getByText("Profile"));
    expect(nav.push).toHaveBeenCalledWith("/profile");
    expect(logout).not.toHaveBeenCalled();
  });

  it("navigates to the settings page", () => {
    renderHeader();
    openAccountMenu();

    fireEvent.click(screen.getByText("Settings"));
    expect(nav.push).toHaveBeenCalledWith("/settings");
  });

  it("logs out from the account menu", () => {
    renderHeader();
    openAccountMenu();

    fireEvent.click(screen.getByText("Log out"));
    expect(logout).toHaveBeenCalledTimes(1);
    expect(nav.push).not.toHaveBeenCalled();
  });
});
