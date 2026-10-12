import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { AuthProvider, type User } from "@/contexts/AuthContext";
import { SidebarProvider } from "@/components/ui/sidebar";
import { signedInIdentity } from "@/hooks/use-signed-in-identity";
import { AppSidebar } from "./app-sidebar";
import { Header } from "./header";

// #643: the console shell shows the account the session belongs to, taken
// from the JWT claims, never a "User" / user@example.com placeholder.

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => "/dashboard",
}));

function jwtFor(payload: Record<string, unknown>): string {
  const b64 = (o: Record<string, unknown>) =>
    Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "none", typ: "JWT" })}.${b64(payload)}.sig`;
}

const sessionToken = jwtFor({
  sub: "user-7",
  email: "jhahn@example.com",
  tenant_id: "tenant-42",
  is_tenant_owner: true,
  roles: ["admin"],
  exp: Math.floor(Date.now() / 1000) + 3600,
});

function renderShell() {
  return render(
    <AuthProvider>
      <SidebarProvider>
        <AppSidebar />
        <Header />
      </SidebarProvider>
    </AuthProvider>
  );
}

// floating-ui asks every ancestor of the open account menu whether it is in
// the top layer via `matches(":modal")`. jsdom's selector engine answers
// `:modal` by testing `:fullscreen` across the document — about 80 million
// calls, nine seconds of CPU. jsdom implements neither fullscreen nor
// showModal(), so nothing is ever modal; answer the probe directly.
const nativeMatches = Element.prototype.matches;

describe("console shell identity", () => {
  beforeAll(() => {
    Element.prototype.matches = function (this: Element, selector: string) {
      return selector === ":modal" ? false : nativeMatches.call(this, selector);
    };
  });

  afterAll(() => {
    Element.prototype.matches = nativeMatches;
  });

  afterEach(() => {
    cleanup();
    document.cookie = "jwt=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
  });

  it("shows the authenticated subject in the sidebar and header", async () => {
    document.cookie = `jwt=${sessionToken}; path=/`;
    renderShell();

    const sidebarEmail = await screen.findByTestId("sidebar-account-email");
    expect(sidebarEmail.textContent).toBe("jhahn@example.com");

    fireEvent.keyDown(screen.getByTestId("header-account-menu"), { key: "Enter" });
    const headerEmail = await screen.findByTestId("header-account-email");
    expect(headerEmail.textContent).toBe("jhahn@example.com");
    expect(screen.getAllByText("tenant-42").length).toBeGreaterThan(0);
    expect(screen.queryByText("user@example.com")).toBeNull();
  });

  it("shows no placeholder identity without a session", () => {
    renderShell();

    expect(screen.getByTestId("sidebar-account-email").textContent).toBe("");
    expect(screen.queryByText("user@example.com")).toBeNull();
    expect(screen.queryByText("User")).toBeNull();
  });
});

describe("signedInIdentity", () => {
  const user: User = {
    id: "user-7",
    email: "jhahn@example.com",
    tenantId: "tenant-42",
    isTenantOwner: true,
    roles: ["admin"],
  };

  it("maps the session user to the shell identity", () => {
    expect(signedInIdentity(user)).toEqual({
      email: "jhahn@example.com",
      tenantId: "tenant-42",
      initial: "J",
    });
  });

  it("returns null without a user or an email claim", () => {
    expect(signedInIdentity(null)).toBeNull();
    expect(signedInIdentity({ ...user, email: "" })).toBeNull();
  });
});
