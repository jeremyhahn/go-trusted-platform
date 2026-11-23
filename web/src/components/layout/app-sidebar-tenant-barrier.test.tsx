import { cleanup, render, screen } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { AuthProvider } from "@/contexts/AuthContext";
import { SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "./app-sidebar";

// #2067: the tenant barrier page, /tenant/barrier, is reachable from the
// sidebar's Tenant group like the other tenant pages.

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => "/tenant/barrier",
}));

function renderSidebar() {
  return render(
    <AuthProvider>
      <SidebarProvider>
        <AppSidebar />
      </SidebarProvider>
    </AuthProvider>
  );
}

// jsdom answers `matches(":modal")` very slowly and nothing is ever modal
// there; answer the probe directly (see account-identity.test.tsx).
const nativeMatches = Element.prototype.matches;

describe("AppSidebar tenant barrier entry", () => {
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
  });

  it("lists Barrier under Tenant, linking to /tenant/barrier", () => {
    renderSidebar();

    // The Tenant group opens by itself only when one of its children is the
    // active path, so the link is in the document only if the entry exists.
    const link = screen.getByRole("link", { name: "Barrier" });
    expect(link.getAttribute("href")).toBe("/tenant/barrier");
  });

  it("marks the Barrier entry active on /tenant/barrier", () => {
    renderSidebar();

    // SidebarMenuSubButton marks the active entry with the bg-neutral-200
    // class (no data attribute); the inactive siblings do not carry it.
    const link = screen.getByRole("link", { name: "Barrier" });
    expect(link.classList.contains("bg-neutral-200")).toBe(true);
    const quotas = screen.getByRole("link", { name: "Quotas" });
    expect(quotas.classList.contains("bg-neutral-200")).toBe(false);
  });
});
