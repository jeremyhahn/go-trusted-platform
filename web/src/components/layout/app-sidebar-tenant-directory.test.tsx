import { cleanup, render, screen } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { AuthProvider } from "@/contexts/AuthContext";
import { SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "./app-sidebar";

// #2067: the tenant directory page, /tenant/directory, is reachable from the
// sidebar's Tenant group like the other tenant pages.

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => "/tenant/directory",
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

describe("AppSidebar tenant directory entry", () => {
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

  it("lists Directory under Tenant, linking to /tenant/directory", () => {
    renderSidebar();

    // The Tenant group opens by itself only when one of its children is the
    // active path, so the link is in the document only if the entry exists.
    const link = screen.getByRole("link", { name: "Directory" });
    expect(link.getAttribute("href")).toBe("/tenant/directory");
  });

  it("marks the Directory entry active on /tenant/directory", () => {
    renderSidebar();

    const link = screen.getByRole("link", { name: "Directory" });
    expect(link.classList.contains("bg-neutral-200")).toBe(true);
    const barrier = screen.getByRole("link", { name: "Barrier" });
    expect(barrier.classList.contains("bg-neutral-200")).toBe(false);
  });
});
