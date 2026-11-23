import { cleanup, render, screen } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { AuthProvider } from "@/contexts/AuthContext";
import { SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "./app-sidebar";

// #2061: the proxy routes and pools pages are reachable from the sidebar,
// under Networking.

let pathname = "/networking/proxy";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => pathname,
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

// floating-ui asks every ancestor of the open account menu whether it is in
// the top layer via `matches(":modal")`. jsdom's selector engine answers
// `:modal` by testing `:fullscreen` across the document, which burns seconds
// of CPU. jsdom implements neither fullscreen nor showModal(), so nothing is
// ever modal; answer the probe directly.
const nativeMatches = Element.prototype.matches;

describe("sidebar: proxy pages", () => {
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

  it("links the proxy routes page under Networking", () => {
    pathname = "/networking/proxy";
    renderSidebar();

    const link = screen.getByRole("link", { name: "Proxy Routes" });
    expect(link.getAttribute("href")).toBe("/networking/proxy");
  });

  it("links the proxy pools page under Networking", () => {
    pathname = "/networking/proxy/pools";
    renderSidebar();

    const link = screen.getByRole("link", { name: "Proxy Pools" });
    expect(link.getAttribute("href")).toBe("/networking/proxy/pools");
  });
});
