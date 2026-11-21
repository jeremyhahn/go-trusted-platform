import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthProvider } from "@/contexts/AuthContext";
import { SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "./app-sidebar";

// #2043: the Cluster page at /platform/cluster is reachable from the
// sidebar's Platform group, not only by typing its URL.

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => "/platform/cluster",
}));

function renderShell() {
  return render(
    <AuthProvider>
      <SidebarProvider>
        <AppSidebar />
      </SidebarProvider>
    </AuthProvider>
  );
}

describe("sidebar Platform group", () => {
  afterEach(() => {
    cleanup();
  });

  it("links to the Cluster page", () => {
    renderShell();

    const link = screen.getByRole("link", { name: "Cluster" });
    expect(link.getAttribute("href")).toBe("/platform/cluster");
  });

  it("lists Cluster between Services and Configuration", () => {
    renderShell();

    const services = screen.getByRole("link", { name: "Services" });
    const cluster = screen.getByRole("link", { name: "Cluster" });
    const config = screen.getByRole("link", { name: "Configuration" });

    expect(
      services.compareDocumentPosition(cluster) & Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();
    expect(
      cluster.compareDocumentPosition(config) & Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();
  });
});
