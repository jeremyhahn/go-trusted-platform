import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthProvider } from "@/contexts/AuthContext";
import { SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "./app-sidebar";

// #2042: the bootstrap ceremony status page is reachable from the Platform
// group of the console sidebar.

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => "/platform/ceremony",
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

describe("AppSidebar ceremony entry (#2042)", () => {
  afterEach(() => {
    cleanup();
  });

  it("lists the bootstrap ceremony page under Platform", () => {
    renderSidebar();
    const link = screen.getByRole("link", { name: "Bootstrap Ceremony" });
    expect(link).toHaveAttribute("href", "/platform/ceremony");
  });

  it("marks the entry active on the ceremony page", () => {
    renderSidebar();
    const link = screen.getByRole("link", { name: "Bootstrap Ceremony" });
    expect(link).toHaveClass("bg-neutral-200");
    const health = screen.getByRole("link", { name: "Health" });
    expect(health).not.toHaveClass("bg-neutral-200");
  });
});
