import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Breadcrumbs } from "./breadcrumbs";

const nav = vi.hoisted(() => ({ pathname: "/" }));

vi.mock("next/navigation", () => ({
  usePathname: () => nav.pathname,
}));

function renderAt(pathname: string) {
  nav.pathname = pathname;
  return render(<Breadcrumbs />);
}

function links() {
  return Array.from(document.querySelectorAll("nav a")).map((a) => [
    a.textContent,
    a.getAttribute("href"),
  ]);
}

describe("Breadcrumbs", () => {
  afterEach(() => {
    cleanup();
  });

  it("renders nothing on the home page", () => {
    const { container } = renderAt("/");
    expect(container.innerHTML).toBe("");
  });

  it("renders nothing for an empty pathname", () => {
    const { container } = renderAt("");
    expect(container.innerHTML).toBe("");
  });

  it("renders nothing for a pathname of slashes only", () => {
    const { container } = renderAt("///");
    expect(container.innerHTML).toBe("");
  });

  it("renders Home and the current page for a single segment", () => {
    renderAt("/dashboard");
    expect(screen.getByRole("navigation", { name: "Breadcrumb" })).toBeTruthy();
    expect(links()).toEqual([["Home", "/"]]);
    const current = screen.getByText("Dashboard");
    expect(current.tagName).toBe("SPAN");
  });

  it("links every ancestor with its accumulated path and leaves the last unlinked", () => {
    renderAt("/iam/users/123");
    expect(links()).toEqual([
      ["Home", "/"],
      ["IAM", "/iam"],
      ["Users", "/iam/users"],
    ]);
    expect(screen.getByText("123").tagName).toBe("SPAN");
  });

  it("ignores leading, trailing and doubled slashes", () => {
    renderAt("//networking//sdn/");
    expect(links()).toEqual([
      ["Home", "/"],
      ["Networking", "/networking"],
    ]);
    expect(screen.getByText("SDN").tagName).toBe("SPAN");
  });

  it("upper-cases known acronyms whatever their case", () => {
    renderAt("/Ca/KMS/api/dns/pxe/vm/vms");
    for (const label of ["CA", "KMS", "API", "DNS", "PXE", "VM", "VMS"]) {
      expect(screen.getByText(label)).toBeTruthy();
    }
  });

  it("turns hyphens and underscores into spaces and capitalises each word", () => {
    renderAt("/storage/backup-and_restore");
    expect(screen.getByText("Backup And Restore").tagName).toBe("SPAN");
  });

  it("keeps acronyms inside multi-word segments upper-case", () => {
    renderAt("/iam-api_keys");
    expect(screen.getByText("IAM API Keys")).toBeTruthy();
  });

  it("keeps the rest of a word as written", () => {
    renderAt("/tpm/eventLog");
    expect(screen.getByText("Tpm").tagName).toBe("A");
    expect(screen.getByText("EventLog").tagName).toBe("SPAN");
  });

  it("re-renders the trail when the pathname changes", () => {
    const { rerender } = renderAt("/tenant");
    expect(screen.getByText("Tenant").tagName).toBe("SPAN");
    nav.pathname = "/tenant/members";
    rerender(<Breadcrumbs />);
    expect(screen.getByText("Tenant").tagName).toBe("A");
    expect(screen.getByText("Members").tagName).toBe("SPAN");
  });
});
