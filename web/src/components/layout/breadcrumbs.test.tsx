import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Breadcrumbs } from "./breadcrumbs";

// #1819: unit tests for the header breadcrumbs: one crumb per path segment,
// the last one plain text, labels formatted from the URL segment.

const nav = vi.hoisted(() => ({ pathname: "/" }));

vi.mock("next/navigation", () => ({
  usePathname: () => nav.pathname,
}));

function renderAt(pathname: string) {
  nav.pathname = pathname;
  return render(<Breadcrumbs />);
}

function crumbs(): string[] {
  const navEl = screen.getByRole("navigation", { name: "Breadcrumb" });
  return Array.from(navEl.querySelectorAll("a, span")).map(
    (el) => el.textContent ?? ""
  );
}

describe("Breadcrumbs", () => {
  beforeEach(() => {
    nav.pathname = "/";
  });

  afterEach(() => {
    cleanup();
  });

  it("renders nothing on the home page", () => {
    const { container } = renderAt("/");
    expect(container.innerHTML).toBe("");
  });

  it("renders nothing for an empty path", () => {
    const { container } = renderAt("");
    expect(container.innerHTML).toBe("");
  });

  it("renders nothing for a path of slashes only", () => {
    const { container } = renderAt("///");
    expect(container.innerHTML).toBe("");
  });

  it("links Home and shows a single segment as the current page", () => {
    renderAt("/dashboard");

    expect(screen.getByText("Home").getAttribute("href")).toBe("/");
    const current = screen.getByText("Dashboard");
    expect(current.tagName).toBe("SPAN");
    expect(current.closest("a")).toBeNull();
  });

  it("links every ancestor segment with its accumulated path", () => {
    renderAt("/networking/overlays/vteps");

    expect(crumbs()).toEqual(["Home", "Networking", "Overlays", "Vteps"]);
    expect(screen.getByText("Networking").getAttribute("href")).toBe(
      "/networking"
    );
    expect(screen.getByText("Overlays").getAttribute("href")).toBe(
      "/networking/overlays"
    );
    expect(screen.getByText("Vteps").tagName).toBe("SPAN");
  });

  it("ignores leading, trailing and doubled slashes", () => {
    renderAt("//iam//users/");

    expect(crumbs()).toEqual(["Home", "IAM", "Users"]);
    expect(screen.getByText("IAM").getAttribute("href")).toBe("/iam");
  });

  it("upper-cases the known acronyms in any case", () => {
    renderAt("/IAM/Api/ca/kms/sdn/dns/pxe/vm/vms");

    expect(crumbs()).toEqual([
      "Home",
      "IAM",
      "API",
      "CA",
      "KMS",
      "SDN",
      "DNS",
      "PXE",
      "VM",
      "VMS",
    ]);
  });

  it("splits hyphens and underscores into capitalised words", () => {
    renderAt("/compute/virtual-machines/key_value-store");

    expect(crumbs()).toEqual([
      "Home",
      "Compute",
      "Virtual Machines",
      "Key Value Store",
    ]);
  });

  it("formats acronyms inside multi-word segments", () => {
    renderAt("/networking/dns-zones");

    expect(screen.getByText("DNS Zones").tagName).toBe("SPAN");
  });

  it("keeps the rest of a word as written", () => {
    // tpm is not in the acronym list, so it is only capitalised.
    renderAt("/tpm/eventLog");

    expect(crumbs()).toEqual(["Home", "Tpm", "EventLog"]);
  });

  it("does not treat an acronym as a prefix", () => {
    renderAt("/cache/vmware");

    expect(crumbs()).toEqual(["Home", "Cache", "Vmware"]);
  });

  it("leaves digits and other characters unchanged", () => {
    renderAt("/devices/42/%20x");

    expect(crumbs()).toEqual(["Home", "Devices", "42", "%20x"]);
    expect(screen.getByText("42").getAttribute("href")).toBe("/devices/42");
  });
});
