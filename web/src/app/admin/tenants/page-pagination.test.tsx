import * as React from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import AdminTenantsPage from "./page";

// #2023 Codex P1: Previous stays enabled while the Next page is loading, so a
// superseded page response that settles last must not replace the page the
// user selected, and the page info must describe the page that is shown.

vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) => <a href={href}>{children}</a>,
}));

const tenantSvc = vi.hoisted(() => ({
  listTenants: vi.fn(),
  createTenant: vi.fn(),
  getTenantByName: vi.fn(),
  deleteTenant: vi.fn(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useTenant: () => tenantSvc,
}));

type Page = { success: boolean; data: { tenants: Array<Record<string, unknown>>; total: number } };

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

const TOTAL = 150;

function page(at: number, count: number): Page {
  const tenants = Array.from({ length: count }, (_, i) => ({
    id: `t-${at + i}`,
    name: `tenant-${at + i}`,
    displayName: `Tenant ${at + i}`,
    state: 1,
  }));
  return { success: true, data: { tenants, total: TOTAL } };
}

// Every listTenants call parks on a deferred response, keyed by call order.
function deferredPages() {
  const calls: Array<{ offset: number; resolve: (p: Page) => void }> = [];
  tenantSvc.listTenants.mockImplementation(({ offset }: { offset: number }) => {
    const d = deferred<Page>();
    calls.push({ offset, resolve: d.resolve });
    return d.promise;
  });
  return calls;
}

async function settle(resolve: (p: Page) => void, p: Page) {
  await act(async () => {
    resolve(p);
  });
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name }));
  });
}

describe("AdminTenantsPage pagination", () => {
  beforeEach(() => {
    for (const fn of Object.values(tenantSvc)) fn.mockReset();
  });
  afterEach(() => cleanup());

  it("keeps the selected page when an earlier page request settles last", async () => {
    const calls = deferredPages();
    await act(async () => {
      render(<AdminTenantsPage />);
    });
    await settle(calls[0].resolve, page(0, 100));
    expect(screen.getByTestId("tenant-page-info").textContent).toBe("Showing 1-100 of 150");

    await click("Next");
    await click("Previous");
    const next = calls.find((c, i) => i > 0 && c.offset === 100);
    const prev = calls.slice(1).reverse().find((c) => c.offset === 0);
    expect(next).toBeTruthy();
    expect(prev).toBeTruthy();
    await settle(prev!.resolve, page(0, 100));
    await settle(next!.resolve, page(100, 50));

    expect(screen.getByTestId("tenant-page-info").textContent).toBe("Showing 1-100 of 150");
    expect(screen.getByTestId("tenant-row-t-0")).toBeTruthy();
    expect(screen.queryByTestId("tenant-row-t-100")).toBeNull();
    expect((screen.getByRole("button", { name: "Previous" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows page two when the page requests settle in order", async () => {
    const calls = deferredPages();
    await act(async () => {
      render(<AdminTenantsPage />);
    });
    await settle(calls[0].resolve, page(0, 100));
    await click("Next");
    const next = calls.find((c, i) => i > 0 && c.offset === 100);
    expect(next).toBeTruthy();
    await settle(next!.resolve, page(100, 50));

    expect(screen.getByTestId("tenant-page-info").textContent).toBe("Showing 101-150 of 150");
    expect(screen.getByTestId("tenant-row-t-100")).toBeTruthy();
    expect(screen.queryByTestId("tenant-row-t-0")).toBeNull();
    expect((screen.getByRole("button", { name: "Previous" }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole("button", { name: "Next" }) as HTMLButtonElement).disabled).toBe(true);
  });
});
