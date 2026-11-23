import React from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformProvider } from "trusted-platform-sdk";

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from "@/test/control-plane-fetch";
import { PermissionCheckCard } from "./permission-check-card";

// #2033 item 5: Gated reads the server's capabilities through this hook; the card's own requests stay on the control-plane stub.
const caps = vi.hoisted(() => ({ capability: vi.fn() }));
vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({ loading: false, error: undefined, capability: caps.capability }),
}));

/**
 * PermissionCheckCard shows a verdict only for the tenant and the inputs
 * that were checked, and never a previous verdict while a new check runs
 * or after a check fails. The card runs on the real SDK hooks and client
 * over the control-plane fetch stub, so each answer is a REST envelope
 * (#2127 Codex round 2).
 */

const route = "POST /api/v1/iam/tenants/t-1/permissions/check";
const checkOp = "POST /api/v1/iam/tenants/{tenant}/permissions/check";

function fill(subject: string, action: string, resource: string) {
  fireEvent.change(screen.getByLabelText("Subject ID"), { target: { value: subject } });
  fireEvent.change(screen.getByLabelText("Action"), { target: { value: action } });
  fireEvent.change(screen.getByLabelText("Resource"), { target: { value: resource } });
}

async function submit() {
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /Check/ }));
  });
}

/** Mounts on an SDK client that does not retry, so failures settle at once. */
function withNoRetry(children: React.ReactNode) {
  return (
    <PlatformProvider
      config={{
        baseUrl: "https://control-plane.test/api",
        retry: { maxRetries: 0, retryOnNetworkError: false },
      }}
    >
      <>{children}</>
    </PlatformProvider>
  );
}

function answer(a: Answer): Response {
  return new Response(JSON.stringify(a.body), {
    status: a.status,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * The SDK client keeps the fetch it was built with, so a test that changes
 * the answer mid-test installs one delegating fetch: serve runs setup (which
 * stubs fetch), takes that stub as the current handler and puts the
 * delegator back.
 */
let current: typeof fetch;
function serve(setup: () => unknown) {
  setup();
  current = globalThis.fetch;
  vi.stubGlobal("fetch", (input: RequestInfo | URL, init?: RequestInit) => current(input, init));
}

function stubNetworkFailure() {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw new TypeError("fetch failed");
    })
  );
}

describe("PermissionCheckCard", () => {
  beforeEach(() => {
    caps.capability.mockReset();
    caps.capability.mockImplementation(() => ({ enabled: true }));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("shows the verdict for the inputs that were checked", async () => {
    const sent = stubControlPlane({ [route]: ok({ allowed: true, matched_policy: "p-1" }) });
    render(withControlPlane(<PermissionCheckCard tenantId="t-1" />));

    fill("u-1", "read", "fleet");
    await submit();

    expect(await screen.findByText("Allowed")).toBeDefined();
    expect(sent).toHaveLength(1);
    expect(sent[0].path).toBe("/api/v1/iam/tenants/t-1/permissions/check");
    expect(sent[0].body).toEqual({ subject_id: "u-1", action: "read", resource: "fleet" });
  });

  it("shows the matched policy from the REST envelope", async () => {
    stubControlPlane({ [route]: ok({ allowed: true, matched_policy: "p-1" }) });
    render(withControlPlane(<PermissionCheckCard tenantId="t-1" />));

    fill("u-1", "read", "fleet");
    await submit();

    expect(await screen.findByText("Allowed")).toBeDefined();
    expect(await screen.findByText("by policy p-1")).toBeDefined();
  });

  it("hides the verdict once an input changes", async () => {
    stubControlPlane({ [route]: ok({ allowed: true }) });
    render(withControlPlane(<PermissionCheckCard tenantId="t-1" />));

    fill("u-1", "read", "fleet");
    await submit();
    expect(await screen.findByText("Allowed")).toBeDefined();

    fireEvent.change(screen.getByLabelText("Resource"), { target: { value: "secrets" } });
    expect(screen.queryByText("Allowed")).toBeNull();

    fireEvent.change(screen.getByLabelText("Resource"), { target: { value: "fleet" } });
    expect(screen.getByText("Allowed")).toBeDefined();
  });

  it("hides the verdict when the tenant changes", async () => {
    stubControlPlane({ [route]: ok({ allowed: false }) });
    const { rerender } = render(withControlPlane(<PermissionCheckCard tenantId="t-1" />));

    fill("u-1", "read", "fleet");
    await submit();
    expect(await screen.findByText("Denied")).toBeDefined();

    rerender(withControlPlane(<PermissionCheckCard tenantId="t-2" />));
    expect(screen.queryByText("Denied")).toBeNull();
  });

  it("does not show the previous verdict while another check runs", async () => {
    serve(() => stubControlPlane({ [route]: ok({ allowed: true }) }));
    render(withControlPlane(<PermissionCheckCard tenantId="t-1" />));

    fill("u-1", "read", "fleet");
    await submit();
    expect(await screen.findByText("Allowed")).toBeDefined();

    let resolve!: (r: Response) => void;
    const held = vi.fn(() => new Promise<Response>((r) => (resolve = r)));
    serve(() => vi.stubGlobal("fetch", held));
    fill("u-1", "write", "fleet");
    fireEvent.change(screen.getByLabelText("Action"), { target: { value: "read" } });
    await submit();
    await waitFor(() => expect(held).toHaveBeenCalledTimes(1));
    expect(screen.queryByText("Allowed")).toBeNull();
    expect(screen.queryByText("Denied")).toBeNull();

    await act(async () => {
      resolve(answer(ok({ allowed: false })));
    });
    expect(await screen.findByText("Denied")).toBeDefined();
  });

  it("sends the roles and groups typed for the subject", async () => {
    const sent = stubControlPlane({ [route]: ok({ allowed: true }) });
    render(withControlPlane(<PermissionCheckCard tenantId="t-1" />));

    fill("u-1", "read", "fleet");
    fireEvent.change(screen.getByLabelText("Roles"), { target: { value: " admin, ops ," } });
    fireEvent.change(screen.getByLabelText("Groups"), { target: { value: "g-1" } });
    await submit();

    expect(await screen.findByText("Allowed")).toBeDefined();
    expect(sent).toHaveLength(1);
    expect(sent[0].path).toBe("/api/v1/iam/tenants/t-1/permissions/check");
    expect(sent[0].body).toEqual({
      subject_id: "u-1",
      action: "read",
      resource: "fleet",
      roles: ["admin", "ops"],
      groups: ["g-1"],
    });
  });

  it("hides the verdict once the roles change", async () => {
    stubControlPlane({ [route]: ok({ allowed: true }) });
    render(withControlPlane(<PermissionCheckCard tenantId="t-1" />));

    fill("u-1", "read", "fleet");
    fireEvent.change(screen.getByLabelText("Roles"), { target: { value: "admin" } });
    await submit();
    expect(await screen.findByText("Allowed")).toBeDefined();

    fireEvent.change(screen.getByLabelText("Roles"), { target: { value: "viewer" } });
    expect(screen.queryByText("Allowed")).toBeNull();

    fireEvent.change(screen.getByLabelText("Roles"), { target: { value: "admin" } });
    expect(screen.getByText("Allowed")).toBeDefined();
  });

  it.each([
    ["403", refused(403, "permission denied")],
    ["503", refused(503, "iam unavailable")],
  ])("a refused check (%s) shows Check failed and no verdict", async (_status, refusal) => {
    stubControlPlane({ [route]: refusal });
    render(withNoRetry(<PermissionCheckCard tenantId="t-1" />));

    fill("u-1", "read", "fleet");
    await submit();

    expect(await screen.findByText(/Check failed/)).toBeDefined();
    expect(screen.queryByText("Allowed")).toBeNull();
    expect(screen.queryByText("Denied")).toBeNull();
  });

  it("a network failure shows Check failed", async () => {
    stubNetworkFailure();
    render(withNoRetry(<PermissionCheckCard tenantId="t-1" />));

    fill("u-1", "read", "fleet");
    await submit();

    expect(await screen.findByText(/Check failed/)).toBeDefined();
    expect(screen.queryByText("Allowed")).toBeNull();
    expect(screen.queryByText("Denied")).toBeNull();
  });

  it.each([
    ["a 403", () => void stubControlPlane({ [route]: refused(403, "permission denied") })],
    ["a network failure", stubNetworkFailure],
  ])("a failure after an Allowed verdict hides it (%s)", async (_name, fail) => {
    serve(() => stubControlPlane({ [route]: ok({ allowed: true }) }));
    render(withNoRetry(<PermissionCheckCard tenantId="t-1" />));

    fill("u-1", "read", "fleet");
    await submit();
    expect(await screen.findByText("Allowed")).toBeDefined();

    serve(fail);
    await submit();

    expect(await screen.findByText(/Check failed/)).toBeDefined();
    expect(screen.queryByText("Allowed")).toBeNull();
    expect(screen.queryByText("Denied")).toBeNull();
  });

  it("withholds Check with the server's reason when the tenant permission check is not offered", async () => {
    caps.capability.mockImplementation((op: string) =>
      op === checkOp ? { enabled: false, reason: "not-configured: iam" } : { enabled: true }
    );
    const sent = stubControlPlane({ [route]: ok({ allowed: true }) });
    render(withControlPlane(<PermissionCheckCard tenantId="t-1" />));

    fill("u-1", "read", "fleet");
    const button = screen.getByRole("button", { name: /Check/ }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.getAttribute("title")).toBe("not-configured: iam");
    expect(button.getAttribute("data-capability-op")).toBe(checkOp);
    expect(button.getAttribute("data-capability-enabled")).toBe("false");

    await submit();
    expect(sent).toHaveLength(0);
    expect(screen.queryByText("Allowed")).toBeNull();
  });

  it("asks the gate for the tenant permission check and keeps the fill rule when it is offered", () => {
    stubControlPlane({ [route]: ok({ allowed: true }) });
    render(withControlPlane(<PermissionCheckCard tenantId="t-1" />));

    expect(caps.capability).toHaveBeenCalledWith(checkOp);
    const button = screen.getByRole("button", { name: /Check/ }) as HTMLButtonElement;
    expect(button.getAttribute("data-capability-enabled")).toBe("true");
    expect(button.disabled).toBe(true);

    fill("u-1", "read", "fleet");
    expect(button.disabled).toBe(false);
  });
});
