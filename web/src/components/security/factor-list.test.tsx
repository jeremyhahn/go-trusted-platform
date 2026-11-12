import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import React from "react";

import type { AuthFactor } from "@/types/auth-factors";
import { FactorList } from "./factor-list";

function factor(overrides: Partial<AuthFactor>): AuthFactor {
  return {
    id: "f1",
    user_id: "u1",
    type: "mtls",
    label: "laptop",
    metadata: {},
    registered_at: new Date(Date.now() - 3 * 24 * 3600 * 1000).toISOString(),
    last_used_at: null,
    revoked_at: null,
    created_by: "self",
    ...overrides,
  };
}

function setup(factors: AuthFactor[] | null, loading = false) {
  const handlers = { onRotate: vi.fn(), onRemove: vi.fn(), onRelabel: vi.fn() };
  render(
    <FactorList
      factors={factors as AuthFactor[]}
      loading={loading}
      {...handlers}
    />,
  );
  return handlers;
}

describe("FactorList", () => {
  afterEach(() => {
    cleanup();
  });

  it("shows skeletons while loading", () => {
    setup([factor({})], true);
    const busy = screen.getByLabelText("Loading factors");
    expect(busy.getAttribute("aria-busy")).toBe("true");
    expect(busy.children.length).toBe(3);
    expect(screen.queryByText("laptop")).toBeNull();
  });

  it("shows the empty state for an empty list", () => {
    setup([]);
    expect(screen.getByText(/No authentication factors registered/)).toBeTruthy();
  });

  it("treats a null factor list as empty", () => {
    setup(null);
    expect(screen.getByText(/No authentication factors registered/)).toBeTruthy();
  });

  it("shows the empty state when every factor is revoked", () => {
    setup([factor({ revoked_at: "2026-01-02T00:00:00Z" })]);
    expect(screen.getByText(/No authentication factors registered/)).toBeTruthy();
  });

  it("groups active factors by type and hides revoked ones", () => {
    setup([
      factor({ id: "a", label: "cert-a" }),
      factor({ id: "b", label: "cert-b" }),
      factor({ id: "c", type: "fido2", label: "key-c" }),
      factor({ id: "d", type: "piv", label: "gone", revoked_at: "2026-01-02T00:00:00Z" }),
    ]);
    expect(screen.getByText("mTLS Certificate")).toBeTruthy();
    expect(screen.getByText("FIDO2 / Passkey")).toBeTruthy();
    expect(screen.queryByText("PIV Smartcard")).toBeNull();
    expect(screen.queryByText("gone")).toBeNull();
    expect(screen.getByText("cert-a")).toBeTruthy();
    expect(screen.getByText("key-c")).toBeTruthy();
    expect(screen.getByText("2")).toBeTruthy();
    expect(screen.getByText("1")).toBeTruthy();
  });

  it("shows relative registration time and Never for an unused factor", () => {
    setup([factor({})]);
    expect(screen.getByText("Registered 3 days ago")).toBeTruthy();
    expect(screen.getByText("Last used Never")).toBeTruthy();
  });

  it("shows an unparseable timestamp as given", () => {
    setup([factor({ registered_at: "not-a-date" })]);
    expect(screen.getByText("Registered not-a-date")).toBeTruthy();
  });

  it("calls onRotate with the factor", () => {
    const f = factor({});
    const h = setup([f]);
    fireEvent.click(screen.getByLabelText("Rotate laptop"));
    expect(h.onRotate).toHaveBeenCalledWith(f);
  });

  it("disables Remove on the last active factor", () => {
    setup([factor({}), factor({ id: "x", label: "old", revoked_at: "2026-01-02T00:00:00Z" })]);
    const btn = screen.getByLabelText("Remove laptop") as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    expect(btn.getAttribute("title")).toBe("Cannot remove the last factor");
  });

  it("asks for confirmation before removing and removes on confirm", () => {
    const f = factor({ id: "a", label: "cert-a" });
    const h = setup([f, factor({ id: "b", label: "cert-b" })]);
    const btn = screen.getByLabelText("Remove cert-a") as HTMLButtonElement;
    expect(btn.disabled).toBe(false);
    fireEvent.click(btn);
    expect(h.onRemove).not.toHaveBeenCalled();
    expect(screen.getByText("Remove authentication factor")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    expect(h.onRemove).toHaveBeenCalledTimes(1);
    expect(h.onRemove).toHaveBeenCalledWith(f);
    expect(screen.queryByText("Remove authentication factor")).toBeNull();
  });

  it("does not remove when the confirmation is cancelled", () => {
    const h = setup([factor({ id: "a", label: "cert-a" }), factor({ id: "b", label: "cert-b" })]);
    fireEvent.click(screen.getByLabelText("Remove cert-b"));
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(h.onRemove).not.toHaveBeenCalled();
    expect(screen.queryByText("Remove authentication factor")).toBeNull();
  });

  it("relabels on Enter with the trimmed label", () => {
    const f = factor({});
    const h = setup([f]);
    fireEvent.click(screen.getByLabelText("Edit label"));
    const input = screen.getByLabelText("Factor label");
    fireEvent.change(input, { target: { value: "  work laptop  " } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(h.onRelabel).toHaveBeenCalledWith(f, "work laptop");
    expect(screen.queryByLabelText("Factor label")).toBeNull();
  });

  it("relabels with the Save button", () => {
    const f = factor({});
    const h = setup([f]);
    fireEvent.click(screen.getByLabelText("Edit label"));
    fireEvent.change(screen.getByLabelText("Factor label"), { target: { value: "desk" } });
    fireEvent.click(screen.getByLabelText("Save label"));
    expect(h.onRelabel).toHaveBeenCalledWith(f, "desk");
  });

  it("does not relabel with a blank or unchanged label", () => {
    const h = setup([factor({})]);
    fireEvent.click(screen.getByLabelText("Edit label"));
    fireEvent.change(screen.getByLabelText("Factor label"), { target: { value: "   " } });
    fireEvent.keyDown(screen.getByLabelText("Factor label"), { key: "Enter" });
    fireEvent.click(screen.getByLabelText("Edit label"));
    fireEvent.change(screen.getByLabelText("Factor label"), { target: { value: "laptop" } });
    fireEvent.click(screen.getByLabelText("Save label"));
    expect(h.onRelabel).not.toHaveBeenCalled();
  });

  it("restores the label on Escape and on Cancel", () => {
    const h = setup([factor({})]);
    fireEvent.click(screen.getByLabelText("Edit label"));
    fireEvent.change(screen.getByLabelText("Factor label"), { target: { value: "draft" } });
    fireEvent.keyDown(screen.getByLabelText("Factor label"), { key: "Escape" });
    expect(screen.queryByLabelText("Factor label")).toBeNull();
    fireEvent.click(screen.getByLabelText("Edit label"));
    expect((screen.getByLabelText("Factor label") as HTMLInputElement).value).toBe("laptop");
    fireEvent.click(screen.getByLabelText("Cancel"));
    expect(screen.queryByLabelText("Factor label")).toBeNull();
    expect(h.onRelabel).not.toHaveBeenCalled();
  });
});
