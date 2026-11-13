import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AuthFactor } from "@/types/auth-factors";
import { FactorList } from "./factor-list";

// #1820: unit tests for FactorList — grouping, empty and loading states,
// remove confirmation, last-factor guard and inline relabel.

function factor(over: Partial<AuthFactor>): AuthFactor {
  return {
    id: "f",
    user_id: "user-7",
    type: "mtls",
    label: "factor",
    metadata: {},
    registered_at: "2026-11-01T00:00:00Z",
    last_used_at: null,
    revoked_at: null,
    created_by: "self",
    ...over,
  };
}

const laptop = factor({ id: "m1", label: "Laptop", metadata: { issuer_cn: "Platform CA" } });
const desktop = factor({ id: "m2", label: "Desktop", last_used_at: "2026-11-10T00:00:00Z" });
const yubikey = factor({
  id: "k1",
  type: "fido2",
  label: "YubiKey",
  metadata: { aaguid: "cb69481e-8ff7-4039-93ec-0a2729a154a8" },
});
const revokedCard = factor({
  id: "p1",
  type: "piv",
  label: "Old card",
  revoked_at: "2026-11-02T00:00:00Z",
});

function renderList(factors: AuthFactor[], loading?: boolean) {
  const onRotate = vi.fn();
  const onRemove = vi.fn();
  const onRelabel = vi.fn();
  render(
    <FactorList
      factors={factors}
      loading={loading}
      onRotate={onRotate}
      onRemove={onRemove}
      onRelabel={onRelabel}
    />
  );
  return { onRotate, onRemove, onRelabel };
}

describe("FactorList", () => {
  afterEach(() => {
    cleanup();
  });

  it("shows a busy skeleton while loading, even with factors", () => {
    renderList([laptop], true);
    const busy = screen.getByLabelText("Loading factors");
    expect(busy.getAttribute("aria-busy")).toBe("true");
    expect(busy.children).toHaveLength(3);
    expect(screen.queryByText("Laptop")).toBeNull();
  });

  it("shows the empty state for no factors, only revoked ones, or a missing list", () => {
    const empty = /No authentication factors registered/;
    renderList([]);
    expect(screen.getByText(empty)).toBeTruthy();
    cleanup();

    renderList([revokedCard]);
    expect(screen.getByText(empty)).toBeTruthy();
    cleanup();

    renderList(null as unknown as AuthFactor[]);
    expect(screen.getByText(empty)).toBeTruthy();
  });

  it("groups active factors by type with counts and hides revoked ones", () => {
    renderList([laptop, yubikey, desktop, revokedCard]);

    const headings = screen.getAllByRole("heading");
    expect(headings).toHaveLength(2);
    expect(headings[0].textContent).toContain("mTLS Certificate");
    expect(headings[0].textContent).toContain("2");
    expect(headings[1].textContent).toContain("FIDO2 / Passkey");
    expect(headings[1].textContent).toContain("1");

    expect(screen.getByText("Laptop")).toBeTruthy();
    expect(screen.getByText("Desktop")).toBeTruthy();
    expect(screen.getByText("YubiKey")).toBeTruthy();
    expect(screen.queryByText("Old card")).toBeNull();
    expect(screen.queryByText("PIV Smartcard")).toBeNull();

    expect(screen.getByText("Platform CA")).toBeTruthy();
    expect(screen.getByText("Self-issued (mTLS)")).toBeTruthy();
    expect(screen.getByText("YubiKey 5 NFC")).toBeTruthy();
  });

  it("shows Never for an unused factor and the raw value for a bad date", () => {
    renderList([factor({ label: "Odd", registered_at: "not-a-date" })]);
    expect(screen.getByText("Registered not-a-date")).toBeTruthy();
    expect(screen.getByText("Last used Never")).toBeTruthy();
  });

  it("calls onRotate with the factor", () => {
    const { onRotate } = renderList([laptop, desktop]);
    fireEvent.click(screen.getByRole("button", { name: "Rotate Desktop" }));
    expect(onRotate).toHaveBeenCalledWith(desktop);
  });

  it("removes a factor only after confirmation", () => {
    const { onRemove } = renderList([laptop, desktop]);
    fireEvent.click(screen.getByRole("button", { name: "Remove Laptop" }));
    expect(onRemove).not.toHaveBeenCalled();

    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("Remove authentication factor")).toBeTruthy();
    expect(within(dialog).getByText("Laptop")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));

    expect(onRemove).toHaveBeenCalledTimes(1);
    expect(onRemove).toHaveBeenCalledWith(laptop);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("does not remove when the confirmation is cancelled", () => {
    const { onRemove } = renderList([laptop, desktop]);
    fireEvent.click(screen.getByRole("button", { name: "Remove Desktop" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(onRemove).not.toHaveBeenCalled();
  });

  it("refuses to remove the last active factor", () => {
    renderList([laptop, revokedCard]);
    const remove = screen.getByRole("button", { name: "Remove Laptop" });
    expect(remove).toHaveProperty("disabled", true);
    expect(remove.getAttribute("title")).toBe("Cannot remove the last factor");
    expect(screen.getByRole("button", { name: "Rotate Laptop" })).toHaveProperty("disabled", false);
  });

  it("relabels a factor with Enter or Save, trimming the new label", () => {
    const { onRelabel } = renderList([laptop, desktop]);

    fireEvent.click(screen.getAllByRole("button", { name: "Edit label" })[0]);
    const input = screen.getByLabelText("Factor label");
    expect((input as HTMLInputElement).value).toBe("Laptop");
    fireEvent.change(input, { target: { value: "  Work laptop  " } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(onRelabel).toHaveBeenCalledWith(laptop, "Work laptop");
    expect(screen.queryByLabelText("Factor label")).toBeNull();

    fireEvent.click(screen.getAllByRole("button", { name: "Edit label" })[1]);
    fireEvent.change(screen.getByLabelText("Factor label"), { target: { value: "Home" } });
    fireEvent.click(screen.getByRole("button", { name: "Save label" }));
    expect(onRelabel).toHaveBeenLastCalledWith(desktop, "Home");
    expect(onRelabel).toHaveBeenCalledTimes(2);
  });

  it("ignores a blank or unchanged label and restores it on Escape or Cancel", () => {
    const { onRelabel } = renderList([laptop, desktop]);
    const edit = () => fireEvent.click(screen.getAllByRole("button", { name: "Edit label" })[0]);

    edit();
    fireEvent.keyDown(screen.getByLabelText("Factor label"), { key: "Enter" });
    expect(screen.queryByLabelText("Factor label")).toBeNull();

    edit();
    fireEvent.change(screen.getByLabelText("Factor label"), { target: { value: "   " } });
    fireEvent.keyDown(screen.getByLabelText("Factor label"), { key: "Enter" });
    expect(screen.queryByLabelText("Factor label")).toBeNull();

    // A rejected blank draft must not survive into the next edit.
    edit();
    expect((screen.getByLabelText("Factor label") as HTMLInputElement).value).toBe("Laptop");
    fireEvent.change(screen.getByLabelText("Factor label"), { target: { value: "Changed" } });
    fireEvent.keyDown(screen.getByLabelText("Factor label"), { key: "Escape" });
    expect(screen.queryByLabelText("Factor label")).toBeNull();
    expect(screen.getByText("Laptop")).toBeTruthy();

    edit();
    expect((screen.getByLabelText("Factor label") as HTMLInputElement).value).toBe("Laptop");
    fireEvent.change(screen.getByLabelText("Factor label"), { target: { value: "Other" } });
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByLabelText("Factor label")).toBeNull();

    expect(onRelabel).not.toHaveBeenCalled();
  });
});
