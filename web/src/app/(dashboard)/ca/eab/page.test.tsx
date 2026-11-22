import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import EABCredentialsPage from "./page";

// The rows the server writes: protojson sends the uint64 id as a string and
// the status as the enum name.
const credentials = [
  {
    id: "7",
    keyId: "kid-active",
    profileId: "3",
    tenantId: "t1",
    status: "EAB_CREDENTIAL_STATUS_ACTIVE",
    expiresAt: "2099-01-01T00:00:00Z",
    createdAt: "2026-11-01T00:00:00Z",
  },
  {
    id: "8",
    keyId: "kid-revoked",
    profileId: "3",
    tenantId: "t1",
    status: "EAB_CREDENTIAL_STATUS_REVOKED",
    expiresAt: "2099-01-01T00:00:00Z",
    createdAt: "2026-11-01T00:00:00Z",
  },
];

// Hook results are stable objects so the page's rows do not re-key per render.
const revoke = { mutateAsync: vi.fn().mockResolvedValue({}), isLoading: false };
const deleteCredential = { mutateAsync: vi.fn().mockResolvedValue({}), isLoading: false };
const eabHooks = { revoke, deleteCredential };
const listResult = {
  data: { credentials, total: 2 },
  isLoading: false,
  error: null,
  refetch: vi.fn(),
};
const toastResult = { toast: vi.fn() };

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useToast: () => toastResult,
  useEAB: () => eabHooks,
  useEABList: () => listResult,
}));

vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({ loading: false, error: null, capability: () => ({ enabled: true }) }),
}));

beforeEach(() => {
  vi.spyOn(window, "confirm").mockReturnValue(true);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function rowFor(keyId: string): HTMLElement {
  const row = screen.getByText(keyId).closest("tr");
  if (!row) throw new Error(`no table row for ${keyId}`);
  return row;
}

describe("EABCredentialsPage", () => {
  it("lists both credentials with their status", () => {
    render(<EABCredentialsPage />);
    expect(within(rowFor("kid-active")).getByText("Active")).toBeTruthy();
    expect(within(rowFor("kid-revoked")).getByText("Revoked")).toBeTruthy();
  });

  it("revokes the active credential by its numeric id and refetches", async () => {
    render(<EABCredentialsPage />);
    fireEvent.click(within(rowFor("kid-active")).getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(listResult.refetch).toHaveBeenCalled());
    expect(revoke.mutateAsync).toHaveBeenCalledWith(7);
  });

  it("offers no Revoke on a revoked credential", () => {
    render(<EABCredentialsPage />);
    expect(within(rowFor("kid-revoked")).queryByRole("button", { name: "Revoke" })).toBeNull();
  });

  it("deletes the revoked credential by its numeric id", async () => {
    render(<EABCredentialsPage />);
    fireEvent.click(within(rowFor("kid-revoked")).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(deleteCredential.mutateAsync).toHaveBeenCalledWith(8));
  });
});
