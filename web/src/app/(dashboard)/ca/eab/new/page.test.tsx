import * as React from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import NewEABCredentialPage from "./page";

// Hook results are stable objects so the page sees the same mutation on
// every render.
const create = { mutateAsync: vi.fn(), isLoading: false };
const eabHooks = { create };
const toastResult = { toast: vi.fn() };
const routerResult = { push: vi.fn(), replace: vi.fn(), back: vi.fn(), refresh: vi.fn() };

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useToast: () => toastResult,
  useEAB: () => eabHooks,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => routerResult,
  usePathname: () => "/ca/eab/new",
}));

beforeEach(() => {
  create.mutateAsync.mockReset();
  toastResult.toast.mockReset();
});

afterEach(() => {
  cleanup();
});

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

async function submit() {
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Create credential" }));
  });
}

describe("NewEABCredentialPage", () => {
  it("creates a credential with numeric profile ID and expiry", async () => {
    create.mutateAsync.mockResolvedValue({ credential: { keyId: "k", hmacKey: "h" } });
    render(<NewEABCredentialPage />);
    fill("Profile ID", "3");
    fill("Tenant ID", "t1");
    fill("Expires in (seconds)", "86400");
    await submit();

    await waitFor(() => expect(create.mutateAsync).toHaveBeenCalledTimes(1));
    expect(create.mutateAsync).toHaveBeenCalledWith({
      profileId: 3,
      tenantId: "t1",
      expiresInSeconds: 86400,
    });
  });

  it("omits expiresInSeconds when the expiry is left empty", async () => {
    create.mutateAsync.mockResolvedValue({ credential: { keyId: "k", hmacKey: "h" } });
    render(<NewEABCredentialPage />);
    fill("Profile ID", "3");
    fill("Tenant ID", "t1");
    await submit();

    await waitFor(() => expect(create.mutateAsync).toHaveBeenCalledTimes(1));
    const arg = create.mutateAsync.mock.calls[0][0] as Record<string, unknown>;
    expect(arg).toEqual({ profileId: 3, tenantId: "t1" });
    expect("expiresInSeconds" in arg).toBe(false);
  });

  it("shows the key ID and HMAC key once after create", async () => {
    create.mutateAsync.mockResolvedValue({
      credential: {
        id: "9",
        keyId: "kid-new",
        hmacKey: "c2VjcmV0",
        profileId: "3",
        tenantId: "t1",
        status: "EAB_CREDENTIAL_STATUS_ACTIVE",
      },
    });
    render(<NewEABCredentialPage />);
    fill("Profile ID", "3");
    fill("Tenant ID", "t1");
    await submit();

    expect(await screen.findByText("kid-new")).toBeTruthy();
    expect(screen.getByText("c2VjcmV0")).toBeTruthy();
    expect(screen.getByText(/will not be shown again/)).toBeTruthy();
  });

  it("toasts the error and shows no HMAC key when create fails", async () => {
    create.mutateAsync.mockRejectedValue(new Error("boom"));
    render(<NewEABCredentialPage />);
    fill("Profile ID", "3");
    fill("Tenant ID", "t1");
    await submit();

    await waitFor(() => expect(toastResult.toast).toHaveBeenCalled());
    expect(toastResult.toast).toHaveBeenCalledWith(
      expect.objectContaining({ variant: "destructive", description: "boom" }),
    );
    expect(screen.queryByText("c2VjcmV0")).toBeNull();
    expect(screen.queryByText(/will not be shown again/)).toBeNull();
  });
});
