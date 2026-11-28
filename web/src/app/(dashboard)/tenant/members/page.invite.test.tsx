import * as React from "react";
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import MembersPage from "./page";

const toastResult = { toast: vi.fn() };
const authResult = { tenantId: "tenant-1", isLoading: false };
const apiResult = {
  data: { users: [] },
  isLoading: false,
  error: null,
  refetch: vi.fn(),
};
const mutationResult = { mutate: vi.fn(), isLoading: false };
const iamResult = {};
const invitationHooks = {
  create: { mutateAsync: vi.fn(), isLoading: false },
};

// The promise the page's onSubmit returned on the last "Invite" click.
let submitted: Promise<void> | undefined;

vi.mock("@/contexts/AuthContext", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/contexts/AuthContext")>()),
  useAuth: () => authResult,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useIAM: () => iamResult,
  useApi: () => apiResult,
  useMutation: () => mutationResult,
  useToast: () => toastResult,
  useInvitation: () => invitationHooks,
}));

vi.mock("@/components/features/tenant/invitation-form", () => ({
  InvitationForm: ({
    onSubmit,
  }: {
    onSubmit: (data: { email: string; role: string }) => Promise<void>;
  }) => (
    <button
      type="button"
      onClick={() => {
        submitted = onSubmit({ email: "new-member", role: "admin" });
        // The test awaits the promise itself; mark it handled so a
        // rejection is not reported as unhandled before it does.
        submitted.catch(() => undefined);
      }}
    >
      Invite
    </button>
  ),
}));

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  submitted = undefined;
});

describe("MembersPage Invite Member", () => {
  it("sends the invitation through the SDK create hook and toasts success", async () => {
    invitationHooks.create.mutateAsync.mockResolvedValue(undefined);
    render(<MembersPage />);

    await act(async () => {
      screen.getByRole("button", { name: "Invite" }).click();
      await submitted;
    });

    expect(invitationHooks.create.mutateAsync).toHaveBeenCalledTimes(1);
    expect(invitationHooks.create.mutateAsync).toHaveBeenCalledWith({
      email: "new-member",
      role: "admin",
      expiresIn: 72,
    });
    expect(toastResult.toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Invitation sent", variant: "success" }),
    );
  });

  it("toasts the create failure and rejects so the form stays open", async () => {
    const failure = new Error("quota reached");
    invitationHooks.create.mutateAsync.mockRejectedValue(failure);
    render(<MembersPage />);

    await act(async () => {
      screen.getByRole("button", { name: "Invite" }).click();
      await submitted?.catch(() => undefined);
    });

    await expect(submitted).rejects.toThrow("quota reached");
    expect(toastResult.toast).toHaveBeenCalledWith({
      title: "Failed to send invitation",
      description: "quota reached",
      variant: "destructive",
    });
  });
});
