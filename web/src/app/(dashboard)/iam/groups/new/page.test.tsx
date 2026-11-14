import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

type MutationOpts = {
  onSuccess?: (data: unknown) => void;
  onError?: (err: unknown) => void;
};

const push = vi.fn();
const toast = vi.fn();
const createGroup = vi.fn();
const auth = { tenantId: "t1" as string | null, isLoading: false };
const mutationState = { isLoading: false };

vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));
vi.mock("@/contexts/AuthContext", () => ({ useAuth: () => auth }));
vi.mock("@/hooks", () => ({
  useIAM: () => ({ createGroup }),
  useToast: () => ({ toast }),
  useMutation: (fn: (v: unknown) => Promise<unknown>, opts: MutationOpts) => ({
    isLoading: mutationState.isLoading,
    mutate: async (v: unknown) => {
      try {
        opts.onSuccess?.(await fn(v));
      } catch (err) {
        opts.onError?.(err);
      }
    },
  }),
}));

import NewGroupPage from "./page";

const submit = () => screen.getByRole("button", { name: /Create Group/ });
const setField = (label: RegExp, value: string) =>
  fireEvent.change(screen.getByLabelText(label), { target: { value } });

beforeEach(() => {
  push.mockReset();
  toast.mockReset();
  createGroup.mockReset();
  auth.tenantId = "t1";
  auth.isLoading = false;
  mutationState.isLoading = false;
});
afterEach(() => cleanup());

describe("NewGroupPage", () => {
  it("shows only a spinner while auth is loading", () => {
    auth.isLoading = true;
    render(<NewGroupPage />);
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.queryByLabelText(/Name/)).toBeNull();
  });

  it("disables submit until a name is entered", () => {
    render(<NewGroupPage />);
    expect((submit() as HTMLButtonElement).disabled).toBe(true);
    setField(/^Name/, "eng");
    expect((submit() as HTMLButtonElement).disabled).toBe(false);
  });

  it("disables submit while the mutation is loading", () => {
    mutationState.isLoading = true;
    render(<NewGroupPage />);
    setField(/^Name/, "eng");
    expect((submit() as HTMLButtonElement).disabled).toBe(true);
  });

  it("creates the group with a slug id derived from the name, then navigates", async () => {
    createGroup.mockResolvedValue({});
    render(<NewGroupPage />);
    setField(/^Name/, "Platform Team #1");
    setField(/Description/, "the platform team");
    fireEvent.click(submit());
    await waitFor(() => expect(push).toHaveBeenCalledWith("/iam/groups"));
    expect(createGroup).toHaveBeenCalledWith({
      tenantId: "t1",
      id: "platform-team-1",
      name: "Platform Team #1",
      description: "the platform team",
    });
    expect(toast).toHaveBeenCalledWith({ title: "Group created", variant: "success" });
  });

  it("keeps hyphens and digits and collapses runs of other characters", async () => {
    createGroup.mockResolvedValue({});
    render(<NewGroupPage />);
    setField(/^Name/, "ops-2__ÄB");
    fireEvent.click(submit());
    await waitFor(() => expect(createGroup).toHaveBeenCalledTimes(1));
    expect(createGroup.mock.calls[0][0]).toMatchObject({ id: "ops-2-b", description: "" });
  });

  it("reports an error and does not call the API without a tenant", async () => {
    auth.tenantId = null;
    render(<NewGroupPage />);
    setField(/^Name/, "eng");
    fireEvent.click(submit());
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Failed to create group",
        description: "No tenant available",
        variant: "destructive",
      }),
    );
    expect(createGroup).not.toHaveBeenCalled();
    expect(push).not.toHaveBeenCalled();
  });

  it("toasts the API error message and stays on the page", async () => {
    createGroup.mockRejectedValue(new Error("already exists"));
    render(<NewGroupPage />);
    setField(/^Name/, "eng");
    fireEvent.click(submit());
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ description: "already exists", variant: "destructive" }),
      ),
    );
    expect(push).not.toHaveBeenCalled();
  });

  it("toasts 'Unknown error' for a non-Error rejection", async () => {
    createGroup.mockRejectedValue(42);
    render(<NewGroupPage />);
    setField(/^Name/, "eng");
    fireEvent.click(submit());
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ description: "Unknown error" }),
      ),
    );
  });

  it("Cancel navigates back to the group list without creating", () => {
    render(<NewGroupPage />);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(push).toHaveBeenCalledWith("/iam/groups");
    expect(createGroup).not.toHaveBeenCalled();
  });
});
