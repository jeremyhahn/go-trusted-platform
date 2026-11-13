import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

type MutationOpts = {
  onSuccess?: (data: unknown) => void;
  onError?: (err: unknown) => void;
};

const push = vi.fn();
const toast = vi.fn();
const registerApp = vi.fn();
const auth = { tenantId: "t1" as string | null, isLoading: false };
const mutationState = { isLoading: false };

vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));
vi.mock("@/contexts/AuthContext", () => ({ useAuth: () => auth }));
vi.mock("@/hooks", () => ({
  useIAM: () => ({ registerApp }),
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

import NewAppPage from "./page";

const submit = () => screen.getByRole("button", { name: /Register Application/ });
const setField = (label: RegExp, value: string) =>
  fireEvent.change(screen.getByLabelText(label), { target: { value } });

beforeEach(() => {
  push.mockReset();
  toast.mockReset();
  registerApp.mockReset();
  auth.tenantId = "t1";
  auth.isLoading = false;
  mutationState.isLoading = false;
});
afterEach(() => cleanup());

describe("NewAppPage", () => {
  it("shows only a spinner while auth is loading", () => {
    auth.isLoading = true;
    render(<NewAppPage />);
    expect(screen.queryByText("Register a new OAuth 2.0 client application.")).toBeNull();
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("disables submit until a name is entered and defaults grant types", () => {
    render(<NewAppPage />);
    expect((submit() as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByLabelText(/Grant Types/) as HTMLInputElement).value).toBe(
      "client_credentials",
    );
    setField(/Application Name/, "svc");
    expect((submit() as HTMLButtonElement).disabled).toBe(false);
  });

  it("disables submit while the mutation is loading", () => {
    mutationState.isLoading = true;
    render(<NewAppPage />);
    setField(/Application Name/, "svc");
    expect((submit() as HTMLButtonElement).disabled).toBe(true);
  });

  it("registers with trimmed, non-empty URIs and grants, then navigates", async () => {
    registerApp.mockResolvedValue({});
    render(<NewAppPage />);
    setField(/Application Name/, "svc");
    setField(/Grant Types/, " client_credentials , ,authorization_code ");
    setField(/Redirect URIs/, "a/cb, ,  b/cb ,");
    fireEvent.click(submit());
    await waitFor(() => expect(push).toHaveBeenCalledWith("/iam/apps"));
    expect(registerApp).toHaveBeenCalledWith({
      tenantId: "t1",
      name: "svc",
      redirectUris: ["a/cb", "b/cb"],
      grantTypes: ["client_credentials", "authorization_code"],
    });
    expect(toast).toHaveBeenCalledWith({ title: "Application registered", variant: "success" });
  });

  it("sends undefined for empty or blank-only lists", async () => {
    registerApp.mockResolvedValue({});
    render(<NewAppPage />);
    setField(/Application Name/, "svc");
    setField(/Grant Types/, " , ,");
    fireEvent.click(submit());
    await waitFor(() => expect(registerApp).toHaveBeenCalledTimes(1));
    expect(registerApp).toHaveBeenCalledWith({
      tenantId: "t1",
      name: "svc",
      redirectUris: undefined,
      grantTypes: undefined,
    });
  });

  it("reports an error and does not call the API without a tenant", async () => {
    auth.tenantId = null;
    render(<NewAppPage />);
    setField(/Application Name/, "svc");
    fireEvent.click(submit());
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Failed to register application",
        description: "No tenant available",
        variant: "destructive",
      }),
    );
    expect(registerApp).not.toHaveBeenCalled();
    expect(push).not.toHaveBeenCalled();
  });

  it("toasts the API error message and stays on the page", async () => {
    registerApp.mockRejectedValue(new Error("duplicate name"));
    render(<NewAppPage />);
    setField(/Application Name/, "svc");
    fireEvent.click(submit());
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ description: "duplicate name", variant: "destructive" }),
      ),
    );
    expect(push).not.toHaveBeenCalled();
  });

  it("toasts 'Unknown error' for a non-Error rejection", async () => {
    registerApp.mockRejectedValue("boom");
    render(<NewAppPage />);
    setField(/Application Name/, "svc");
    fireEvent.click(submit());
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ description: "Unknown error" }),
      ),
    );
  });

  it("Cancel navigates back to the app list without registering", () => {
    render(<NewAppPage />);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(push).toHaveBeenCalledWith("/iam/apps");
    expect(registerApp).not.toHaveBeenCalled();
  });
});
