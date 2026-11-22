import * as React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import NewAppPage from "./page";

const { push } = vi.hoisted(() => ({ push: vi.fn() }));
const registerApp = vi.fn();
const iam = { registerApp };
const toast = vi.fn();
const toastResult = { toast };
const router = { push };
const auth = { tenantId: "t1", isLoading: false };

vi.mock("next/navigation", () => ({
  useRouter: () => router,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useIAM: () => iam,
  useToast: () => toastResult,
}));

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => auth,
}));

function register() {
  fireEvent.change(screen.getByLabelText("Application Name *"), { target: { value: "App" } });
  fireEvent.click(screen.getByRole("button", { name: "Register Application" }));
}

describe("NewAppPage", () => {
  beforeEach(() => {
    push.mockReset();
    registerApp.mockReset();
    toast.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("shows the one-time client secret and leaves only on Done", async () => {
    registerApp.mockResolvedValue({ data: { client_id: "c-1", client_secret: "s3cret", name: "App" } });
    render(<NewAppPage />);

    register();

    expect(await screen.findByText("s3cret")).toBeTruthy();
    expect(screen.getByText("c-1")).toBeTruthy();
    expect(push).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(push).toHaveBeenCalledWith("/iam/apps");
  });

  it("reads the secret from the SDK's wrapped camelCase answer", async () => {
    registerApp.mockResolvedValue({ data: { app: { clientId: "c-2", clientSecret: "camel-secret" } } });
    render(<NewAppPage />);

    register();

    expect(await screen.findByText("camel-secret")).toBeTruthy();
    expect(screen.getByText("c-2")).toBeTruthy();
  });
});
