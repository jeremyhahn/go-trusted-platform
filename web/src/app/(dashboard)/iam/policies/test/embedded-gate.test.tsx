import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import PolicyTestPage from "./page";

// #2024 Codex: the embedded IAM backend (go-quicbaas v0.12.0-alpha) has no
// Policy.Validate or Policy.Simulate handler, so Validate and Run Test are
// gated off with the reason shown, and never reach the SDK.

const state = vi.hoisted(() => ({
  validate: vi.fn(),
  test: vi.fn(),
}));

function idle(mutate: ReturnType<typeof vi.fn>) {
  return {
    data: undefined,
    variables: undefined,
    error: undefined,
    isLoading: false,
    isError: false,
    isSuccess: false,
    mutate,
  };
}

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));

vi.mock("@/contexts/AuthContext", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/contexts/AuthContext")>()),
  useAuth: () => ({ tenantId: "t1" }),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  usePolicyTools: () => ({ validate: idle(state.validate), test: idle(state.test) }),
}));

describe("PolicyTestPage on the embedded IAM backend", () => {
  afterEach(() => {
    cleanup();
    state.validate.mockReset();
    state.test.mockReset();
  });

  it("disables Validate with the Policy.Validate reason and never calls the SDK", () => {
    render(<PolicyTestPage />);
    const button = screen.getByRole("button", { name: /Validate/ }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(
      screen.getByText("Not available: the embedded IAM backend does not implement Policy.Validate yet"),
    ).toBeTruthy();
    fireEvent.click(button);
    expect(state.validate).not.toHaveBeenCalled();
  });

  it("disables Run Test with the Policy.Simulate reason and never calls the SDK", () => {
    render(<PolicyTestPage />);
    fireEvent.change(screen.getByLabelText("Subject ID *"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Resource *"), { target: { value: "doc/1" } });
    const button = screen.getByRole("button", { name: /Run Test/ }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(
      screen.getByText("Not available: the embedded IAM backend does not implement Policy.Simulate yet"),
    ).toBeTruthy();
    fireEvent.click(button);
    expect(state.test).not.toHaveBeenCalled();
  });
});
