import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import PolicyTestPage from "./page";

// #2024 Codex round 2 P1: the SDK useMutation keeps `data` while a new
// request runs and after it fails. A verdict belongs to the tenant and the
// exact inputs it was evaluated for; it shows only after a successful request
// for the current inputs.

interface FakeMutation {
  data: unknown;
  variables: unknown;
  error: unknown;
  isLoading: boolean;
  isError: boolean;
  isSuccess: boolean;
  mutate: ReturnType<typeof vi.fn>;
}

function idle(): FakeMutation {
  return {
    data: undefined,
    variables: undefined,
    error: undefined,
    isLoading: false,
    isError: false,
    isSuccess: false,
    mutate: vi.fn(),
  };
}

const state = vi.hoisted(() => ({
  validate: undefined as unknown as FakeMutation,
  test: undefined as unknown as FakeMutation,
}));

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));

vi.mock("@/contexts/AuthContext", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/contexts/AuthContext")>()),
  useAuth: () => ({ tenantId: "t1" }),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  usePolicyTools: () => ({ validate: state.validate, test: state.test }),
}));

function fillTest(subject: string) {
  fireEvent.change(screen.getByLabelText("Subject ID *"), { target: { value: subject } });
  fireEvent.change(screen.getByLabelText("Resource *"), { target: { value: "doc/1" } });
}

function allowedFor(subjectId: string): Partial<FakeMutation> {
  return {
    data: { allowed: true, matched_policy: "allow-read" },
    variables: {
      tenantId: "t1",
      subjectId,
      action: "read",
      resource: "doc/1",
      roles: [],
      groups: [],
    },
    isSuccess: true,
  };
}

describe("PolicyTestPage verdicts", () => {
  beforeEach(() => {
    state.validate = idle();
    state.test = idle();
  });

  afterEach(() => {
    cleanup();
  });

  it("shows the verdict for the inputs it was evaluated for", () => {
    const view = render(<PolicyTestPage />);
    fillTest("alice");
    Object.assign(state.test, allowedFor("alice"));
    view.rerender(<PolicyTestPage />);
    expect(screen.getByTestId("test-result").textContent).toContain("Allowed");
    expect(screen.getByText("Matched policy: allow-read")).toBeTruthy();
  });

  it("hides the verdict after the subject changes", () => {
    const view = render(<PolicyTestPage />);
    fillTest("alice");
    Object.assign(state.test, allowedFor("alice"));
    view.rerender(<PolicyTestPage />);
    expect(screen.getByTestId("test-result")).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Subject ID *"), { target: { value: "bob" } });
    expect(screen.queryByTestId("test-result")).toBeNull();
  });

  it("hides a retained verdict while a request runs and after it fails", () => {
    const view = render(<PolicyTestPage />);
    fillTest("bob");
    // The SDK keeps the previous Allowed data while the new request is pending.
    Object.assign(state.test, allowedFor("alice"), {
      variables: { ...(allowedFor("bob").variables as object) },
      isSuccess: false,
      isLoading: true,
    });
    view.rerender(<PolicyTestPage />);
    expect(screen.queryByTestId("test-result")).toBeNull();

    Object.assign(state.test, {
      isLoading: false,
      isError: true,
      error: new Error("boom"),
    });
    view.rerender(<PolicyTestPage />);
    expect(screen.queryByTestId("test-result")).toBeNull();
    expect(screen.queryByText("Matched policy: allow-read")).toBeNull();
    expect(screen.getByRole("alert").textContent).toContain("boom");
  });

  it("binds the validation result to the validated document", () => {
    const view = render(<PolicyTestPage />);
    const yaml = (screen.getByLabelText("Policy YAML") as HTMLTextAreaElement).value;
    Object.assign(state.validate, {
      data: { valid: true },
      variables: { tenantId: "t1", specYaml: yaml },
      isSuccess: true,
    });
    view.rerender(<PolicyTestPage />);
    expect(screen.getByTestId("validate-result").textContent).toContain("Policy is valid");

    fireEvent.change(screen.getByLabelText("Policy YAML"), { target: { value: "kind: Broken" } });
    expect(screen.queryByTestId("validate-result")).toBeNull();
  });

  it("hides a retained validation result while pending and after a failure", () => {
    const view = render(<PolicyTestPage />);
    const yaml = (screen.getByLabelText("Policy YAML") as HTMLTextAreaElement).value;
    Object.assign(state.validate, {
      data: { valid: true },
      variables: { tenantId: "t1", specYaml: yaml },
      isLoading: true,
    });
    view.rerender(<PolicyTestPage />);
    expect(screen.queryByTestId("validate-result")).toBeNull();

    Object.assign(state.validate, { isLoading: false, isError: true, error: new Error("bad") });
    view.rerender(<PolicyTestPage />);
    expect(screen.queryByTestId("validate-result")).toBeNull();
  });
});
