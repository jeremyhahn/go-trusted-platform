import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import CallerPolicyPage from "./page";

// useCallerPolicy is driven by hand so each test sets the exact state the
// page renders; reload is a spy so the Refresh button can be checked.
const reload = vi.fn();
const hook: {
  state: { policy?: Record<string, unknown>; error?: string; loading: boolean };
} = { state: { loading: false } };

vi.mock("@/hooks/use-caller-policy", () => ({
  useCallerPolicy: () => ({ ...hook.state, reload }),
}));

function policy(overrides: Record<string, unknown> = {}) {
  return {
    strategy: "allowlist",
    list_valid: true,
    anchors_configured: false,
    attested_peers_available: true,
    admits_nobody: false,
    identities: [],
    ...overrides,
  };
}

describe("CallerPolicyPage", () => {
  beforeEach(() => {
    hook.state = { loading: false };
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("shows the loading state while the policy loads", () => {
    hook.state = { loading: true };
    render(<CallerPolicyPage />);

    expect(screen.getByText(/Loading caller policy/)).toBeTruthy();
    expect(screen.queryByText(/Strategy:/)).toBeNull();
    expect(screen.getByRole("button", { name: /Refresh/ }).hasAttribute("disabled")).toBe(true);
  });

  it("shows the error alert and no loading state", () => {
    hook.state = { loading: false, error: "service unavailable" };
    render(<CallerPolicyPage />);

    expect(screen.getByText("Caller policy unavailable")).toBeTruthy();
    expect(screen.getByText("service unavailable")).toBeTruthy();
    expect(screen.queryByText(/Loading caller policy/)).toBeNull();
  });

  it("shows none and the admits-nobody alert for an empty policy", () => {
    hook.state = { loading: false, policy: policy({ admits_nobody: true }) };
    render(<CallerPolicyPage />);

    expect(screen.getByText("No caller is admitted")).toBeTruthy();
    expect(screen.getByText("none")).toBeTruthy();
    expect(screen.queryByText(/Invalid entries/)).toBeNull();
  });

  it("lists the policy with its identities, sources and invalid entries", () => {
    hook.state = {
      loading: false,
      policy: policy({
        identities: ["spiffe://a", "spiffe://b"],
        identities_source: "/etc/callers.yaml",
        anchor_source: "/etc/anchors.pem",
        invalid_entries: ["bad-entry"],
      }),
    };
    render(<CallerPolicyPage />);

    expect(screen.getByText("Strategy: allowlist")).toBeTruthy();
    expect(screen.getByText("Identities from: /etc/callers.yaml")).toBeTruthy();
    expect(screen.getByText("Anchors from: /etc/anchors.pem")).toBeTruthy();
    expect(screen.getByText("spiffe://a")).toBeTruthy();
    expect(screen.getByText("spiffe://b")).toBeTruthy();
    expect(screen.getByText("bad-entry")).toBeTruthy();
    expect(screen.getAllByText("yes")).toHaveLength(2);
    expect(screen.getAllByText("no")).toHaveLength(1);
    expect(screen.queryByText("No caller is admitted")).toBeNull();
  });

  it("reloads the policy when Refresh is clicked", () => {
    hook.state = { loading: false, policy: policy() };
    render(<CallerPolicyPage />);

    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));
    expect(reload).toHaveBeenCalledTimes(1);
  });
});
