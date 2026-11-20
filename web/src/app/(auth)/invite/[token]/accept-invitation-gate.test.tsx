import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

// #2056: AcceptInvitation marks an invitation accepted without adding the user
// to the tenant, so the control is gated off: disabled, with the reason, and
// it never calls the SDK.

const accept = vi.fn();

vi.mock("trusted-platform-sdk", () => ({
  useInvitation: () => ({ service: { accept }, accept: { mutateAsync: accept } }),
}));

import { ACCEPT_INVITATION_GATE_REASON, AcceptInvitationGate } from "./accept-invitation-gate";

afterEach(() => {
  cleanup();
});

describe("AcceptInvitationGate", () => {
  it("renders a disabled accept button described by a visible reason", () => {
    render(<AcceptInvitationGate />);
    const button = screen.getByRole("button", { name: /accept with this account/i }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    const reasonId = button.getAttribute("aria-describedby");
    expect(reasonId).toBeTruthy();
    const reason = document.getElementById(reasonId as string);
    expect(reason).not.toBeNull();
    expect(reason?.textContent).toBe(ACCEPT_INVITATION_GATE_REASON);
    expect(ACCEPT_INVITATION_GATE_REASON).toMatch(/passkey/i);
    expect(button.getAttribute("title")).toBe(ACCEPT_INVITATION_GATE_REASON);
  });

  it("calls no AcceptInvitation when clicked", () => {
    render(<AcceptInvitationGate />);
    fireEvent.click(screen.getByRole("button", { name: /accept with this account/i }));
    expect(accept).not.toHaveBeenCalled();
  });
});
