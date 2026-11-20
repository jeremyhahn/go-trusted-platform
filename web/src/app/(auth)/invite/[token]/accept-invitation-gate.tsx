"use client";

import { Button } from "@/components/ui/button";

/**
 * AcceptInvitation (POST /api/v1/invitations/accept) marks an invitation
 * accepted but grants no tenant membership (#1681 Codex round 2), so the web
 * never calls it: the control is gated off with the reason, and joining goes
 * through the passkey sign-up (RegisterInvitedUser). Modelled on
 * EmbeddedIamGate; it calls no SDK method.
 */
export const ACCEPT_INVITATION_GATE_REASON =
  "Accepting from a signed-in account is not available: the server marks the invitation accepted without adding you to the tenant. Join with the passkey sign-up from a signed-out browser.";

const REASON_ID = "accept-invitation-gate-reason";

export function AcceptInvitationGate() {
  return (
    <div className="space-y-2">
      <Button
        type="button"
        disabled
        aria-describedby={REASON_ID}
        title={ACCEPT_INVITATION_GATE_REASON}
      >
        Accept with this account
      </Button>
      <p id={REASON_ID} className="text-sm text-muted-foreground">
        {ACCEPT_INVITATION_GATE_REASON}
      </p>
    </div>
  );
}
