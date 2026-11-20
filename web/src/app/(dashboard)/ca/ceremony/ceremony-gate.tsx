"use client";

import * as React from "react";
import { Button } from "@/components/ui/button";

type ButtonProps = React.ComponentProps<typeof Button>;

export interface CeremonyGateProps extends Omit<ButtonProps, "disabled"> {
  /** Why the control is off (no ceremony backend, wrong state); null = on */
  reason: string | null;
  /** Off for a reason the user can fix on the page (busy, empty field) */
  busy?: boolean;
  gateId: string;
}

/**
 * The capability gate of the ceremony controls: a control is on only when
 * the server answered the status read and the ceremony is in a state that
 * accepts the step. Otherwise it is disabled and says why.
 */
export function CeremonyGate({ reason, busy = false, gateId, children, ...props }: CeremonyGateProps) {
  const reasonId = `${gateId}-reason`;
  return (
    <span className="inline-flex flex-col items-start gap-1">
      <Button
        {...props}
        type="button"
        disabled={reason !== null || busy}
        aria-describedby={reason !== null ? reasonId : undefined}
        title={reason ?? undefined}
      >
        {children}
      </Button>
      {reason !== null && (
        <span id={reasonId} className="text-xs text-muted-foreground">
          {reason}
        </span>
      )}
    </span>
  );
}

/** The gate reason of every ceremony step from the status read */
export function ceremonyGateReason(statusError: string | null, loading: boolean): string | null {
  if (loading) return "Reading the ceremony status";
  if (statusError !== null) return `The server has no ceremony backend: ${statusError}`;
  return null;
}

/** Init is on only for a ceremony that has not been initialised */
export function ceremonyInitReason(base: string | null, state: string | undefined): string | null {
  if (base !== null) return base;
  if (state !== undefined && state !== "" && state !== "uninitialized" && state !== "unknown") {
    return `The ceremony is already ${state}`;
  }
  return null;
}
