"use client";

import type { ReactNode } from "react";
import type { EABOperation, UseEABGateResult } from "@/hooks/use-eab-gate";

interface EABGateProps {
  gate: UseEABGateResult;
  op: EABOperation;
  children: ReactNode;
}

/**
 * Renders an EAB control as it is while the server offers its operation;
 * otherwise disables every control inside it and shows the reason.
 */
export function EABGate({ gate, op, children }: EABGateProps) {
  const reason = gate.reason(op);
  if (reason === null) return <>{children}</>;
  const id = `eab-gate-${op}`;
  return (
    <fieldset disabled aria-describedby={id} data-testid={id} className="contents">
      {children}
      <p id={id} className="text-xs text-muted-foreground">
        {reason}
      </p>
    </fieldset>
  );
}
