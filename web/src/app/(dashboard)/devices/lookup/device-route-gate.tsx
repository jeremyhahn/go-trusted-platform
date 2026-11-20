'use client';

import type { ReactNode } from 'react';
import { Button, type ButtonProps } from '@/components/ui/button';

/**
 * DeviceService operations the daemon does not serve to an operator yet
 * (#2048). A gate is only for a capability the daemon does not serve yet
 * (ruling 1042): its control renders disabled through DeviceRouteGate with
 * the reason shown, and never calls the SDK.
 */
export type DeviceGatedOperation = 'AttestDevice';

const REASONS: Record<DeviceGatedOperation, string> = {
  AttestDevice:
    'Not available: the server verifies pasted evidence against the nonce it carries with no age limit, so an old quote would replay as a fresh verdict; a server-issued attestation challenge is tracked in #2134',
};

export function deviceRouteReason(operation: DeviceGatedOperation): string {
  return REASONS[operation];
}

function reasonId(operation: DeviceGatedOperation): string {
  return `device-gate-reason-${operation.toLowerCase()}`;
}

interface DeviceRouteGateProps extends Omit<ButtonProps, 'onClick' | 'disabled' | 'type'> {
  operation: DeviceGatedOperation;
  children: ReactNode;
}

/** A disabled button for a device operation the operator cannot perform. */
export function DeviceRouteGate({ operation, children, ...props }: DeviceRouteGateProps) {
  return (
    <span className="inline-flex flex-col items-start gap-1">
      <Button {...props} type="button" disabled aria-describedby={reasonId(operation)} title={REASONS[operation]}>
        {children}
      </Button>
      <p id={reasonId(operation)} data-testid={`device-gate-${operation}`} className="text-xs text-muted-foreground">
        {REASONS[operation]}
      </p>
    </span>
  );
}
