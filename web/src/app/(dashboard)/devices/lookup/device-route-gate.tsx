'use client';

import type { ReactNode } from 'react';
import { Button, type ButtonProps } from '@/components/ui/button';

/**
 * DeviceService operations an operator's browser session cannot perform
 * (#2048). A control for one renders disabled through DeviceRouteGate with
 * the reason shown, and never calls the SDK.
 */
export type DeviceGatedOperation = 'AttestDevice' | 'GetProfile' | 'BootCertificate' | 'BootDelivery';

const REASONS: Record<DeviceGatedOperation, string> = {
  AttestDevice:
    'Not available: the server verifies pasted evidence against the nonce it carries with no age limit, so an old quote would replay as a fresh verdict; a challenge-based flow is follow-up work',
  GetProfile:
    "Not available: GET /device/profile resolves the calling device from its mTLS client certificate, which an operator's browser does not hold; find the profile by ID, MAC or serial instead",
  BootCertificate:
    "Not available: POST /device/boot/certificate is machine-facing, called by a diskless node over its own connection to prove its key",
  BootDelivery:
    "Not available: POST /device/boot is machine-facing, an attested delivery bound to the diskless node's own mTLS connection",
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
