'use client';

import type { ReactNode } from 'react';
import { Button, type ButtonProps } from '@/components/ui/button';

/**
 * IAM methods the default embedded backend (go-quicbaas v0.12.0-alpha) has
 * no handler for (#2024 Codex). A control that needs one renders disabled
 * through EmbeddedIamGate with the reason shown, and never calls the SDK.
 */
export type EmbeddedIamMissingMethod =
  | 'Policy.Validate'
  | 'Policy.Simulate'
  | 'Policy.Update'
  | 'App.Update'
  | 'Group.AddMember'
  | 'Group.RemoveMember';

export function embeddedIamReason(method: EmbeddedIamMissingMethod): string {
  return `Not available: the embedded IAM backend does not implement ${method} yet`;
}

function reasonId(method: EmbeddedIamMissingMethod): string {
  return `iam-gate-${method.replace('.', '-').toLowerCase()}`;
}

/** The visible reason line for a gated control. */
export function EmbeddedIamReason({ method }: { method: EmbeddedIamMissingMethod }) {
  return (
    <p id={reasonId(method)} className="text-xs text-muted-foreground">
      {embeddedIamReason(method)}
    </p>
  );
}

interface EmbeddedIamGateProps extends Omit<ButtonProps, 'onClick' | 'disabled' | 'type'> {
  method: EmbeddedIamMissingMethod;
  children: ReactNode;
  /** Show the reason line under the button (default true). */
  showReason?: boolean;
}

/** A disabled button for a control the embedded backend cannot serve. */
export function EmbeddedIamGate({ method, children, showReason = true, ...props }: EmbeddedIamGateProps) {
  return (
    <span className="inline-flex flex-col items-end gap-1">
      <Button
        {...props}
        type="button"
        disabled
        aria-describedby={reasonId(method)}
        title={embeddedIamReason(method)}
      >
        {children}
      </Button>
      {showReason && <EmbeddedIamReason method={method} />}
    </span>
  );
}
