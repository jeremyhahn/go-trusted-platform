"use client";

// Capability gate for the CA lifecycle operations no API route serves
// (InitCA, InstallCACertificates, UninstallCACertificates), after the
// pattern of iam/embedded-iam-gate.tsx: the control is shown, disabled, and
// described by its reason, so the gap is visible and no request is sent.
import { Button } from "@/components/ui/button";
import { caOperationReason, type CAGatedControl } from "@/hooks/use-ca-ops";

export function CAOperationGate({ control }: { control: CAGatedControl }) {
  const reasonId = `${control.testId}-reason`;
  const reason = caOperationReason(control.operation);
  return (
    <span className="inline-flex flex-col items-start gap-1">
      <Button
        type="button"
        variant="outline"
        disabled
        data-testid={control.testId}
        aria-describedby={reasonId}
        title={reason}
      >
        {control.label}
      </Button>
      <span id={reasonId} data-testid={reasonId} className="text-xs text-muted-foreground">
        {reason}
      </span>
    </span>
  );
}
