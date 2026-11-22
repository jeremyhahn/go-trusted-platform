"use client";

/**
 * CeremonyStatusCard shows CeremonyService.Status, read through the SDK
 * client on `useCeremony()`. It is read-only and has no controls: the write
 * flows (Init, claim cert, claim share, Sign CSR) come with the capability
 * gate.
 */
import * as React from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useCeremony, type CeremonyStatusResponse } from "@/hooks/use-ceremony";

/** ceremonyStateLabel names a CeremonyState for the operator. */
export function ceremonyStateLabel(state?: string): string {
  switch ((state ?? "").replace(/^CEREMONY_STATE_/, "")) {
    case "UNINITIALIZED":
      return "Not initialized";
    case "IN_PROGRESS":
      return "In progress";
    case "COMPLETE":
      return "Complete";
    default:
      return "Unknown";
  }
}

/** officerProgress gives the enrolled officers out of those required. */
export function officerProgress(
  s?: Pick<CeremonyStatusResponse, "officersEnrolled" | "officersRequired">
): string {
  return `${s?.officersEnrolled ?? 0} of ${s?.officersRequired ?? 0}`;
}

interface StatusState {
  status?: CeremonyStatusResponse;
  error?: string;
  loading: boolean;
}

export function CeremonyStatusCard() {
  const ceremony = useCeremony();
  const [state, setState] = React.useState<StatusState>({ loading: true });

  React.useEffect(() => {
    let cancelled = false;
    ceremony.status().then((res) => {
      if (cancelled) return;
      if (res.error) {
        setState({ error: res.error.message, loading: false });
      } else {
        setState({ status: res.data, loading: false });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [ceremony]);

  const { status, error, loading } = state;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Ceremony status</CardTitle>
      </CardHeader>
      <CardContent>
        {loading ? (
          <p>Loading ceremony status</p>
        ) : error ? (
          <p role="alert">Ceremony status unavailable: {error}</p>
        ) : (
          <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2">
            <dt className="text-muted-foreground">State</dt>
            <dd>{ceremonyStateLabel(status?.state)}</dd>
            <dt className="text-muted-foreground">Officers</dt>
            <dd>{officerProgress(status)}</dd>
            <dt className="text-muted-foreground">Threshold</dt>
            <dd>{status?.threshold || "-"}</dd>
            <dt className="text-muted-foreground">Ceremony ID</dt>
            <dd>{status?.ceremonyId || "-"}</dd>
            <dt className="text-muted-foreground">Initialized</dt>
            <dd>{status?.initializedAt ?? "Not initialized"}</dd>
          </dl>
        )}
      </CardContent>
    </Card>
  );
}
