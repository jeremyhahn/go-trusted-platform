"use client";

/**
 * CeremonyStatusCard shows CeremonyService.Status, read through the SDK
 * client on `useCeremony()`. It is read-only and has no controls: the write
 * flows (Init, claim cert, claim share, Sign CSR) come with the capability
 * gate. The backend reports only the ceremony ID and state today, so the
 * officers, threshold and initialization time it leaves out read Unavailable.
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

/** UNAVAILABLE stands for a value the server does not report. */
export const UNAVAILABLE = "Unavailable";

/**
 * officerProgress gives the enrolled officers out of those required, or
 * UNAVAILABLE when the server does not report how many are required.
 */
export function officerProgress(
  s?: Partial<Pick<CeremonyStatusResponse, "officersEnrolled" | "officersRequired">>
): string {
  const required = s?.officersRequired;
  if (typeof required !== "number" || required <= 0) return UNAVAILABLE;
  return `${s?.officersEnrolled ?? 0} of ${required}`;
}

/** initializedLabel gives the initialization time, if the server reports one. */
function initializedLabel(status?: CeremonyStatusResponse): string {
  if (status?.initializedAt) return status.initializedAt;
  const label = ceremonyStateLabel(status?.state);
  return label === "Not initialized" ? label : UNAVAILABLE;
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
            <dd>{status?.threshold || UNAVAILABLE}</dd>
            <dt className="text-muted-foreground">Ceremony ID</dt>
            <dd>{status?.ceremonyId || "-"}</dd>
            <dt className="text-muted-foreground">Initialized</dt>
            <dd>{initializedLabel(status)}</dd>
          </dl>
        )}
      </CardContent>
    </Card>
  );
}
