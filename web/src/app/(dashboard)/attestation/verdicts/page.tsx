"use client";

import * as React from "react";
import { RefreshCw, Radio } from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useApi } from "@/hooks";
import {
  callerPolicySummary,
  useAttestationFeed,
  type DeviceVerdictEvent,
} from "@/hooks/use-attestation-feed";

interface VerdictsState {
  cursor: string;
  verdicts: DeviceVerdictEvent[];
  error?: string;
  loading: boolean;
}

function newestFirst(a: DeviceVerdictEvent, b: DeviceVerdictEvent): number {
  return (b.recordedAt ?? "").localeCompare(a.recordedAt ?? "");
}

/**
 * Device verdicts page: the caller policy of the attestation feed
 * (DescribeCallerPolicy) and the device verdicts recorded for the
 * session's tenant (PollDeviceVerdicts), polled from the kept cursor or
 * read again from the start.
 */
export default function AttestationVerdictsPage() {
  const feed = useAttestationFeed();
  const callers = useApi(() => feed.describeCallers(), [feed]);
  const [state, setState] = React.useState<VerdictsState>({
    cursor: "",
    verdicts: [],
    loading: true,
  });

  const poll = React.useCallback(
    async (reset: boolean) => {
      setState((s) => ({ ...s, loading: true }));
      const res = await feed.pollVerdicts({
        cursor: reset ? undefined : state.cursor,
        waitMs: 0,
      });
      setState((s) => {
        if (!res.success || !res.data) {
          return {
            ...s,
            loading: false,
            error: res.error?.message ?? "Failed to poll verdicts",
          };
        }
        const incoming = res.data.verdicts ?? [];
        if (reset) {
          return { cursor: res.data.cursor, verdicts: incoming, loading: false };
        }
        const shown = new Set(s.verdicts.map((v) => v.eventId));
        const fresh = incoming.filter((v) => !shown.has(v.eventId));
        return {
          cursor: res.data.cursor,
          verdicts: [...fresh, ...s.verdicts],
          loading: false,
        };
      });
    },
    [feed, state.cursor],
  );

  React.useEffect(() => {
    void poll(true);
    // Poll once from the start on mount; later polls come from the buttons.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const policy = callers.data;
  const rows = [...state.verdicts].sort(newestFirst);

  return (
    <div className="container mx-auto py-6 space-y-6">
      <PageHeader
        title="Device verdicts"
        description="Attestation verdicts recorded for this tenant's devices"
      >
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            void callers.refetch();
            void poll(true);
          }}
        >
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
        <Button size="sm" onClick={() => void poll(false)} disabled={state.loading}>
          <Radio className="h-4 w-4 mr-2" />
          Poll for new verdicts
        </Button>
      </PageHeader>

      <Card data-testid="caller-policy">
        <CardHeader>
          <CardTitle>Caller policy</CardTitle>
          <CardDescription>Who may read the attestation feed</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {callers.error ? (
            <p role="alert" className="text-sm text-destructive">
              {callers.error.message}
            </p>
          ) : policy ? (
            <>
              <p className="text-sm font-medium">{callerPolicySummary(policy)}</p>
              <dl className="grid grid-cols-2 gap-2 text-sm max-w-xl">
                <dt className="text-muted-foreground">Strategy</dt>
                <dd>{policy.strategy}</dd>
                <dt className="text-muted-foreground">Identities</dt>
                <dd className="flex flex-wrap gap-1">
                  {policy.identities.length === 0
                    ? "None"
                    : policy.identities.map((id) => (
                        <Badge key={id} variant="secondary" className="font-mono">
                          {id}
                        </Badge>
                      ))}
                </dd>
                <dt className="text-muted-foreground">Identities source</dt>
                <dd>{policy.identities_source || "-"}</dd>
                <dt className="text-muted-foreground">Anchors configured</dt>
                <dd>{policy.anchors_configured ? "Yes" : "No"}</dd>
                <dt className="text-muted-foreground">Attested peers</dt>
                <dd>{policy.attested_peers_available ? "Yes" : "No"}</dd>
              </dl>
              {policy.invalid_entries?.length ? (
                <div className="text-sm">
                  <p className="font-medium">Invalid entries</p>
                  <ul className="list-disc pl-5">
                    {policy.invalid_entries.map((e) => (
                      <li key={e} className="font-mono">
                        {e}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </>
          ) : null}
        </CardContent>
      </Card>

      <Card data-testid="device-verdicts">
        <CardHeader>
          <CardTitle>Verdicts</CardTitle>
          <CardDescription>Cursor: {state.cursor || "-"}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {state.error ? (
            <p role="alert" className="text-sm text-destructive">
              {state.error}
            </p>
          ) : null}
          {rows.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">
              No verdicts yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Recorded</TableHead>
                  <TableHead>Device</TableHead>
                  <TableHead>Serial</TableHead>
                  <TableHead>Host</TableHead>
                  <TableHead>Result</TableHead>
                  <TableHead>Check</TableHead>
                  <TableHead>Reason</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((v) => (
                  <TableRow key={v.eventId}>
                    <TableCell>{v.recordedAt || "-"}</TableCell>
                    <TableCell className="font-mono">{v.deviceId}</TableCell>
                    <TableCell>{v.serial}</TableCell>
                    <TableCell>{v.hostId}</TableCell>
                    <TableCell>
                      <Badge variant={v.passed ? "default" : "destructive"}>
                        {v.passed ? "Passed" : "Failed"}
                      </Badge>
                    </TableCell>
                    <TableCell>{v.cryptographic ? "Cryptographic" : "Policy"}</TableCell>
                    <TableCell>{v.reason || "-"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
