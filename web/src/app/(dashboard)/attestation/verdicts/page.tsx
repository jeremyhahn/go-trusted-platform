"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { RefreshCw } from "lucide-react";
import type { DeviceVerdictEvent } from "trusted-platform-sdk";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAttestation } from "@/hooks";
import { useCapabilities } from "@/hooks/use-capabilities";
import { Gated } from "@/components/features/capabilities/gated";

const OP = "GET /api/v1/attestation/verdicts";

// DeviceVerdictsPage lists the device attestation verdicts the tenant may
// see (AttestationService.PollDeviceVerdicts), polled only when the server
// offers GET /api/v1/attestation/verdicts. Each further poll continues from
// the cursor of the previous answer and appends what it returns. When the
// server no longer holds the verdicts after that cursor (ErrMissedVerdicts,
// HTTP 429), the page offers Resynchronize: a poll from the head cursor that
// reports the gap and points to the device reports.
export default function DeviceVerdictsPage() {
  const attestation = useAttestation();
  const { loading: capsLoading, capability } = useCapabilities();
  const cap = capability(OP);
  const enabled = !capsLoading && cap.enabled;

  const [verdicts, setVerdicts] = useState<DeviceVerdictEvent[]>([]);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [missed, setMissed] = useState(false);
  const [gap, setGap] = useState<string | null>(null);

  const poll = useCallback(async () => {
    setBusy(true);
    try {
      const res = await attestation.pollDeviceVerdicts({ cursor, waitMs: 0 });
      if (res.success && res.data) {
        const data = res.data;
        setVerdicts((prev) => [...prev, ...(data.verdicts ?? [])]);
        setCursor(data.cursor);
        setError(null);
      } else if (res.error?.status === 429 && /missed verdicts/i.test(res.error.message ?? "")) {
        // feed.Poll refused the cursor with ErrMissedVerdicts: polling it again repeats the refusal.
        setMissed(true);
        setError(null);
      } else {
        setError(res.error?.message ?? "The verdict poll failed");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [attestation, cursor]);

  // Resynchronize polls with no cursor: the zero cursor returns the head cursor at once.
  const resync = useCallback(async () => {
    setBusy(true);
    try {
      const res = await attestation.pollDeviceVerdicts({ waitMs: 0 });
      if (res.success && res.data) {
        const data = res.data;
        setVerdicts((prev) => [...prev, ...(data.verdicts ?? [])]);
        setCursor(data.cursor);
        setMissed(false);
        setError(null);
        setGap(
          `Resynchronized at ${new Date().toLocaleString()}: verdicts recorded before this point may be missing from this list.`,
        );
      } else {
        setError(res.error?.message ?? "The verdict poll failed");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [attestation]);

  // The first poll, once the capabilities say the route is offered.
  const started = useRef(false);
  useEffect(() => {
    if (enabled && !started.current) {
      started.current = true;
      void poll();
    }
  }, [enabled, poll]);

  return (
    <div className="container mx-auto py-6 space-y-6">
      <PageHeader title="Device verdicts" description="Attestation verdicts recorded for your devices">
        <Gated op={OP}>
          <Button variant="outline" size="sm" disabled={busy || missed} onClick={() => void poll()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Check for new verdicts
          </Button>
        </Gated>
      </PageHeader>

      {!capsLoading && !cap.enabled ? (
        <Card data-testid="verdicts-not-enabled">
          <CardHeader>
            <CardTitle>Device verdicts are not offered by this server</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">{cap.reason}</p>
          </CardContent>
        </Card>
      ) : error ? (
        <Card data-testid="verdicts-error">
          <CardHeader>
            <CardTitle>Could not read the device verdicts</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
            {/* A failed resync keeps the way to resume (#2038). */}
            {missed && (
              <>
                <p>
                  <Link href="/devices" className="underline">
                    Device reports
                  </Link>
                  : read each device&apos;s latest attestation report there to see what was missed.
                </p>
                <Gated op={OP}>
                  <Button size="sm" disabled={busy} onClick={() => void resync()}>
                    Resynchronize
                  </Button>
                </Gated>
              </>
            )}
          </CardContent>
        </Card>
      ) : (
        <>
        {missed && (
          <Card data-testid="verdicts-missed" role="alert">
            <CardHeader>
              <CardTitle>Verdicts were missed</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <p>
                The server no longer holds the verdicts after the last cursor (the daemon restarted, or more than 256
                newer verdicts were recorded), so verdicts were missed. Resynchronize to continue from the newest verdict.
              </p>
              <p>
                <Link href="/devices" className="underline">
                  Device reports
                </Link>
                : read each device&apos;s latest attestation report there to see what was missed.
              </p>
              <Gated op={OP}>
                <Button size="sm" disabled={busy} onClick={() => void resync()}>
                  Resynchronize
                </Button>
              </Gated>
            </CardContent>
          </Card>
        )}
        {gap && (
          <p data-testid="verdicts-gap" role="status" className="text-sm text-muted-foreground">
            {gap}{" "}
            <Link href="/devices" className="underline">
              Device reports
            </Link>
          </p>
        )}
        <Card>
          <CardContent className="pt-6">
            <Table data-testid="verdicts-table">
              <TableHeader>
                <TableRow>
                  <TableHead>Recorded</TableHead>
                  <TableHead>Device</TableHead>
                  <TableHead>Serial</TableHead>
                  <TableHead>Host</TableHead>
                  <TableHead>Verdict</TableHead>
                  <TableHead>Reason</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {verdicts.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground">
                      No verdicts yet
                    </TableCell>
                  </TableRow>
                ) : (
                  verdicts.map((v) => (
                    <TableRow key={v.eventId} data-testid={`verdict-${v.eventId}`}>
                      <TableCell className="font-mono text-xs">{v.recordedAt}</TableCell>
                      <TableCell className="font-mono">{v.deviceId}</TableCell>
                      <TableCell className="font-mono">{v.serial}</TableCell>
                      <TableCell className="font-mono">{v.hostId}</TableCell>
                      <TableCell>
                        {v.passed ? (
                          "Passed"
                        ) : (
                          <span className="flex items-center gap-2">
                            Failed
                            {v.cryptographic ? <Badge variant="destructive">Compromise</Badge> : null}
                          </span>
                        )}
                      </TableCell>
                      <TableCell>{v.reason || "-"}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
        </>
      )}
    </div>
  );
}
