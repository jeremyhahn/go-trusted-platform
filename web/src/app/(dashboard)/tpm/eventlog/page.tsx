"use client";

/**
 * TPM Event Log Page
 *
 * Renders the TCG event log returned by /api/v1/tpm/eventlog.
 * Each entry is a measurement that was extended into a PCR during
 * boot (BIOS/UEFI components, Secure Boot variables, MOK, kernel,
 * initrd, etc.). The log is the canonical replay path for the
 * current PCR values: hashing each event in order against the
 * starting PCR state should produce the live PCR readout from the
 * PCR Banks page.
 *
 * Modeled after the xkey TPM Svelte view's "Measurements"
 * (Event Log Viewer + replay) tab; see memory
 * `reference_xkey_tpm_gui.md`.
 */

import * as React from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  RefreshCw,
  ScrollText,
  AlertCircle,
  Hash,
} from "lucide-react";
import { useApi, useTPM, useToast } from "@/hooks";

interface EventLogEntry {
  eventNum?: number;
  pcrIndex: number;
  eventType: string;
  digestCount?: number;
  digests?: Array<{ algorithmId?: string; algorithm?: string; digest?: string; value?: string }>;
  eventSize?: number;
  eventString?: string;
  data?: string;
  description?: string;
}

const PCR_LABELS: Record<number, string> = {
  0: "BIOS/UEFI code",
  1: "BIOS/UEFI configuration",
  2: "Option ROM code",
  3: "Option ROM configuration",
  4: "Master Boot Record",
  5: "MBR/GPT configuration",
  6: "State transitions / wake events",
  7: "Secure Boot policy",
  8: "GRUB bootloader / kernel cmdline",
  9: "Kernel + initrd",
  10: "IMA measurements",
  11: "BitLocker / VSM",
  12: "Boot manager",
  13: "Authority for verifier",
  14: "MOK (Machine Owner Keys)",
  15: "OS-supplied measurements",
  23: "Platform PCR (golden measurements)",
};

const decodeASCII = (hex: string): string => {
  if (!hex) return "";
  // Convert base64 to hex if necessary, then strip non-printable runs.
  let raw = hex;
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    try {
      const bin = atob(hex);
      raw = Array.from(bin)
        .map((c) => c.charCodeAt(0).toString(16).padStart(2, "0"))
        .join("");
    } catch {
      return "";
    }
  }
  let s = "";
  for (let i = 0; i < raw.length; i += 2) {
    const code = parseInt(raw.slice(i, i + 2), 16);
    if (code >= 32 && code <= 126) s += String.fromCharCode(code);
  }
  return s.trim();
};

export default function TPMEventLogPage() {
  const { toast } = useToast();
  const tpm = useTPM();

  const {
    data: logData,
    isLoading: loading,
    error,
    refetch,
  } = useApi(
    () => tpm.getEventLog(),
    [],
    {
      onError: (err) => {
        toast({
          title: "Error loading event log",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // The platformd `/api/v1/tpm/eventlog` endpoint returns the
  // raw TCG2 event log as a single base64 blob plus an
  // `eventCount` summary. Server-side structured parsing of the
  // binary event log is not yet implemented — until it is, this
  // page surfaces the count + format and lets the operator
  // download the raw log for offline parsing with tpm2-tools or
  // tcg-parser. The `entries` array stays empty by design and
  // the empty-state copy explains the situation; we don't
  // synthesize fake parsed rows.
  const entries: EventLogEntry[] = React.useMemo(() => {
    const events = (logData as any)?.events || (logData as any)?.entries || [];
    return events as EventLogEntry[];
  }, [logData]);

  const rawEventLog: string | null = (logData as any)?.eventLog ?? null;
  const eventCount: number = parseInt(
    String((logData as any)?.eventCount ?? entries.length ?? 0),
    10,
  );
  const eventLogFormat: string = (logData as any)?.format || "tcg2";

  const stats = React.useMemo(() => {
    const byPCR = new Map<number, number>();
    for (const e of entries) {
      byPCR.set(e.pcrIndex, (byPCR.get(e.pcrIndex) ?? 0) + 1);
    }
    return {
      total: eventCount || entries.length,
      pcrsTouched: byPCR.size,
      mostMeasured: [...byPCR.entries()].sort((a, b) => b[1] - a[1])[0],
    };
  }, [entries, eventCount]);

  const downloadRawLog = React.useCallback(() => {
    if (!rawEventLog) return;
    const bin = atob(rawEventLog);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    const blob = new Blob([buf], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `tpm-eventlog-${eventLogFormat}.bin`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast({
      title: "Event log downloaded",
      description: `Raw ${eventLogFormat} log saved (parse with tpm2_eventlog)`,
      variant: "success",
    });
  }, [rawEventLog, eventLogFormat, toast]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">TPM Event Log</h1>
          <p className="text-muted-foreground">
            TCG measurement log &mdash; every PCR extend recorded during boot
          </p>
        </div>
        <div className="flex items-center gap-2">
          {rawEventLog && (
            <Button variant="outline" onClick={downloadRawLog}>
              Download .bin
            </Button>
          )}
          <Button variant="outline" onClick={() => refetch()} disabled={loading}>
            <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-4 bg-destructive/10 border border-destructive rounded-lg">
          <AlertCircle className="h-4 w-4 text-destructive" />
          <div>
            <p className="font-medium text-destructive">Error</p>
            <p className="text-sm text-destructive">{error.message}</p>
          </div>
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Events</CardTitle>
            <ScrollText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">
              Measurements logged during boot
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">PCRs Measured</CardTitle>
            <Hash className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.pcrsTouched}</div>
            <p className="text-xs text-muted-foreground">
              Distinct PCRs extended
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Format</CardTitle>
            <ScrollText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold uppercase">{eventLogFormat}</div>
            <p className="text-xs text-muted-foreground">
              {eventLogFormat === "tcg2"
                ? "Crypto-agile TCG 2.0 log (multiple banks)"
                : "Legacy SHA-1-only TCG 1.2 log"}
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Measurement Log Entries</CardTitle>
          <CardDescription>
            Each row is a PCR extend recorded by firmware / bootloader / kernel
          </CardDescription>
        </CardHeader>
        <CardContent>
          {entries.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground space-y-3">
              {loading ? (
                <p>Loading event log…</p>
              ) : eventCount > 0 ? (
                <>
                  <p>
                    Server reports <strong>{eventCount}</strong> events in the
                    raw <code>{eventLogFormat}</code> log, but structured
                    parsing is not yet implemented server-side. Use the
                    Download .bin button above to fetch the raw log and
                    parse with <code>tpm2_eventlog</code>:
                  </p>
                  <pre className="text-left bg-muted p-3 rounded text-xs inline-block">
                    tpm2_eventlog tpm-eventlog-{eventLogFormat}.bin
                  </pre>
                  <p className="text-xs">
                    A future server-side parser will surface these as
                    structured rows (PCR, type, digest, ASCII data).
                  </p>
                </>
              ) : (
                <p>No event log entries available.</p>
              )}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-20">PCR</TableHead>
                  <TableHead>Event Type</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Data / ASCII</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.slice(0, 200).map((e, i) => {
                  // Server populates eventString from xkms (ASCII for
                  // string-form events, hex for opaque blobs);
                  // decodeASCII is only used as a fallback for older
                  // payloads that returned raw `data`.
                  const display = e.eventString || decodeASCII(e.data || "");
                  const label = PCR_LABELS[e.pcrIndex];
                  return (
                    <TableRow key={i}>
                      <TableCell>
                        <Badge variant="outline">PCR {e.pcrIndex}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{e.eventType || "—"}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {e.description || label || "—"}
                      </TableCell>
                      <TableCell className="text-xs font-mono whitespace-pre-wrap break-all max-w-md">
                        {display || (e.data?.slice(0, 40) ?? "—")}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
          {entries.length > 200 && (
            <p className="text-xs text-muted-foreground mt-2">
              Showing first 200 of {entries.length} events. Filter by PCR to see more.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
