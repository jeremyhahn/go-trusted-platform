"use client";

import { Loader2, RefreshCw } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useDeviceVerdicts } from "@/hooks/use-device-verdicts";

/** PollDeviceVerdicts (#2038): the device verdict feed for this tenant. */
export default function DeviceVerdictsPage() {
  const { verdicts, error, loading, poll } = useDeviceVerdicts();

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Device verdicts</h1>
          <p className="text-muted-foreground">
            Attestation verdicts recorded for this tenant&apos;s devices, oldest first
          </p>
        </div>
        <Button variant="outline" onClick={() => poll()} disabled={loading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Poll again
        </Button>
      </div>

      <Card data-testid="device-verdicts">
        <CardHeader>
          <CardTitle>Verdicts</CardTitle>
          <CardDescription>Each poll continues from the last verdict shown</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {error && (
            <Alert variant="destructive">
              <AlertTitle>Verdict feed unavailable</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          {loading && verdicts.length === 0 && !error && (
            <p className="flex items-center text-sm">
              <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Polling verdicts...
            </p>
          )}
          {!loading && !error && verdicts.length === 0 && (
            <p className="text-sm text-muted-foreground">No verdicts recorded yet.</p>
          )}
          {verdicts.length > 0 && (
            <Table>
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
                {verdicts.map((v) => (
                  <TableRow key={v.eventId}>
                    <TableCell>{v.recordedAt}</TableCell>
                    <TableCell>{v.deviceId}</TableCell>
                    <TableCell>{v.serial}</TableCell>
                    <TableCell>{v.hostId}</TableCell>
                    <TableCell>
                      {v.passed ? (
                        <Badge>passed</Badge>
                      ) : (
                        <Badge variant="destructive">{v.cryptographic ? "compromised" : "failed"}</Badge>
                      )}
                    </TableCell>
                    <TableCell>{v.reason}</TableCell>
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
