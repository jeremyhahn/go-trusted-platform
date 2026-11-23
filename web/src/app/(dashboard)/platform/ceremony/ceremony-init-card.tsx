"use client";

/**
 * CeremonyInitCard initializes the bootstrap ceremony: CeremonyService.Init
 * through `useCeremony().init`, `POST /api/v1/ceremony/init`, behind a
 * confirm dialog. The reply carries the admin private key: the card shows it
 * once, read-only, and keeps it only in component state (no storage, no log,
 * no toast), so it is gone when the page is left.
 */
import * as React from "react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Gated } from "@/components/features/capabilities/gated";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  useCeremony,
  type CeremonyInitRequest,
  type CeremonyInitResponse,
} from "@/hooks/use-ceremony";

/** parseSANs splits SANs on commas and newlines, trimmed, empties dropped. */
export function parseSANs(text: string): string[] {
  return text
    .split(/[,\n]/)
    .map((s) => s.trim())
    .filter((s) => s !== "");
}

// thresholdValid reports whether spec is "M-of-N" with 1 <= M <= N, the only
// threshold the backend accepts besides none at all (single-admin).
export function thresholdValid(spec: string): boolean {
  const match = /^(\d+)-of-(\d+)$/.exec(spec);
  if (!match) return false;
  const m = Number(match[1]);
  const n = Number(match[2]);
  return m >= 1 && m <= n;
}

export function CeremonyInitCard({ onInitialized }: { onInitialized?: () => void }) {
  const ceremony = useCeremony();
  const [soPin, setSoPin] = React.useState("");
  const [userPin, setUserPin] = React.useState("");
  const [threshold, setThreshold] = React.useState("");
  const [hostname, setHostname] = React.useState("");
  const [sans, setSans] = React.useState("");
  const [confirmOpen, setConfirmOpen] = React.useState(false);
  const [running, setRunning] = React.useState(false);
  const [refusal, setRefusal] = React.useState<string | null>(null);
  const [result, setResult] = React.useState<CeremonyInitResponse | null>(null);

  const thresholdOk = thresholdValid(threshold);
  const disabled = soPin === "" || !thresholdOk || running;

  const handleInit = async () => {
    setConfirmOpen(false);
    setRunning(true);
    setRefusal(null);
    const request: CeremonyInitRequest = {
      soPin,
      userPin: userPin || undefined,
      threshold,
      hostname: hostname || undefined,
    };
    const sanList = parseSANs(sans);
    if (sanList.length > 0) request.sans = sanList;
    try {
      const res = await ceremony.init(request);
      if (res.success && res.data) {
        setSoPin("");
        setUserPin("");
        setResult(res.data);
        onInitialized?.();
      } else {
        setRefusal(res.error?.message ?? "");
      }
    } catch (err) {
      setRefusal(err instanceof Error ? err.message : String(err));
    } finally {
      setRunning(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Initialize ceremony</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="ceremony-init-so-pin">SO PIN</Label>
          <Input
            id="ceremony-init-so-pin"
            type="password"
            autoComplete="off"
            value={soPin}
            onChange={(e) => setSoPin(e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="ceremony-init-user-pin">User PIN</Label>
          <Input
            id="ceremony-init-user-pin"
            type="password"
            autoComplete="off"
            value={userPin}
            onChange={(e) => setUserPin(e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="ceremony-init-threshold">Threshold</Label>
          <Input
            id="ceremony-init-threshold"
            placeholder="3-of-5"
            value={threshold}
            onChange={(e) => setThreshold(e.target.value)}
            aria-invalid={threshold !== "" && !thresholdOk}
          />
          {threshold !== "" && !thresholdOk && (
            <p className="text-sm text-destructive">Threshold must be M-of-N, for example 3-of-5</p>
          )}
        </div>
        <div className="space-y-2">
          <Label htmlFor="ceremony-init-hostname">Hostname</Label>
          <Input
            id="ceremony-init-hostname"
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="ceremony-init-sans">SANs</Label>
          <Textarea
            id="ceremony-init-sans"
            placeholder="One per line or comma separated"
            value={sans}
            onChange={(e) => setSans(e.target.value)}
          />
        </div>
        <Gated op="POST /api/v1/ceremony/init">
          <Button disabled={disabled} onClick={() => setConfirmOpen(true)}>
            Initialize
          </Button>
        </Gated>

        {refusal !== null && <p role="alert">Init refused: {refusal}</p>}

        {result && (
          <div className="space-y-4">
            <Alert variant="warning">
              <AlertDescription>Save the admin key now: the platform keeps no copy.</AlertDescription>
            </Alert>
            <div className="space-y-2">
              <Label htmlFor="ceremony-init-admin-cert">Admin certificate</Label>
              <Textarea id="ceremony-init-admin-cert" readOnly value={result.adminCertPem} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ceremony-init-admin-key">Admin private key</Label>
              <Textarea id="ceremony-init-admin-key" readOnly value={result.adminKeyPem} />
            </div>
            <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2">
              <dt className="text-muted-foreground">SPKI pin</dt>
              <dd className="break-all">{result.spkiPin}</dd>
              <dt className="text-muted-foreground">Ceremony ID</dt>
              <dd>{result.ceremonyId}</dd>
            </dl>
          </div>
        )}
      </CardContent>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Initialize the ceremony?</DialogTitle>
            <DialogDescription>
              This creates the ceremony CA and the admin credential. It runs once.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleInit}>Initialize</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
