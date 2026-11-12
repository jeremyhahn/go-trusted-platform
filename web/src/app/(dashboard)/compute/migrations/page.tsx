"use client";

/**
 * Migration receivers (#1727): PrepareMigration opens a receiver on this
 * destination host; FinalizeMigration commits or aborts it. Both finalize
 * actions ask for confirmation first.
 */

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useVMOperations } from "@/hooks";
import type { PrepareMigrationResponse } from "trusted-platform-sdk";

export default function MigrationsPage() {
  const ops = useVMOperations();
  const busy = ops.pending !== null;

  const [vmName, setVmName] = useState("");
  const [sourceVmId, setSourceVmId] = useState("");
  const [mode, setMode] = useState<"cold" | "live">("live");
  const [receiver, setReceiver] = useState<PrepareMigrationResponse | null>(null);

  const [receiverId, setReceiverId] = useState("");
  const [confirmCommit, setConfirmCommit] = useState<boolean | null>(null);
  const [finalizeResult, setFinalizeResult] = useState("");

  const handlePrepare = async () => {
    if (!vmName) return;
    const result = await ops.prepareMigration({
      vmName,
      vmId: sourceVmId || undefined,
      mode,
    });
    if (result) {
      setReceiver(result);
      if (result.receiverId) setReceiverId(result.receiverId);
    }
  };

  const runFinalize = async () => {
    const commit = confirmCommit;
    setConfirmCommit(null);
    if (commit === null || !receiverId) return;
    const result = await ops.finalizeMigration(receiverId, commit);
    if (result) {
      setFinalizeResult(`Receiver ${receiverId} ${commit ? "committed" : "aborted"}`);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">VM Migrations</h1>
        <p className="text-muted-foreground mt-1">
          Prepare a migration receiver on this host, then finalize it
        </p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Prepare Receiver</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <Label htmlFor="migration-vm-name">Guest name</Label>
              <Input id="migration-vm-name" value={vmName} onChange={(e) => setVmName(e.target.value)} />
            </div>
            <div>
              <Label htmlFor="migration-vm-id">Source VM ID (optional)</Label>
              <Input
                id="migration-vm-id"
                value={sourceVmId}
                onChange={(e) => setSourceVmId(e.target.value)}
              />
            </div>
            <div>
              <Label htmlFor="migration-mode">Mode</Label>
              <select
                id="migration-mode"
                className="block w-full rounded-md border px-2 py-1 text-sm bg-background"
                value={mode}
                onChange={(e) => setMode(e.target.value === "cold" ? "cold" : "live")}
              >
                <option value="live">live</option>
                <option value="cold">cold</option>
              </select>
            </div>
            <Button onClick={handlePrepare} disabled={busy}>
              Prepare Migration
            </Button>
            {receiver && (
              <div className="text-sm" data-testid="migration-receiver">
                <p>Receiver: {receiver.receiverId}</p>
                <p>Port: {receiver.port}</p>
                <p>TLS name: {receiver.tlsHostname}</p>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Finalize Receiver</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <Label htmlFor="migration-receiver-id">Receiver ID</Label>
              <Input
                id="migration-receiver-id"
                value={receiverId}
                onChange={(e) => setReceiverId(e.target.value)}
              />
            </div>
            <div className="flex gap-2">
              <Button onClick={() => receiverId && setConfirmCommit(true)} disabled={busy}>
                Commit Migration
              </Button>
              <Button
                variant="destructive"
                onClick={() => receiverId && setConfirmCommit(false)}
                disabled={busy}
              >
                Abort Migration
              </Button>
            </div>
            {finalizeResult && (
              <p className="text-sm" data-testid="migration-finalize-result">
                {finalizeResult}
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      <Dialog open={confirmCommit !== null} onOpenChange={(open) => !open && setConfirmCommit(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{confirmCommit ? "Commit migration" : "Abort migration"}</DialogTitle>
            <DialogDescription>
              {confirmCommit
                ? `Register and resume the VM received by ${receiverId}?`
                : `Abort receiver ${receiverId} and discard the received VM?`}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmCommit(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={runFinalize}>
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
