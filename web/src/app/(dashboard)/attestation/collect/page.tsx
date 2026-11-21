"use client";
import * as React from "react";
import { Loader2, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useAttestationCollect, useToast } from "@/hooks";
import type { AttestationCollectOperation } from "@/hooks";
import {
  WORKLOAD_COLLECTION_AVAILABLE,
  WORKLOAD_COLLECTION_UNAVAILABLE,
} from "@/hooks/use-attestation-collect";

const operationTitles: Record<AttestationCollectOperation, string> = {
  collectHost: "Host attestation",
  collectVM: "VM attestation",
  collectContainer: "Container attestation",
  deleteManifest: "Manifest deletion",
};

/**
 * Attestation collect (#1732): collect host attestation and delete a manifest
 * (behind a confirm dialog). VM and container collection are shown but gated
 * as unavailable until the service supports them (#1747 Codex round 2).
 * Manifest verification is not offered until the verifier fails closed.
 */
export default function AttestationCollectPage() {
  const { toast } = useToast();
  const ops = useAttestationCollect();
  const [vmId, setVmId] = React.useState("");
  const [containerId, setContainerId] = React.useState("");
  const [manifestId, setManifestId] = React.useState("");
  const [confirmDelete, setConfirmDelete] = React.useState(false);

  const busy = ops.pending !== undefined;
  const workloadGated = !WORKLOAD_COLLECTION_AVAILABLE;

  const remove = async () => {
    setConfirmDelete(false);
    const ok = await ops.deleteManifest(manifestId.trim());
    if (ok) {
      toast({ title: "Manifest deleted", description: manifestId.trim() });
      setManifestId("");
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Attestation Collect</h1>
        <p className="text-muted-foreground">
          Collect host attestation and delete manifests
        </p>
      </div>

      {workloadGated && (
        <Alert data-testid="workload-collect-unavailable">
          <AlertTitle>VM and container collection unavailable</AlertTitle>
          <AlertDescription>{WORKLOAD_COLLECTION_UNAVAILABLE}</AlertDescription>
        </Alert>
      )}

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Host</CardTitle>
            <CardDescription>Quote this host&apos;s TPM with a fresh nonce</CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={() => ops.collectHost()} disabled={busy}>
              {ops.pending === "collectHost" && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Collect host attestation
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Virtual machine</CardTitle>
            <CardDescription>Collect attestation for one VM</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            <Label htmlFor="vm-id">VM ID</Label>
            <Input
              id="vm-id"
              value={vmId}
              onChange={(e) => setVmId(e.target.value)}
              disabled={workloadGated}
            />
            <Button
              onClick={() => ops.collectVM(vmId.trim())}
              disabled={workloadGated || busy || !vmId.trim()}
            >
              {ops.pending === "collectVM" && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Collect VM attestation
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Container</CardTitle>
            <CardDescription>Collect attestation for one container</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            <Label htmlFor="container-id">Container ID</Label>
            <Input
              id="container-id"
              value={containerId}
              onChange={(e) => setContainerId(e.target.value)}
              disabled={workloadGated}
            />
            <Button
              onClick={() => ops.collectContainer(containerId.trim())}
              disabled={workloadGated || busy || !containerId.trim()}
            >
              {ops.pending === "collectContainer" && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Collect container attestation
            </Button>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Delete manifest</CardTitle>
            <CardDescription>Remove a stored manifest by its ID</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            <Label htmlFor="manifest-id">Manifest ID</Label>
            <Input
              id="manifest-id"
              value={manifestId}
              onChange={(e) => setManifestId(e.target.value)}
            />
            <Button
              variant="destructive"
              onClick={() => setConfirmDelete(true)}
              disabled={busy || !manifestId.trim()}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete manifest
            </Button>
          </CardContent>
        </Card>
      </div>

      {ops.operation && ops.error && (
        <Alert variant="destructive" data-testid="collect-error">
          <AlertTitle>{operationTitles[ops.operation]} failed</AlertTitle>
          <AlertDescription>{ops.error}</AlertDescription>
        </Alert>
      )}

      {ops.operation && !ops.error && ops.result !== undefined && (
        <Card data-testid="collect-result">
          <CardHeader>
            <CardTitle>{operationTitles[ops.operation]}</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="overflow-auto rounded bg-muted p-4 text-xs">
              {JSON.stringify(ops.result, null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}

      <Dialog open={confirmDelete} onOpenChange={setConfirmDelete}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete manifest?</DialogTitle>
            <DialogDescription>
              Manifest {manifestId.trim()} is removed for good. Verification against it stops.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmDelete(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={remove}>
              Confirm delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
