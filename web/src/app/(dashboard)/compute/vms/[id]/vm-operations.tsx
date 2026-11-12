"use client";

/**
 * VM operations on the VM detail page (#1727): attestation, metrics, disks,
 * snapshots and migration. Detach and migrate ask for confirmation first.
 * Attach sends the Disk ID field, or a generated ID, and leaves it in the
 * field, since the daemon returns no disk ID and GetVM lists no disks.
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
import type { AttestVMResponse, Snapshot, VMMetrics } from "trusted-platform-sdk";

interface PendingConfirm {
  title: string;
  description: string;
  action: () => Promise<unknown>;
}

function newDiskId(): string {
  const b = new Uint8Array(8);
  globalThis.crypto.getRandomValues(b);
  return "disk-" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function VMOperations({ vmId }: { vmId: string }) {
  const ops = useVMOperations();
  const busy = ops.pending !== null;

  const [attestation, setAttestation] = useState<AttestVMResponse | null>(null);
  const [metrics, setMetrics] = useState<VMMetrics | null>(null);

  const [diskPath, setDiskPath] = useState("");
  const [diskSize, setDiskSize] = useState("10");
  const [diskId, setDiskId] = useState("");
  const [diskNewSize, setDiskNewSize] = useState("");
  const [diskResult, setDiskResult] = useState("");

  const [snapshotName, setSnapshotName] = useState("");
  const [snapshotId, setSnapshotId] = useState("");
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);

  const [destination, setDestination] = useState("");
  const [live, setLive] = useState(true);
  const [migrateResult, setMigrateResult] = useState("");

  const [confirm, setConfirm] = useState<PendingConfirm | null>(null);

  const handleAttest = async () => {
    const result = await ops.attest(vmId);
    if (result) setAttestation(result);
  };

  const handleMetrics = async () => {
    const result = await ops.metrics(vmId);
    if (result?.metrics) setMetrics(result.metrics);
  };

  const handleAttach = async () => {
    if (!diskPath) return;
    const sizeGb = Number(diskSize) || undefined;
    const id = diskId.trim() || newDiskId();
    if (await ops.attachDisk(vmId, { id, path: diskPath, sizeGb })) {
      setDiskId(id);
      setDiskResult(`Attached ${diskPath} as ${id}`);
    }
  };

  const handleResize = async () => {
    const size = Number(diskNewSize);
    if (!diskId || !size) return;
    if (await ops.resizeDisk(vmId, diskId, size)) {
      setDiskResult(`Resized ${diskId} to ${size} GB`);
    }
  };

  const askDetach = () => {
    if (!diskId) return;
    const id = diskId;
    setConfirm({
      title: "Detach disk",
      description: `Detach disk ${id} from this VM?`,
      action: async () => {
        if (await ops.detachDisk(vmId, id)) setDiskResult(`Detached ${id}`);
      },
    });
  };

  const handleCreateSnapshot = async () => {
    if (!snapshotName) return;
    const result = await ops.createSnapshot(vmId, snapshotName);
    if (result) {
      setSnapshot(result.snapshot ?? null);
      if (result.snapshot?.id) setSnapshotId(result.snapshot.id);
    }
  };

  const handleGetSnapshot = async () => {
    if (!snapshotId) return;
    const result = await ops.getSnapshot(vmId, snapshotId);
    if (result?.snapshot) setSnapshot(result.snapshot);
  };

  const askMigrate = () => {
    if (!destination) return;
    const dest = destination;
    const isLive = live;
    setConfirm({
      title: "Migrate VM",
      description: `Migrate this VM to ${dest}${isLive ? " (live)" : ""}?`,
      action: async () => {
        if (await ops.migrate(vmId, dest, isLive)) setMigrateResult(`Migration to ${dest} started`);
      },
    });
  };

  const runConfirmed = async () => {
    const pending = confirm;
    setConfirm(null);
    if (pending) await pending.action();
  };

  return (
    <div className="grid gap-6 md:grid-cols-2" data-testid="vm-operations">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Attestation</CardTitle>
            <Button size="sm" onClick={handleAttest} disabled={busy}>
              Attest VM
            </Button>
          </div>
        </CardHeader>
        <CardContent data-testid="vm-attestation">
          {attestation ? (
            <div className="space-y-1 text-sm">
              <p>{attestation.status?.message || "Attestation collected"}</p>
              <p>PCR values: {attestation.pcrValues?.length ?? 0}</p>
              {attestation.signatureAlgorithm && <p>Algorithm: {attestation.signatureAlgorithm}</p>}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No attestation collected</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Live Metrics</CardTitle>
            <Button size="sm" variant="outline" onClick={handleMetrics} disabled={busy}>
              Load Metrics
            </Button>
          </div>
        </CardHeader>
        <CardContent data-testid="vm-live-metrics">
          {metrics ? (
            <div className="space-y-1 text-sm">
              <p>CPU: {metrics.cpuUsagePercent}%</p>
              <p>Memory used: {metrics.memoryUsedMb} MB</p>
              <p>Uptime: {metrics.uptimeSeconds} s</p>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No metrics loaded</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Disks</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Label htmlFor="disk-path">Disk path</Label>
              <Input id="disk-path" value={diskPath} onChange={(e) => setDiskPath(e.target.value)} />
            </div>
            <div className="w-24">
              <Label htmlFor="disk-size">Size GB</Label>
              <Input id="disk-size" value={diskSize} onChange={(e) => setDiskSize(e.target.value)} />
            </div>
            <Button size="sm" onClick={handleAttach} disabled={busy}>
              Attach Disk
            </Button>
          </div>
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Label htmlFor="disk-id">Disk ID</Label>
              <Input id="disk-id" value={diskId} onChange={(e) => setDiskId(e.target.value)} />
            </div>
            <div className="w-24">
              <Label htmlFor="disk-new-size">New size GB</Label>
              <Input
                id="disk-new-size"
                value={diskNewSize}
                onChange={(e) => setDiskNewSize(e.target.value)}
              />
            </div>
            <Button size="sm" variant="outline" onClick={handleResize} disabled={busy}>
              Resize Disk
            </Button>
            <Button size="sm" variant="destructive" onClick={askDetach} disabled={busy}>
              Detach Disk
            </Button>
          </div>
          {diskResult && (
            <p className="text-sm" data-testid="vm-disk-result">
              {diskResult}
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Snapshot Operations</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Label htmlFor="snapshot-name">Snapshot name</Label>
              <Input
                id="snapshot-name"
                value={snapshotName}
                onChange={(e) => setSnapshotName(e.target.value)}
              />
            </div>
            <Button size="sm" onClick={handleCreateSnapshot} disabled={busy}>
              Take Snapshot
            </Button>
          </div>
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Label htmlFor="snapshot-id">Snapshot ID</Label>
              <Input id="snapshot-id" value={snapshotId} onChange={(e) => setSnapshotId(e.target.value)} />
            </div>
            <Button size="sm" variant="outline" onClick={handleGetSnapshot} disabled={busy}>
              Get Snapshot
            </Button>
          </div>
          {snapshot && (
            <div className="text-sm" data-testid="vm-snapshot-detail">
              <p>
                {snapshot.config?.name} ({snapshot.id})
              </p>
              <p>Size: {snapshot.sizeBytes} bytes</p>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Migration</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Label htmlFor="migrate-destination">Destination host</Label>
              <Input
                id="migrate-destination"
                value={destination}
                onChange={(e) => setDestination(e.target.value)}
              />
            </div>
            <label className="flex items-center gap-1 text-sm">
              <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
              Live
            </label>
            <Button size="sm" variant="destructive" onClick={askMigrate} disabled={busy}>
              Migrate VM
            </Button>
          </div>
          {migrateResult && (
            <p className="text-sm" data-testid="vm-migrate-result">
              {migrateResult}
            </p>
          )}
        </CardContent>
      </Card>

      <Dialog open={confirm !== null} onOpenChange={(open) => !open && setConfirm(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{confirm?.title}</DialogTitle>
            <DialogDescription>{confirm?.description}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirm(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={runConfirmed}>
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
