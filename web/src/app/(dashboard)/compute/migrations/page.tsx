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
import type { PrepareMigrationResponse, VMMigrationSpec } from "trusted-platform-sdk";

export default function MigrationsPage() {
  const ops = useVMOperations();
  const busy = ops.pending !== null;

  const [vmName, setVmName] = useState("");
  const [sourceVmId, setSourceVmId] = useState("");
  const [mode, setMode] = useState<"cold" | "live">("live");
  const [receiver, setReceiver] = useState<PrepareMigrationResponse | null>(null);

  // The source guest's configuration: the daemon refuses a prepare without it.
  const [memoryMb, setMemoryMb] = useState("");
  const [cpus, setCpus] = useState("");
  const [diskSize, setDiskSize] = useState("");
  const [bootMode, setBootMode] = useState("");
  const [arch, setArch] = useState<"x86_64" | "aarch64">("x86_64");
  const [secureBoot, setSecureBoot] = useState(false);
  const [tpmEnabled, setTpmEnabled] = useState(false);
  const [enableKvm, setEnableKvm] = useState(true);
  // The receiver's NIC must match the source guest's or its migration state
  // does not load; the daemon defaults an empty mode to bridge.
  const [networkMode, setNetworkMode] = useState<"bridge" | "user" | "none">("bridge");
  const [macAddress, setMacAddress] = useState("");

  const [receiverId, setReceiverId] = useState("");
  const [confirmCommit, setConfirmCommit] = useState<boolean | null>(null);
  const [finalizeResult, setFinalizeResult] = useState("");

  const positiveInt = (value: string) => (/^[1-9][0-9]*$/.test(value.trim()) ? Number(value.trim()) : 0);
  const specMemoryMb = positiveInt(memoryMb);
  const specCpus = positiveInt(cpus);
  const specValid = specMemoryMb > 0 && specCpus > 0;

  const handlePrepare = async () => {
    // One outstanding receiver at a time: each holds a QEMU process until finalized.
    if (receiver || !vmName || !specValid) return;
    const spec: VMMigrationSpec = { memoryMb: specMemoryMb, cpus: specCpus };
    if (diskSize.trim()) spec.diskSize = diskSize.trim();
    if (bootMode.trim()) spec.bootMode = bootMode.trim();
    spec.arch = arch;
    spec.secureBoot = secureBoot;
    spec.tpmEnabled = tpmEnabled;
    spec.enableKvm = enableKvm;
    spec.networkMode = networkMode;
    if (macAddress.trim()) spec.macAddress = macAddress.trim();
    const result = await ops.prepareMigration({
      vmName,
      vmId: sourceVmId || undefined,
      mode,
      spec,
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
      if (receiverId === receiver?.receiverId) setReceiver(null);
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
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label htmlFor="migration-memory-mb">Memory MB</Label>
                <Input
                  id="migration-memory-mb"
                  inputMode="numeric"
                  value={memoryMb}
                  onChange={(e) => setMemoryMb(e.target.value)}
                />
              </div>
              <div>
                <Label htmlFor="migration-cpus">CPUs</Label>
                <Input
                  id="migration-cpus"
                  inputMode="numeric"
                  value={cpus}
                  onChange={(e) => setCpus(e.target.value)}
                />
              </div>
              <div>
                <Label htmlFor="migration-disk-size">Disk size</Label>
                <Input
                  id="migration-disk-size"
                  placeholder="20G"
                  value={diskSize}
                  onChange={(e) => setDiskSize(e.target.value)}
                />
              </div>
              <div>
                <Label htmlFor="migration-boot-mode">Boot mode</Label>
                <Input
                  id="migration-boot-mode"
                  value={bootMode}
                  onChange={(e) => setBootMode(e.target.value)}
                />
              </div>
              <div>
                <Label htmlFor="migration-arch">Arch</Label>
                <select
                  id="migration-arch"
                  className="block w-full rounded-md border px-2 py-1 text-sm bg-background"
                  value={arch}
                  onChange={(e) => setArch(e.target.value === "aarch64" ? "aarch64" : "x86_64")}
                >
                  <option value="x86_64">x86_64</option>
                  <option value="aarch64">aarch64</option>
                </select>
              </div>
              <div className="flex flex-col justify-end gap-1 text-sm">
                <label className="flex items-center gap-2" htmlFor="migration-secure-boot">
                  <input
                    id="migration-secure-boot"
                    type="checkbox"
                    checked={secureBoot}
                    onChange={(e) => setSecureBoot(e.target.checked)}
                  />
                  Secure boot
                </label>
                <label className="flex items-center gap-2" htmlFor="migration-tpm">
                  <input
                    id="migration-tpm"
                    type="checkbox"
                    checked={tpmEnabled}
                    onChange={(e) => setTpmEnabled(e.target.checked)}
                  />
                  TPM
                </label>
                <label className="flex items-center gap-2" htmlFor="migration-kvm">
                  <input
                    id="migration-kvm"
                    type="checkbox"
                    checked={enableKvm}
                    onChange={(e) => setEnableKvm(e.target.checked)}
                  />
                  KVM acceleration
                </label>
              </div>
              <div>
                <Label htmlFor="migration-network-mode">Network mode</Label>
                <select
                  id="migration-network-mode"
                  className="block w-full rounded-md border px-2 py-1 text-sm bg-background"
                  value={networkMode}
                  onChange={(e) =>
                    setNetworkMode(
                      e.target.value === "user" ? "user" : e.target.value === "none" ? "none" : "bridge",
                    )
                  }
                >
                  <option value="bridge">bridge</option>
                  <option value="user">user</option>
                  <option value="none">none</option>
                </select>
              </div>
              <div>
                <Label htmlFor="migration-mac-address">MAC address</Label>
                <Input
                  id="migration-mac-address"
                  placeholder="MAC address"
                  value={macAddress}
                  onChange={(e) => setMacAddress(e.target.value)}
                />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              Enter the source guest&apos;s network mode and MAC address so the received VM keeps the same NIC
            </p>
            <Button onClick={handlePrepare} disabled={busy || receiver !== null || !vmName || !specValid}>
              Prepare Migration
            </Button>
            {receiver && (
              <div className="text-sm" data-testid="migration-receiver">
                <p>Receiver: {receiver.receiverId}</p>
                <p>Port: {receiver.port}</p>
                <p>TLS name: {receiver.tlsHostname}</p>
                <p className="text-muted-foreground">Commit or abort this receiver before preparing another</p>
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
