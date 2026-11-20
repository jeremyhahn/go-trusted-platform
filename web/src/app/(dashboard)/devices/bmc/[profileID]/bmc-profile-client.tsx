"use client";

/**
 * BMC profile page (#1736): power status, boot device, virtual media,
 * sensors, system info, provisioning and the BMC's web certificate. Every
 * action that changes the server (boot device, mount, unmount, provision)
 * runs only after a confirm dialog.
 */

import { useState } from "react";
import { useParams, usePathname, useRouter } from "next/navigation";
import { ArrowLeft, Disc, HardDrive, Power, RefreshCw, Rocket, ShieldCheck, Thermometer } from "lucide-react";
import { resolveDynamicId } from "@/utils/dynamic-route";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useBMC, useToast } from "@/hooks";
import type { BMCPart } from "@/hooks";

// The boot devices the server accepts (pkg/bmc/types.go); any other is a 400.
const BOOT_DEVICES = ["none", "pxe", "disk", "cdrom", "virtual_media"];

interface PendingAction {
  title: string;
  description: string;
  run: () => Promise<void>;
  done: string;
}

function PartError({ errors, part }: { errors: Partial<Record<BMCPart, string>>; part: BMCPart }) {
  const message = errors[part];
  if (!message) return null;
  return (
    <p className="text-sm text-destructive" data-testid={`bmc-${part}-error`}>
      {message}
    </p>
  );
}

export default function BMCProfileClient() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const { toast } = useToast();
  const profileID = resolveDynamicId(params, pathname, "bmc", "profileID");
  const bmc = useBMC(profileID);

  const [bootDevice, setBootDevice] = useState("pxe");
  const [image, setImage] = useState("");
  const [pending, setPending] = useState<PendingAction | null>(null);
  const [running, setRunning] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const ask = (action: PendingAction) => {
    setActionError(null);
    setPending(action);
  };

  const confirm = async () => {
    if (!pending) return;
    setRunning(true);
    setActionError(null);
    try {
      await pending.run();
      toast({ title: "Success", description: pending.done });
      setPending(null);
    } catch (e: unknown) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  };

  if (!profileID) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <p className="text-lg font-medium">Select a BMC profile</p>
        <Button className="mt-4" onClick={() => router.push("/devices/bmc")}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to BMC
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" aria-label="Back" onClick={() => router.push("/devices/bmc")}>
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold tracking-tight">BMC {profileID}</h1>
            <p className="text-muted-foreground">Power, boot device, virtual media, sensors and provisioning</p>
          </div>
        </div>
        <Button variant="outline" onClick={() => void bmc.refetch()} disabled={bmc.isLoading}>
          <RefreshCw className="mr-2 h-4 w-4" />
          Refresh
        </Button>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Power className="h-5 w-5" />
              Power
            </CardTitle>
            <CardDescription>Current chassis power state</CardDescription>
          </CardHeader>
          <CardContent>
            {bmc.power && (
              <Badge data-testid="bmc-power-state" variant="outline">
                {bmc.power.state}
              </Badge>
            )}
            <PartError errors={bmc.errors} part="power" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>System</CardTitle>
            <CardDescription>What the BMC reports about the server</CardDescription>
          </CardHeader>
          <CardContent>
            {bmc.systemInfo && (
              <dl className="grid grid-cols-2 gap-2 text-sm" data-testid="bmc-system-info">
                <dt className="text-muted-foreground">Manufacturer</dt>
                <dd>{bmc.systemInfo.manufacturer || "-"}</dd>
                <dt className="text-muted-foreground">Product</dt>
                <dd>{bmc.systemInfo.product || "-"}</dd>
                <dt className="text-muted-foreground">Serial number</dt>
                <dd>{bmc.systemInfo.serial_number || "-"}</dd>
                <dt className="text-muted-foreground">Firmware</dt>
                <dd>{bmc.systemInfo.firmware_version || "-"}</dd>
                <dt className="text-muted-foreground">BIOS</dt>
                <dd>{bmc.systemInfo.bios_version || "-"}</dd>
              </dl>
            )}
            <PartError errors={bmc.errors} part="systemInfo" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <HardDrive className="h-5 w-5" />
              Boot device
            </CardTitle>
            <CardDescription>The device the server boots from next</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {bmc.bootDevice && (
              <p className="text-sm">
                Current: <span data-testid="bmc-boot-device">{bmc.bootDevice.device}</span>
                {bmc.bootDevice.persistent ? " (persistent)" : ""}
              </p>
            )}
            <PartError errors={bmc.errors} part="bootDevice" />
            <div className="flex items-end gap-2">
              <div className="flex-1">
                <Label htmlFor="bmc-boot-select">New boot device</Label>
                <select
                  id="bmc-boot-select"
                  className="mt-1 block w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  value={bootDevice}
                  onChange={(e) => setBootDevice(e.target.value)}
                >
                  {BOOT_DEVICES.map((d) => (
                    <option key={d} value={d}>
                      {d}
                    </option>
                  ))}
                </select>
              </div>
              <Button
                onClick={() =>
                  ask({
                    title: "Set boot device",
                    description: `The server will boot from ${bootDevice} on its next start.`,
                    run: () => bmc.setBootDevice({ device: bootDevice, persistent: false }),
                    done: `Boot device set to ${bootDevice}`,
                  })
                }
              >
                Set boot device
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Disc className="h-5 w-5" />
              Virtual media
            </CardTitle>
            <CardDescription>ISO image attached through the BMC</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {bmc.virtualMedia && (
              <p className="text-sm" data-testid="bmc-virtual-media">
                {bmc.virtualMedia.mounted ? bmc.virtualMedia.image_url ?? "" : "No media"}
              </p>
            )}
            <PartError errors={bmc.errors} part="virtualMedia" />
            <div className="flex items-end gap-2">
              <div className="flex-1">
                <Label htmlFor="bmc-iso-url">ISO URL</Label>
                <Input
                  id="bmc-iso-url"
                  value={image}
                  onChange={(e) => setImage(e.target.value)}
                  placeholder="ISO URL"
                />
              </div>
              <Button
                disabled={!image.trim()}
                onClick={() =>
                  ask({
                    title: "Mount ISO",
                    description: `Attach ${image.trim()} to the server as virtual media.`,
                    run: () => bmc.mountISO(image.trim()),
                    done: "ISO mounted",
                  })
                }
              >
                Mount ISO
              </Button>
              <Button
                variant="outline"
                disabled={!bmc.virtualMedia?.mounted}
                onClick={() =>
                  ask({
                    title: "Unmount ISO",
                    description: "Detach the virtual media from the server.",
                    run: () => bmc.unmountISO(),
                    done: "ISO unmounted",
                  })
                }
              >
                Unmount ISO
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Rocket className="h-5 w-5" />
              Host provisioning
            </CardTitle>
            <CardDescription>
              Installs an operating system on this host over the network. The host is shut down and its disks can be
              overwritten.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {bmc.provisionStatus && (
              <p className="text-sm">
                Status: <span data-testid="bmc-provision-state">{bmc.provisionStatus.status}</span>
                {bmc.provisionStatus.message ? ` — ${bmc.provisionStatus.message}` : ""}
              </p>
            )}
            <PartError errors={bmc.errors} part="provisionStatus" />
            <Button
              variant="destructive"
              onClick={() =>
                ask({
                  title: "Provision host",
                  description:
                    "Provisioning powers the host off, boots it once from the network (PXE), installs an operating " +
                    "system, then sets disk boot and power-cycles it. Running workloads stop and the host's disks " +
                    "can be overwritten.",
                  run: () => bmc.provision(),
                  done: "Host provisioning started",
                })
              }
            >
              Provision
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5" />
              Web certificate
            </CardTitle>
            <CardDescription>The TLS certificate the BMC serves</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {bmc.certificate && (
              <div data-testid="bmc-certificate" className="space-y-1 text-sm">
                <p>Subject: {bmc.certificate.subject || "-"}</p>
                <p>Issuer: {bmc.certificate.issuer || "-"}</p>
                <p>
                  Expires: {bmc.certificate.not_after || "-"} ({bmc.certificate.days_remaining} days remaining)
                </p>
                <p className="break-all font-mono text-xs">Fingerprint: {bmc.certificate.fingerprint || "-"}</p>
              </div>
            )}
            <PartError errors={bmc.errors} part="certificate" />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Thermometer className="h-5 w-5" />
            Sensors
          </CardTitle>
          <CardDescription>Temperatures, fans and voltages</CardDescription>
        </CardHeader>
        <CardContent>
          <PartError errors={bmc.errors} part="sensors" />
          {bmc.sensors && (
            <Table data-testid="bmc-sensors">
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Reading</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {bmc.sensors.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} className="text-center text-muted-foreground">
                      No sensors reported
                    </TableCell>
                  </TableRow>
                ) : (
                  bmc.sensors.map((s) => (
                    <TableRow key={s.name}>
                      <TableCell>{s.name}</TableCell>
                      <TableCell>
                        {s.value} {s.units}
                      </TableCell>
                      <TableCell>{s.status || "-"}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog open={pending !== null} onOpenChange={(open) => !open && !running && setPending(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{pending?.title}</DialogTitle>
            <DialogDescription>{pending?.description}</DialogDescription>
          </DialogHeader>
          {actionError && (
            <p className="text-sm text-destructive" data-testid="bmc-action-error">
              {actionError}
            </p>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setPending(null)} disabled={running}>
              Cancel
            </Button>
            <Button onClick={() => void confirm()} disabled={running}>
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
