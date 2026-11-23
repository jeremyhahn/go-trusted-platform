"use client";

/**
 * The CA overview's lifecycle controls (#2041): InitCA, InstallCACertificates
 * and UninstallCACertificates through the SDK CAService, each gated on its
 * route in GET /api/v1/capabilities. Initialize CA never forces: re-keying
 * an initialized CA is not offered here.
 */

import * as React from "react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Gated } from "@/components/features/capabilities/gated";
import { useCA, useToast } from "@/hooks";

interface LifecycleAnswer<T> {
  success?: boolean;
  data?: T;
  error?: { message?: string };
}

export function CALifecycleControls() {
  const ca = useCA();
  const { toast } = useToast();
  const [includeIntermediates, setIncludeIntermediates] = React.useState(false);
  const [confirmOpen, setConfirmOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  const run = async <T,>(call: () => Promise<LifecycleAnswer<T>>, describe: (data: T | undefined) => string) => {
    setBusy(true);
    try {
      const res = await call();
      if (res.success === false) {
        toast({ title: "CA request failed", description: res.error?.message, variant: "destructive" });
        return;
      }
      toast({ title: "CA request done", description: describe(res.data), variant: "success" });
    } catch (err) {
      toast({
        title: "CA request failed",
        description: err instanceof Error ? err.message : String(err),
        variant: "destructive",
      });
    } finally {
      setBusy(false);
    }
  };

  const onInit = () =>
    run(
      () => ca.initCA({ force: false }),
      (data) => data?.status?.message || "CA initialized",
    );

  const onInstall = () =>
    run(
      () => ca.installCACertificates({ includeIntermediates }),
      (data) => `Installed ${data?.certificatesInstalled ?? 0} certificate(s) to ${data?.installPath ?? ""}`.trim(),
    );

  const onUninstall = async () => {
    setConfirmOpen(false);
    await run(
      () => ca.uninstallCACertificates({ includeIntermediates }),
      (data) => `Removed ${data?.certificatesRemoved ?? 0} certificate(s)`,
    );
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Checkbox
          id="ca-include-intermediates"
          checked={includeIntermediates}
          onCheckedChange={(v) => setIncludeIntermediates(v === true)}
        />
        <Label htmlFor="ca-include-intermediates">Include intermediates</Label>
      </div>
      <div className="flex flex-wrap gap-2">
        <Gated op="POST /api/v1/ca/init">
          <Button variant="outline" data-testid="ca-init-control" disabled={busy} onClick={onInit}>
            Initialize CA
          </Button>
        </Gated>
        <Gated op="POST /api/v1/ca/trust/install">
          <Button variant="outline" data-testid="ca-install-control" disabled={busy} onClick={onInstall}>
            Install CA certificates
          </Button>
        </Gated>
        <Gated op="POST /api/v1/ca/trust/uninstall">
          <Button
            variant="outline"
            data-testid="ca-uninstall-control"
            disabled={busy}
            onClick={() => setConfirmOpen(true)}
          >
            Uninstall CA certificates
          </Button>
        </Gated>
      </div>
      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Uninstall CA certificates?</DialogTitle>
            <DialogDescription>
              The CA certificates{includeIntermediates ? " and the intermediates" : ""} are removed from the
              host trust store.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={onUninstall}>
              Uninstall
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
