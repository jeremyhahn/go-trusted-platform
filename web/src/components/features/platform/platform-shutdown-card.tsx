"use client";

import * as React from "react";
import { usePlatformClient } from "trusted-platform-sdk";
import { Gated } from "@/components/features/capabilities/gated";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";

/** The server's op string the Shut down button is gated on. */
export const SHUTDOWN_OP = "POST /api/v1/platform/shutdown";

/**
 * PlatformShutdownCard offers Shutdown (POST /platform/shutdown). The
 * button follows the server's capabilities and only opens a confirm
 * dialog; the request is sent once the operator confirms.
 */
export function PlatformShutdownCard() {
  const client = usePlatformClient();
  const api = React.useMemo(() => client.getApiClient(), [client]);
  const { toast } = useToast();
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  const shutdown = async () => {
    setBusy(true);
    try {
      const res = await api.post<unknown>("/v1/platform/shutdown", { graceful: true });
      if (res.error) {
        toast({
          title: "Shutdown refused",
          description:
            res.error.status !== undefined
              ? `HTTP ${res.error.status}: ${res.error.message}`
              : res.error.message,
          variant: "destructive",
        });
        return;
      }
      toast({ title: "Shutdown requested", description: "The daemon is shutting down." });
      setOpen(false);
    } catch (err) {
      toast({
        title: "Shutdown failed",
        description: err instanceof Error ? err.message : String(err),
        variant: "destructive",
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="platform-shutdown">
      <CardHeader>
        <CardTitle>Shutdown</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <p className="text-muted-foreground">
          Stops the platform daemon gracefully. The control plane goes offline until the daemon is started again.
        </p>
        <Gated op={SHUTDOWN_OP}>
          <Button variant="destructive" onClick={() => setOpen(true)}>
            Shut down
          </Button>
        </Gated>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Shut the daemon down?</DialogTitle>
              <DialogDescription>
                Every service of this platform stops and this console loses its control plane.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
                Cancel
              </Button>
              <Button variant="destructive" onClick={() => void shutdown()} disabled={busy}>
                Shut down the daemon
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}
