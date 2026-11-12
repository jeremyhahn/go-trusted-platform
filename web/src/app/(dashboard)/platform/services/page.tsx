"use client";

import * as React from "react";
import {
  RefreshCw,
  Play,
  Square,
  RotateCcw,
  Server,
  Info,
  AlertCircle,
  Loader2,
  FileCog,
} from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { usePlatformDaemon, useToast } from "@/hooks";
import type { DaemonServiceAction } from "@/hooks";
import type { DaemonServiceInfo } from "trusted-platform-sdk";

/** Badge variant for a daemon or service status string. */
function statusVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  switch (status.toLowerCase()) {
    case "running":
    case "healthy":
    case "ok":
      return "default";
    case "stopped":
      return "secondary";
    case "error":
    case "failed":
      return "destructive";
    default:
      return "outline";
  }
}

/**
 * The version string from a `GET /version` reply. The daemon sends the
 * version flat or wrapped in `version`; accept both.
 */
function versionString(data: unknown): string {
  if (!data || typeof data !== "object") return "-";
  const v = (data as Record<string, unknown>).version;
  if (typeof v === "string") return v;
  if (v && typeof v === "object") {
    const inner = (v as Record<string, unknown>).version;
    if (typeof inner === "string") return inner;
  }
  return "-";
}

const ACTION_LABEL: Record<DaemonServiceAction, string> = {
  start: "Start",
  stop: "Stop",
  restart: "Restart",
};

/**
 * Platform Services Page
 *
 * Daemon status, version and configuration (with reload), and the daemon's
 * services with status details and start, stop and restart. Stop and
 * restart ask for confirmation first.
 */
export default function ServicesPage() {
  const { toast } = useToast();
  const daemon = usePlatformDaemon();
  const [confirm, setConfirm] = React.useState<{ name: string; action: DaemonServiceAction } | null>(null);
  const [detail, setDetail] = React.useState<DaemonServiceInfo | null>(null);

  const services = daemon.services.data?.services ?? [];

  const refreshAll = () => {
    daemon.status.refetch();
    daemon.version.refetch();
    daemon.config.refetch();
    daemon.services.refetch();
  };

  const fail = (title: string, err: unknown) =>
    toast({
      title,
      description: err instanceof Error ? err.message : String(err),
      variant: "destructive",
    });

  const handleReload = async () => {
    try {
      await daemon.reloadConfig();
      toast({ title: "Configuration reloaded" });
    } catch (err) {
      fail("Configuration reload failed", err);
    }
  };

  const runAction = async (name: string, action: DaemonServiceAction) => {
    try {
      const res = await daemon.serviceAction(name, action);
      toast({
        title: `${ACTION_LABEL[action]} ${name}`,
        description: res?.message || "Done",
      });
    } catch (err) {
      fail(`${ACTION_LABEL[action]} ${name} failed`, err);
    }
  };

  const showDetail = async (name: string) => {
    try {
      const info = await daemon.getServiceStatus(name);
      setDetail(info ?? null);
    } catch (err) {
      fail(`Status of ${name} failed`, err);
    }
  };

  const status = daemon.status.data;
  const anyLoading =
    daemon.status.isLoading || daemon.services.isLoading || daemon.config.isLoading;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Platform Services"
        description="Daemon status, configuration and service control"
      >
        <Button variant="outline" size="sm" onClick={refreshAll} disabled={anyLoading}>
          <RefreshCw className={`h-4 w-4 mr-2 ${anyLoading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </PageHeader>

      <div className="grid gap-4 md:grid-cols-2">
        <Card data-testid="daemon-status">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Daemon Status</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent className="space-y-1 text-sm">
            {daemon.status.error ? (
              <span className="text-destructive">{daemon.status.error.message}</span>
            ) : status ? (
              <>
                <Badge variant={statusVariant(status.status)} className="capitalize">
                  {status.status}
                </Badge>
                {status.git_commit && <p>Commit: {status.git_commit}</p>}
                {status.go_version && <p>Go: {status.go_version}</p>}
              </>
            ) : (
              <span className="text-muted-foreground">Loading...</span>
            )}
          </CardContent>
        </Card>
        <Card data-testid="daemon-version">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Version</CardTitle>
            <Info className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono">
              {daemon.version.error ? "-" : versionString(daemon.version.data)}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <div>
            <CardTitle>Configuration</CardTitle>
            <CardDescription>The daemon&apos;s running configuration</CardDescription>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={handleReload}
            disabled={daemon.pending === "reload"}
          >
            <FileCog className="h-4 w-4 mr-2" />
            Reload Config
          </Button>
        </CardHeader>
        <CardContent>
          {daemon.config.error ? (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Error Loading Configuration</AlertTitle>
              <AlertDescription>{daemon.config.error.message}</AlertDescription>
            </Alert>
          ) : (
            <pre
              data-testid="daemon-config"
              className="max-h-80 overflow-auto rounded bg-muted p-3 text-xs"
            >
              {daemon.config.data ? JSON.stringify(daemon.config.data, null, 2) : "Loading..."}
            </pre>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Services</CardTitle>
          <CardDescription>
            View and manage the daemon&apos;s services. Stop and restart ask for confirmation.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {daemon.services.error ? (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Error Loading Services</AlertTitle>
              <AlertDescription>{daemon.services.error.message}</AlertDescription>
            </Alert>
          ) : daemon.services.isLoading ? (
            <div className="flex items-center justify-center h-32">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
              <span className="ml-2">Loading services...</span>
            </div>
          ) : services.length === 0 ? (
            <p className="text-muted-foreground">No services found</p>
          ) : (
            <table className="w-full text-sm" data-testid="services-table">
              <thead>
                <tr className="border-b text-left">
                  <th className="py-2">Service</th>
                  <th className="py-2">Status</th>
                  <th className="py-2">Uptime</th>
                  <th className="py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {services.map((svc) => (
                  <tr key={svc.name} className="border-b" data-testid={`service-row-${svc.name}`}>
                    <td className="py-2 font-medium">{svc.name}</td>
                    <td className="py-2">
                      <Badge variant={statusVariant(svc.status)} className="capitalize">
                        {svc.status}
                      </Badge>
                    </td>
                    <td className="py-2">{svc.uptime || "-"}</td>
                    <td className="py-2">
                      <div className="flex justify-end gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          aria-label={`Details ${svc.name}`}
                          onClick={() => showDetail(svc.name)}
                        >
                          <Info className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          aria-label={`Start ${svc.name}`}
                          disabled={daemon.pending !== null}
                          onClick={() => runAction(svc.name, "start")}
                        >
                          <Play className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          aria-label={`Stop ${svc.name}`}
                          disabled={daemon.pending !== null}
                          onClick={() => setConfirm({ name: svc.name, action: "stop" })}
                        >
                          <Square className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          aria-label={`Restart ${svc.name}`}
                          disabled={daemon.pending !== null}
                          onClick={() => setConfirm({ name: svc.name, action: "restart" })}
                        >
                          <RotateCcw className="h-4 w-4" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      {detail && (
        <Card data-testid="service-detail">
          <CardHeader>
            <CardTitle>Service {detail.name}</CardTitle>
            <CardDescription>Status reported by the daemon</CardDescription>
          </CardHeader>
          <CardContent className="space-y-1 text-sm">
            <p>
              Status:{" "}
              <Badge variant={statusVariant(detail.status)} className="capitalize">
                {detail.status}
              </Badge>
            </p>
            {detail.started_at && <p>Started: {detail.started_at}</p>}
            {detail.uptime && <p>Uptime: {detail.uptime}</p>}
            <p>Starts: {detail.start_count ?? 0}</p>
            <p>Stops: {detail.stop_count ?? 0}</p>
            {detail.last_error && <p className="text-destructive">Last error: {detail.last_error}</p>}
          </CardContent>
        </Card>
      )}

      <Dialog open={confirm !== null} onOpenChange={(open) => !open && setConfirm(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {confirm ? `${ACTION_LABEL[confirm.action]} ${confirm.name}?` : ""}
            </DialogTitle>
            <DialogDescription>
              {confirm?.action === "stop"
                ? "The service stops serving until it is started again."
                : "The service stops and starts again; requests in flight may fail."}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirm(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => {
                if (confirm) void runAction(confirm.name, confirm.action);
                setConfirm(null);
              }}
            >
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
