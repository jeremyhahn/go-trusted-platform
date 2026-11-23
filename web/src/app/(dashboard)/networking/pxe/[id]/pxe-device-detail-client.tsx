"use client";

import * as React from "react";
import { useParams, usePathname } from "next/navigation";
import type { ProvisioningState } from "trusted-platform-sdk";
import { resolveDynamicId } from "@/utils/dynamic-route";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useApi, usePXE, useToast } from "@/hooks";
import { useCapabilities } from "@/hooks/use-capabilities";
import { Gated } from "@/components/features/capabilities/gated";

const GET_DEVICE_OP = "GET /api/v1/pxe/devices/{id}";
const GET_EVENTS_OP = "GET /api/v1/pxe/devices/{id}/events";
const UPDATE_STATE_OP = "PUT /api/v1/pxe/devices/{id}/state";

/** The states an operator may set (ProvisioningState without UNSPECIFIED). */
const SETTABLE_STATES: ProvisioningState[] = [
  "UNKNOWN",
  "DISCOVERED",
  "BOOTING",
  "INSTALLING",
  "INSTALL_COMPLETE",
  "ENROLLING",
  "ENROLLED",
  "AUTHORIZING",
  "AUTHORIZED",
  "FAILED",
  "QUARANTINED",
];

function eventDetail(details: Record<string, string> | undefined, error: string | undefined): string {
  if (error) return error;
  if (!details) return "-";
  const parts = Object.entries(details).map(([k, v]) => `${k}=${v}`);
  return parts.length > 0 ? parts.join(", ") : "-";
}

/**
 * PXE device detail page: one device on `/api/v1/pxe/devices/{id}` through
 * GetDevice, GetEvents and UpdateState on `client.pxe`, each gated on its
 * route in the server's capabilities listing.
 */
export default function PXEDeviceDetailClient() {
  const params = useParams<{ id: string }>();
  const pathname = usePathname();
  const id = resolveDynamicId(params, pathname, "pxe", "id");
  const pxe = usePXE();
  const { toast } = useToast();
  const { loading: capsLoading, capability } = useCapabilities();

  const deviceCap = capability(GET_DEVICE_OP);
  const device = useApi(() => pxe.getDevice(id), [pxe, id], {
    enabled: !capsLoading && deviceCap.enabled,
  });
  const eventsCap = capability(GET_EVENTS_OP);
  const events = useApi(() => pxe.getEvents(id), [pxe, id], {
    enabled: !capsLoading && eventsCap.enabled,
  });

  const [state, setState] = React.useState<ProvisioningState>("FAILED");
  const [reason, setReason] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const onSetState = async () => {
    setBusy(true);
    try {
      const res = await pxe.updateState({ deviceId: id, state, reason });
      if (res.success === false) {
        toast({
          title: "PXE request failed",
          description: res.error?.message,
          variant: "destructive",
        });
        return;
      }
      toast({ title: "Device state set", description: `state ${state}` });
      setReason("");
      void device.refetch();
      void events.refetch();
    } catch (err) {
      toast({
        title: "PXE request failed",
        description: err instanceof Error ? err.message : String(err),
        variant: "destructive",
      });
    } finally {
      setBusy(false);
    }
  };

  const info = device.data?.device;
  const eventList = events.data?.events ?? [];

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title="PXE device" description={id} />

      {!capsLoading && !deviceCap.enabled ? (
        <Card data-testid="pxe-device-not-enabled">
          <CardContent className="pt-6 text-sm text-muted-foreground">
            Device reads are not enabled on this server: {deviceCap.reason ?? "not offered"}
          </CardContent>
        </Card>
      ) : (
        <Card data-testid="pxe-device">
          <CardHeader>
            <CardTitle className="text-base">Device</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3 text-sm">
            {device.error ? (
              <p role="alert" className="text-destructive">
                {device.error.message}
              </p>
            ) : !info ? (
              <p className="text-muted-foreground">Loading device...</p>
            ) : (
              <>
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">MAC address</span>
                  <span className="font-mono">{info.macAddress}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">State</span>
                  <Badge variant="outline">{info.state}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Current VLAN</span>
                  <span>{info.currentVlan ?? "-"}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Target VLAN</span>
                  <span>{info.targetVlan ?? "-"}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Certificate serial</span>
                  <span className="font-mono">{info.certificateSerial || "-"}</span>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Set state</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          <select
            aria-label="New state"
            className="flex h-9 w-56 rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm"
            value={state}
            onChange={(e) => setState(e.target.value as ProvisioningState)}
          >
            {SETTABLE_STATES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <Input
            aria-label="State reason"
            className="w-72"
            placeholder="Reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
          <Gated op={UPDATE_STATE_OP}>
            <Button onClick={() => void onSetState()} disabled={busy}>
              Set state
            </Button>
          </Gated>
        </CardContent>
      </Card>

      {!capsLoading && eventsCap.enabled && (
        <Card data-testid="pxe-device-events">
          <CardHeader>
            <CardTitle className="text-base">Provisioning events</CardTitle>
          </CardHeader>
          <CardContent>
            {events.error ? (
              <p role="alert" className="text-sm text-destructive">
                {events.error.message}
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Event</TableHead>
                    <TableHead>From</TableHead>
                    <TableHead>To</TableHead>
                    <TableHead>Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {eventList.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-muted-foreground">
                        No events
                      </TableCell>
                    </TableRow>
                  ) : (
                    eventList.map((e) => (
                      <TableRow key={e.id}>
                        <TableCell className="font-mono text-xs">{e.timestamp}</TableCell>
                        <TableCell>{e.eventType}</TableCell>
                        <TableCell>{e.fromState ?? "-"}</TableCell>
                        <TableCell>{e.toState ?? "-"}</TableCell>
                        <TableCell>{eventDetail(e.details, e.error)}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
