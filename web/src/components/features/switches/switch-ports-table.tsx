"use client";

import * as React from "react";
import type { SwitchPortStatus } from "trusted-platform-sdk";
import { Gated } from "@/components/features/capabilities/gated";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/hooks";

export interface SwitchPortsTableProps {
  switchName: string;
  ports: SwitchPortStatus[];
  onEnable: (port: string) => Promise<unknown>;
  onDisable: (port: string) => Promise<unknown>;
  onSetVLAN: (port: string, vlanId: number) => Promise<unknown>;
}

const VLAN_ERROR = "VLAN must be 1-4094";

function vlanText(p: SwitchPortStatus): string {
  if (p.mode !== "trunk") {
    return String(p.access_vlan);
  }
  const parts: string[] = [];
  if (p.trunk_vlans && p.trunk_vlans.length > 0) {
    parts.push(p.trunk_vlans.join(", "));
  }
  if (p.native_vlan !== undefined) {
    parts.push(`native ${p.native_vlan}`);
  }
  return parts.join(" · ");
}

// SwitchPortsTable shows a switch's ports with Enable or Disable and a
// Set VLAN field per row, each gated on its switch route (#2066).
export function SwitchPortsTable({ switchName, ports, onEnable, onDisable, onSetVLAN }: SwitchPortsTableProps) {
  const { toast } = useToast();
  const [vlans, setVlans] = React.useState<Record<string, string>>({});
  const [errors, setErrors] = React.useState<Record<string, string>>({});

  const run = async (call: () => Promise<unknown>) => {
    try {
      await call();
    } catch (err) {
      toast({
        title: "Switch request failed",
        description: err instanceof Error ? err.message : String(err),
        variant: "destructive",
      });
    }
  };

  const setVLAN = (port: string) => {
    const raw = (vlans[port] ?? "").trim();
    const vlanId = Number(raw);
    if (raw === "" || !Number.isInteger(vlanId) || vlanId < 1 || vlanId > 4094) {
      setErrors((e) => ({ ...e, [port]: VLAN_ERROR }));
      return;
    }
    setErrors((e) => {
      const next = { ...e };
      delete next[port];
      return next;
    });
    void run(() => onSetVLAN(port, vlanId));
  };

  return (
    <Table>
      <TableCaption>Ports on {switchName}</TableCaption>
      <TableHeader>
        <TableRow>
          <TableHead>Port</TableHead>
          <TableHead>Mode</TableHead>
          <TableHead>VLAN</TableHead>
          <TableHead>Admin</TableHead>
          <TableHead>Link</TableHead>
          <TableHead>Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {ports.map((p) => (
          <TableRow key={p.port} data-testid={`switch-port-${p.port}`}>
            <TableCell>{p.port}</TableCell>
            <TableCell>{p.mode}</TableCell>
            <TableCell>{vlanText(p)}</TableCell>
            <TableCell>{p.enabled ? "Enabled" : "Disabled"}</TableCell>
            <TableCell>{p.link_up ? "Up" : "Down"}</TableCell>
            <TableCell>
              <div className="flex items-center gap-2">
                {p.enabled ? (
                  <Gated op="POST /api/v1/switches/{switch}/ports/{port}/disable">
                    <Button variant="outline" size="sm" onClick={() => void run(() => onDisable(p.port))}>
                      Disable
                    </Button>
                  </Gated>
                ) : (
                  <Gated op="POST /api/v1/switches/{switch}/ports/{port}/enable">
                    <Button variant="outline" size="sm" onClick={() => void run(() => onEnable(p.port))}>
                      Enable
                    </Button>
                  </Gated>
                )}
                <Input
                  type="number"
                  min={1}
                  max={4094}
                  className="w-24"
                  aria-label={`VLAN for ${p.port}`}
                  value={vlans[p.port] ?? ""}
                  onChange={(e) => setVlans((v) => ({ ...v, [p.port]: e.target.value }))}
                />
                <Gated op="POST /api/v1/switches/{switch}/ports/{port}/vlan">
                  <Button variant="outline" size="sm" onClick={() => setVLAN(p.port)}>
                    Set VLAN
                  </Button>
                </Gated>
              </div>
              {errors[p.port] ? (
                <p role="alert" className="mt-1 text-sm text-destructive">
                  {errors[p.port]}
                </p>
              ) : null}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
