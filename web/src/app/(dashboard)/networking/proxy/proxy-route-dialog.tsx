"use client";

import * as React from "react";
import type { ProxyRoute } from "trusted-platform-sdk";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

/** The editable fields of a proxy route, as the form holds them. */
export interface ProxyRouteFormValues {
  id: string;
  hosts: string;
  pathPrefix: string;
  poolId: string;
}

/** "a.example, b.example" -> ["a.example", "b.example"]; trims, drops empty entries. */
export function parseProxyHosts(s: string): string[] {
  return s
    .split(",")
    .map((h) => h.trim())
    .filter((h) => h !== "");
}

/** Form values of a route: hosts joined by ", ", missing fields as "". */
export function proxyRouteToForm(route: ProxyRoute): ProxyRouteFormValues {
  return {
    id: route.id ?? "",
    hosts: (route.hosts ?? []).join(", "),
    pathPrefix: route.pathPrefix ?? "",
    poolId: route.poolId ?? "",
  };
}

/**
 * The route to send: base (the fetched route on edit, {} on create) with id,
 * hosts, pathPrefix and poolId from the form; id, pathPrefix and poolId
 * trimmed. Other fields of base (auth, stripPrefix, ...) are kept.
 */
export function proxyRouteFromForm(
  values: ProxyRouteFormValues,
  base: ProxyRoute = {},
): ProxyRoute {
  return {
    ...base,
    id: values.id.trim(),
    hosts: parseProxyHosts(values.hosts),
    pathPrefix: values.pathPrefix.trim(),
    poolId: values.poolId.trim(),
  };
}

/** Create or edit dialog for a proxy route. */
export function ProxyRouteDialog(props: {
  open: boolean;
  mode: "create" | "edit";
  initial: ProxyRouteFormValues;
  saving: boolean;
  onCancel: () => void;
  onSave: (values: ProxyRouteFormValues) => void;
}) {
  const { open, mode, initial, saving, onCancel, onSave } = props;
  const [values, setValues] = React.useState<ProxyRouteFormValues>(initial);

  React.useEffect(() => {
    if (open) setValues(initial);
  }, [open, initial]);

  const set =
    (field: keyof ProxyRouteFormValues) =>
    (e: React.ChangeEvent<HTMLInputElement>) =>
      setValues((v) => ({ ...v, [field]: e.target.value }));

  const blank = values.id.trim() === "" || values.poolId.trim() === "";

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o && !saving) onCancel();
      }}
    >
      <DialogContent aria-describedby={undefined}>
        <DialogHeader>
          <DialogTitle>{mode === "create" ? "New route" : "Edit route"}</DialogTitle>
        </DialogHeader>
        <div className="grid gap-3">
          <Input
            aria-label="Route ID"
            placeholder="Route ID"
            value={values.id}
            onChange={set("id")}
            disabled={mode === "edit"}
          />
          <Input
            aria-label="Hosts"
            placeholder="Hosts, comma-separated (empty = any)"
            value={values.hosts}
            onChange={set("hosts")}
          />
          <Input
            aria-label="Path prefix"
            placeholder="Path prefix, for example /api"
            value={values.pathPrefix}
            onChange={set("pathPrefix")}
          />
          <Input
            aria-label="Pool ID"
            placeholder="Pool ID"
            value={values.poolId}
            onChange={set("poolId")}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onCancel} disabled={saving}>
            Cancel
          </Button>
          <Button onClick={() => onSave(values)} disabled={saving || blank}>
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
