"use client";

import * as React from "react";
import type { ProxyBackend, ProxyPool } from "trusted-platform-sdk";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";

export interface ProxyPoolFormValues {
  id: string;
  backends: string;
  balancer: string;
}

/** One backend per line: "<url>" or "<url> <weight>"; blank lines dropped; weight a positive integer, else the backend has no weight. */
export function parseProxyBackends(s: string): ProxyBackend[] {
  const out: ProxyBackend[] = [];
  for (const line of s.split("\n")) {
    const fields = line.trim().split(/\s+/).filter((f) => f !== "");
    if (fields.length === 0) continue;
    const backend: ProxyBackend = { url: fields[0] };
    const w = fields[1];
    if (w !== undefined && /^\d+$/.test(w) && Number(w) > 0) {
      backend.weight = Number(w);
    }
    out.push(backend);
  }
  return out;
}

/** Backends one per line as "<url>" or "<url> <weight>"; balancer "" when unset. */
export function proxyPoolToForm(pool: ProxyPool): ProxyPoolFormValues {
  return {
    id: pool.id ?? "",
    backends: (pool.backends ?? [])
      .map((b) => (b.weight ? `${b.url ?? ""} ${b.weight}` : b.url ?? ""))
      .join("\n"),
    balancer: pool.balancer ?? "",
  };
}

/** base (the fetched pool on edit, {} on create) with id (trimmed), backends and balancer (trimmed; omitted when blank) from the form; tls and the connection fields of base are kept. */
export function proxyPoolFromForm(values: ProxyPoolFormValues, base: ProxyPool = {}): ProxyPool {
  const pool: ProxyPool = { ...base, id: values.id.trim(), backends: parseProxyBackends(values.backends) };
  const balancer = values.balancer.trim();
  if (balancer) {
    pool.balancer = balancer;
  } else {
    delete pool.balancer;
  }
  return pool;
}

/** Create or edit dialog for one backend pool. */
export function ProxyPoolDialog(props: {
  open: boolean;
  mode: "create" | "edit";
  initial: ProxyPoolFormValues;
  saving: boolean;
  onCancel: () => void;
  onSave: (values: ProxyPoolFormValues) => void;
}): React.JSX.Element {
  const { open, mode, initial, saving, onCancel, onSave } = props;
  const [values, setValues] = React.useState<ProxyPoolFormValues>(initial);

  React.useEffect(() => {
    if (open) setValues(initial);
  }, [open, initial]);

  const canSave = !saving && values.id.trim() !== "" && parseProxyBackends(values.backends).length > 0;

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next && !saving) onCancel();
      }}
    >
      <DialogContent aria-describedby={undefined}>
        <DialogHeader>
          <DialogTitle>{mode === "create" ? "New pool" : "Edit pool"}</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <Input
            aria-label="Pool ID"
            placeholder="Pool ID"
            value={values.id}
            disabled={mode === "edit"}
            onChange={(e) => setValues((v) => ({ ...v, id: e.target.value }))}
          />
          <Textarea
            aria-label="Backends"
            placeholder="https://backend.example:8443 1"
            value={values.backends}
            onChange={(e) => setValues((v) => ({ ...v, backends: e.target.value }))}
          />
          <Input
            aria-label="Balancer"
            placeholder="round-robin"
            value={values.balancer}
            onChange={(e) => setValues((v) => ({ ...v, balancer: e.target.value }))}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onCancel} disabled={saving}>
            Cancel
          </Button>
          <Button onClick={() => onSave(values)} disabled={!canSave}>
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
