"use client";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { usePlatformProbes, type PlatformProbes } from "@/hooks/use-platform-probes";

/**
 * PlatformProbesCard shows the control plane's GET /platform/status,
 * /platform/liveness and /platform/readiness. It is read-only; a refused
 * read shows in its own row and the others still show.
 */
export function PlatformProbesCard() {
  const { probes, errors, isLoading, refetch } = usePlatformProbes();
  const { status, liveness, readiness } = probes;

  const row = (key: keyof PlatformProbes, label: string, value: string | null) => (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd>
        {errors[key] ? (
          <span role="alert" data-testid={`probe-${key}-error`} className="text-destructive">
            {errors[key]}
          </span>
        ) : (
          <span data-testid={`probe-${key}`}>{value ?? (isLoading ? "Loading…" : "—")}</span>
        )}
      </dd>
    </>
  );

  const sys = status?.system;
  const statusText = status
    ? `${status.status ?? "—"} — ${sys?.os ?? "?"}/${sys?.arch ?? "?"}, ${sys?.num_cpus ?? "?"} CPUs, up ${sys?.uptime ?? "?"}`
    : null;
  const livenessText = liveness ? (liveness.alive === true ? "Alive" : "Not alive") : null;
  const readinessText = readiness
    ? `${readiness.ready === true ? "Ready" : "Not ready"} (${readiness.status ?? "unknown"})`
    : null;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle>Platform probes</CardTitle>
        <Button
          variant="outline"
          size="sm"
          data-testid="probe-refresh"
          aria-label="Refresh probes"
          onClick={() => void refetch()}
          disabled={isLoading}
        >
          Refresh
        </Button>
      </CardHeader>
      <CardContent>
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
          {row("status", "Status", statusText)}
          {row("liveness", "Liveness", livenessText)}
          {row("readiness", "Readiness", readinessText)}
        </dl>
      </CardContent>
    </Card>
  );
}
