"use client";

import * as React from "react";
import { RefreshCw, Users } from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  HealthStatus,
  ServiceHealthCard,
  ResourceUsage,
} from "@/components/features/platform";
import { usePlatform, useApi } from "@/hooks";
import { useToast } from "@/hooks/use-toast";
import type { SystemHealth, ServiceHealth } from "@/types/platform";

/**
 * System Health Page
 *
 * Features:
 * - Overall system health status
 * - Service health cards with metrics
 * - Resource usage monitoring (CPU, Memory, Disk)
 * - Active connections count
 * - Auto-refresh toggle
 * - Manual refresh button
 *
 * Uses SDK hooks:
 * - usePlatform(): Access to PlatformService
 * - useApi(): Declarative data fetching with auto-refresh support
 */
export default function HealthPage() {
  const { toast } = useToast();
  const platform = usePlatform();
  const [autoRefresh, setAutoRefresh] = React.useState(false);
  const [lastUpdate, setLastUpdate] = React.useState<Date>(new Date());

  // Use the SDK's useApi hook for data fetching
  // This replaces manual useState + useEffect + useCallback pattern
  const {
    data: healthResponse,
    isLoading,
    refetch,
  } = useApi(
    () => platform.getHealth({ includeServices: true }),
    [],
    {
      refetchInterval: autoRefresh ? 30000 : undefined,
      onSuccess: () => setLastUpdate(new Date()),
      onError: (err) => {
        toast({
          title: "Error fetching health data",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // The /platform/health response intentionally omits resource usage; the
  // numbers live on the metrics endpoint. Fetch both so the Resource Usage
  // card on this page reflects reality instead of showing "NaN% used".
  const { data: metricsResponse, refetch: refetchMetrics } = useApi(
    () => platform.getMetrics({ includeHistory: false }),
    [],
    { refetchInterval: autoRefresh ? 30000 : undefined },
  );
  const { data: systemResponse } = useApi(() => platform.getSystemInfo(), []);

  // Transform SDK PlatformHealth to local SystemHealth type
  const health: SystemHealth | null = React.useMemo(() => {
    if (!healthResponse?.health) return null;
    const h = healthResponse.health;

    // Map SDK ServiceHealth to local ServiceHealth.
    //
    // `healthy` is one bit and the registry reports four states, so the
    // component's own `status` word wins when it is present: a DEGRADED
    // component is running and telling us something is wrong, and showing it
    // as "Down" both overstates the fault and hides the message. The node's
    // `ntp` component is exactly this case — it reports `degraded` with
    // `time-unsynced` while the daemon keeps serving (#509).
    const mapServiceHealth = (s: { name: string; healthy: boolean; status?: string; message?: string; lastCheck?: string; latencyMs?: number }): ServiceHealth => ({
      name: s.name,
      status: s.status === "degraded" ? ("degraded" as const) : s.healthy ? ("up" as const) : ("down" as const),
      latencyMs: s.latencyMs ?? 0,
      uptime: 0, // SDK doesn't provide uptime
      lastCheck: s.lastCheck ?? new Date().toISOString(),
      // The message is the only place a degraded component names its
      // reason, so it is carried whenever the component is not healthy.
      error: s.message && !s.healthy ? s.message : undefined,
    });

    // The REST envelope reports system info as snake_case with MB units
    // and the metrics endpoint as percent only — there is no disk-bytes
    // field anywhere. We synthesize totals from the percent so progress
    // bars track real usage while values stay calibrated against a unit
    // that the user understands.
    // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
    const m = (metricsResponse as any)?.metrics ?? {};
    // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
    // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
    const sys = (metricsResponse as any)?.metrics?.system
              ?? (systemResponse as any)?.system
              ?? {};
    const cpuPct = Number(m.cpuUsagePercent ?? m.cpu_usage_percent ?? 0);
    const memPct = Number(m.memoryUsagePercent ?? m.memory_usage_percent ?? 0);
    const diskPct = Number(m.diskUsagePercent ?? m.disk_usage_percent ?? 0);
    const totalCores = Number(sys.num_cpus ?? sys.numCpus ?? sys.cpuCores ?? 0) || 1;
    const totalMemMB = Number(sys.total_memory_mb ?? sys.totalMemoryMb ?? 0);

    const safePct = (p: number) => (Number.isFinite(p) ? p : 0);

    return {
      status: h.healthy ? "healthy" as const : "down" as const,
      activeConnections: Number(m.activeConnections ?? m.active_connections ?? 0),
      timestamp: h.timestamp || new Date().toISOString(),
      resources: {
        cpu: {
          used: +((safePct(cpuPct) * totalCores) / 100).toFixed(2),
          total: totalCores,
        },
        memory: {
          usedMB: totalMemMB > 0
            ? Math.round((safePct(memPct) * totalMemMB) / 100)
            : Math.round(safePct(memPct)),
          totalMB: totalMemMB > 0 ? totalMemMB : 100, // 100 = scale factor for pct-only mode
        },
        disk: {
          // Backend currently reports diskUsagePercent only — no totalDisk.
          // Show as a percent over a 100GB virtual scale so the bar moves
          // meaningfully without inventing a fake total.
          usedGB: +safePct(diskPct).toFixed(2),
          totalGB: 100,
        },
      },
      services: h.services?.map(mapServiceHealth) ?? [],
    };
  }, [healthResponse, metricsResponse, systemResponse]);

  const handleManualRefresh = () => {
    refetch();
    refetchMetrics();
  };

  if (isLoading && !health) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="System Health"
          description="Monitor system status and service health"
        />
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="System Health"
        description="Monitor system status and service health"
      >
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Switch
              id="auto-refresh"
              checked={autoRefresh}
              onCheckedChange={setAutoRefresh}
            />
            <Label htmlFor="auto-refresh" className="cursor-pointer">
              Auto-refresh
            </Label>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={handleManualRefresh}
            disabled={isLoading}
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </PageHeader>

      {health && (
        <>
          {/* Overall Status */}
          <div className="flex items-center justify-between">
            <HealthStatus status={health.status} />
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Users className="h-4 w-4" />
              <span>{health.activeConnections} active connections</span>
            </div>
          </div>

          <p className="text-sm text-muted-foreground">
            Last updated: {lastUpdate.toLocaleTimeString()}
          </p>

          {/* Resource Usage */}
          <ResourceUsage resources={health.resources} />

          {/* Service Health Cards */}
          <div>
            <h2 className="text-lg font-semibold mb-4">Services</h2>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {health.services.map((service) => (
                <ServiceHealthCard key={service.name} service={service} />
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
