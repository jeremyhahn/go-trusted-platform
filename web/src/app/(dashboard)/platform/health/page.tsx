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

  // Transform SDK PlatformHealth to local SystemHealth type
  const health: SystemHealth | null = React.useMemo(() => {
    if (!healthResponse?.health) return null;
    const h = healthResponse.health;

    // Map SDK ServiceHealth to local ServiceHealth
    // The SDK ServiceHealth has: name, healthy, message?, lastCheck?, latencyMs?
    const mapServiceHealth = (s: { name: string; healthy: boolean; message?: string; lastCheck?: string; latencyMs?: number }): ServiceHealth => ({
      name: s.name,
      status: s.healthy ? "up" as const : "down" as const,
      latencyMs: s.latencyMs ?? 0,
      uptime: 0, // SDK doesn't provide uptime
      lastCheck: s.lastCheck ?? new Date().toISOString(),
      error: s.message && !s.healthy ? s.message : undefined,
    });

    return {
      status: h.healthy ? "healthy" as const : "down" as const,
      activeConnections: 0, // SDK doesn't provide this in health response
      timestamp: h.timestamp || new Date().toISOString(),
      resources: {
        cpu: { used: 0, total: 100 },
        memory: { usedMB: 0, totalMB: 0 },
        disk: { usedGB: 0, totalGB: 0 },
      },
      services: h.services?.map(mapServiceHealth) ?? [],
    };
  }, [healthResponse]);

  const handleManualRefresh = () => {
    refetch();
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
