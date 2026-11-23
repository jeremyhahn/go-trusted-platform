'use client';

import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { Activity, Clock, Cpu, HardDrive, MemoryStick, Network, RefreshCw } from 'lucide-react';
import type { VMMetrics } from 'trusted-platform-sdk';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Gated } from '@/components/features/capabilities/gated';
import { useCompute } from '@/hooks';

const METRICS_OP = 'GET /api/v1/compute/vms/{id}/metrics';

interface VMMetricsCardProps {
  vmId: string;
}

function errorText(err: unknown): string {
  if (typeof err === 'string') {
    return err;
  }
  if (err && typeof err === 'object' && 'message' in err && typeof err.message === 'string') {
    return err.message;
  }
  return 'the control plane refused the metrics request';
}

function formatBytes(bytes: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return unit === 0 ? `${value} B` : `${value.toFixed(1)} ${units[unit]}`;
}

function formatUptime(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  return h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${s}s` : `${s}s`;
}

function Row({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-center justify-between text-sm">
      <div className="flex items-center gap-2">
        {icon}
        <span>{label}</span>
      </div>
      <span className="font-medium">{value}</span>
    </div>
  );
}

/**
 * VMMetricsCard reads a VM's metrics through the SDK ComputeService
 * (GetVMMetrics) on mount and on a Refresh control behind the server's
 * capability gate (#2044).
 */
export function VMMetricsCard({ vmId }: VMMetricsCardProps) {
  const compute = useCompute();
  const [metrics, setMetrics] = useState<VMMetrics | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await compute.getVMMetrics(vmId);
      if (res.success === false || !res.data?.metrics) {
        setError(errorText(res.error ?? 'the control plane returned no metrics'));
        return;
      }
      setMetrics(res.data.metrics);
      setError(null);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setLoading(false);
    }
  }, [compute, vmId]);

  useEffect(() => {
    void load();
    // Load once per VM; Refresh reloads on demand.
  }, [vmId]);

  const memoryUsed = metrics?.memoryUsedMb ?? 0;
  const memoryAvailable = metrics?.memoryAvailableMb ?? 0;
  const memoryTotal = memoryUsed + memoryAvailable;
  const memoryPercent = memoryTotal > 0 ? (memoryUsed / memoryTotal) * 100 : 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2">
          <Activity className="h-5 w-5" />
          Performance Metrics
        </CardTitle>
        <Gated op={METRICS_OP}>
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh metrics
          </Button>
        </Gated>
      </CardHeader>
      <CardContent className="space-y-6" data-testid="vm-metrics">
        {error && (
          <p className="text-sm text-destructive" data-testid="vm-metrics-error">
            Could not load metrics: {error}
          </p>
        )}
        {metrics && (
          <>
            <div className="space-y-2">
              <Row
                icon={<Cpu className="h-4 w-4 text-muted-foreground" />}
                label="CPU Usage"
                value={`${(metrics.cpuUsagePercent ?? 0).toFixed(1)}%`}
              />
              <Progress value={metrics.cpuUsagePercent ?? 0} />
            </div>

            <div className="space-y-2">
              <Row
                icon={<MemoryStick className="h-4 w-4 text-muted-foreground" />}
                label="Memory Used / Available"
                value={`${memoryUsed} MB / ${memoryAvailable} MB`}
              />
              <Progress value={memoryPercent} />
            </div>

            <div className="space-y-2">
              <Row
                icon={<HardDrive className="h-4 w-4 text-muted-foreground" />}
                label="Disk Read"
                value={formatBytes(metrics.diskReadBytes ?? 0)}
              />
              <Row
                icon={<HardDrive className="h-4 w-4 text-muted-foreground" />}
                label="Disk Write"
                value={formatBytes(metrics.diskWriteBytes ?? 0)}
              />
            </div>

            <div className="space-y-2">
              <Row
                icon={<Network className="h-4 w-4 text-muted-foreground" />}
                label="Network Received"
                value={formatBytes(metrics.networkRxBytes ?? 0)}
              />
              <Row
                icon={<Network className="h-4 w-4 text-muted-foreground" />}
                label="Network Sent"
                value={formatBytes(metrics.networkTxBytes ?? 0)}
              />
            </div>

            <Row
              icon={<Clock className="h-4 w-4 text-muted-foreground" />}
              label="Uptime"
              value={formatUptime(metrics.uptimeSeconds ?? 0)}
            />
          </>
        )}
      </CardContent>
    </Card>
  );
}
