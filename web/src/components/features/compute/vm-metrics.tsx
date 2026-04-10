'use client';

import { Activity, Cpu, HardDrive, MemoryStick, Network } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import type { VMMetrics } from '@/types/infrastructure';

interface VMMetricsCardProps {
  metrics: VMMetrics;
}

export function VMMetricsCard({ metrics }: VMMetricsCardProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className="h-5 w-5" />
          Performance Metrics
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2">
              <Cpu className="h-4 w-4 text-muted-foreground" />
              <span>CPU Usage</span>
            </div>
            <span className="font-medium">{metrics.cpuUsagePercent.toFixed(1)}%</span>
          </div>
          <Progress value={metrics.cpuUsagePercent} />
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2">
              <MemoryStick className="h-4 w-4 text-muted-foreground" />
              <span>Memory Usage</span>
            </div>
            <span className="font-medium">{metrics.memoryUsagePercent.toFixed(1)}%</span>
          </div>
          <Progress value={metrics.memoryUsagePercent} />
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2">
              <HardDrive className="h-4 w-4 text-muted-foreground" />
              <span>Disk Usage</span>
            </div>
            <span className="font-medium">{metrics.diskUsagePercent.toFixed(1)}%</span>
          </div>
          <Progress value={metrics.diskUsagePercent} />
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2">
              <Network className="h-4 w-4 text-muted-foreground" />
              <span>Network In</span>
            </div>
            <span className="font-medium">{metrics.networkInMbps.toFixed(2)} Mbps</span>
          </div>
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2">
              <Network className="h-4 w-4 text-muted-foreground" />
              <span>Network Out</span>
            </div>
            <span className="font-medium">{metrics.networkOutMbps.toFixed(2)} Mbps</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
