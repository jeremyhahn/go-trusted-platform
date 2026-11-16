"use client";

import { Cpu, MemoryStick, HardDrive } from "lucide-react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import type { ResourceUsage as ResourceUsageType } from "@/types/platform";

interface ResourceUsageProps {
  resources: ResourceUsageType;
}

interface ResourceItemProps {
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  used: number;
  total: number;
  unit: string;
}

function ResourceItem({ label, icon: Icon, used, total, unit }: ResourceItemProps) {
  // A zero or missing total would give NaN or Infinity, and used above total
  // (or below zero) would size the bar outside its track: clamp to 0..100.
  const raw = total > 0 ? (used / total) * 100 : 0;
  const percentage = Number.isFinite(raw) ? Math.min(100, Math.max(0, raw)) : 0;
  const isHigh = percentage > 80;
  const isMedium = percentage > 60;

  const progressColor = isHigh
    ? "bg-red-600 dark:bg-red-500"
    : isMedium
    ? "bg-yellow-600 dark:bg-yellow-500"
    : "bg-green-600 dark:bg-green-500";

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">{label}</span>
        </div>
        <span className="text-sm text-muted-foreground">
          {used.toFixed(1)} / {total.toFixed(1)} {unit}
        </span>
      </div>
      <div className="relative">
        <Progress value={percentage} className="h-2" />
        <div
          className={`absolute top-0 left-0 h-2 rounded-full transition-all ${progressColor}`}
          style={{ width: `${percentage}%` }}
        />
      </div>
      <div className="text-xs text-muted-foreground text-right">
        {percentage.toFixed(1)}% used
      </div>
    </div>
  );
}

/**
 * Resource usage display component
 * Shows CPU, memory, and disk usage with progress bars
 *
 * @example
 * ```tsx
 * <ResourceUsage
 *   resources={{
 *     cpu: { used: 2.4, total: 8 },
 *     memory: { usedMB: 4096, totalMB: 16384 },
 *     disk: { usedGB: 120, totalGB: 500 }
 *   }}
 * />
 * ```
 */
export function ResourceUsage({ resources }: ResourceUsageProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Resource Usage</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <ResourceItem
          label="CPU"
          icon={Cpu}
          used={resources.cpu.used}
          total={resources.cpu.total}
          unit="cores"
        />
        <ResourceItem
          label="Memory"
          icon={MemoryStick}
          used={resources.memory.usedMB}
          total={resources.memory.totalMB}
          unit="MB"
        />
        <ResourceItem
          label="Disk"
          icon={HardDrive}
          used={resources.disk.usedGB}
          total={resources.disk.totalGB}
          unit="GB"
        />
      </CardContent>
    </Card>
  );
}
