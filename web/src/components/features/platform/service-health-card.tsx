"use client";

import { Clock, Zap, AlertTriangle } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { ServiceHealth } from "@/types/platform";

interface ServiceHealthCardProps {
  service: ServiceHealth;
}

const statusConfig = {
  up: {
    label: "Up",
    variant: "default" as const,
    className: "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400",
  },
  degraded: {
    label: "Degraded",
    variant: "secondary" as const,
    className: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400",
  },
  down: {
    label: "Down",
    variant: "destructive" as const,
    className: "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400",
  },
};

const unknownStatusConfig = {
  label: "Unknown",
  variant: "secondary" as const,
  className: "bg-muted text-muted-foreground",
};

function formatUptime(seconds: number): string {
  // A negative or non-finite uptime (clock skew, a missing field) shows as 0m.
  if (!Number.isFinite(seconds) || seconds < 0) {
    return "0m";
  }
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  if (days > 0) {
    return `${days}d ${hours}h`;
  }
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  return `${minutes}m`;
}

/**
 * Service health card component
 * Displays health status for an individual service
 *
 * @example
 * ```tsx
 * <ServiceHealthCard
 *   service={{
 *     name: "API Server",
 *     status: "up",
 *     uptime: 86400,
 *     latencyMs: 45,
 *     lastCheck: "2025-01-19T10:00:00Z"
 *   }}
 * />
 * ```
 */
export function ServiceHealthCard({ service }: ServiceHealthCardProps) {
  const config = statusConfig[service.status] ?? unknownStatusConfig;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">{service.name}</CardTitle>
          <Badge className={config.className}>
            {config.label}
          </Badge>
        </div>
        <CardDescription>
          Last checked: {new Date(service.lastCheck).toLocaleTimeString()}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-4">
          <div className="flex items-center gap-2">
            <Clock className="h-4 w-4 text-muted-foreground" />
            <div className="flex flex-col">
              <span className="text-xs text-muted-foreground">Uptime</span>
              <span className="text-sm font-medium">{formatUptime(service.uptime)}</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Zap className="h-4 w-4 text-muted-foreground" />
            <div className="flex flex-col">
              <span className="text-xs text-muted-foreground">Latency</span>
              <span className="text-sm font-medium">{service.latencyMs}ms</span>
            </div>
          </div>
        </div>
        {service.error && (
          <div className="mt-4 flex items-start gap-2 rounded-md bg-destructive/10 p-3">
            <AlertTriangle className="h-4 w-4 text-destructive mt-0.5 flex-shrink-0" />
            <p className="text-sm text-destructive">{service.error}</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
