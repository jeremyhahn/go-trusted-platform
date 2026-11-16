"use client";

import { CheckCircle2, AlertCircle, XCircle } from "lucide-react";
import type { SystemStatus } from "@/types/platform";

interface HealthStatusProps {
  status: SystemStatus;
  className?: string;
}

const statusConfig = {
  healthy: {
    label: "Healthy",
    icon: CheckCircle2,
    className: "text-green-600 dark:text-green-400",
    bgClassName: "bg-green-100 dark:bg-green-900/20",
  },
  degraded: {
    label: "Degraded",
    icon: AlertCircle,
    className: "text-yellow-600 dark:text-yellow-400",
    bgClassName: "bg-yellow-100 dark:bg-yellow-900/20",
  },
  down: {
    label: "Down",
    icon: XCircle,
    className: "text-red-600 dark:text-red-400",
    bgClassName: "bg-red-100 dark:bg-red-900/20",
  },
};

const unknownStatusConfig = {
  label: "Unknown",
  icon: AlertCircle,
  className: "text-muted-foreground",
  bgClassName: "bg-muted",
};

/**
 * Overall system health status indicator
 *
 * @example
 * ```tsx
 * <HealthStatus status="healthy" />
 * ```
 */
export function HealthStatus({ status, className = "" }: HealthStatusProps) {
  // A status this build does not know (a newer server) renders as Unknown
  // instead of throwing on the missing entry.
  const config = statusConfig[status] ?? unknownStatusConfig;
  const Icon = config.icon;

  return (
    <div className={`inline-flex items-center gap-2 px-3 py-2 rounded-lg ${config.bgClassName} ${className}`}>
      <Icon className={`h-5 w-5 ${config.className}`} />
      <span className={`font-medium ${config.className}`}>{config.label}</span>
    </div>
  );
}
