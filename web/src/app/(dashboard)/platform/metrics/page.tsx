"use client";

import * as React from "react";
import {
  RefreshCw,
  Cpu,
  MemoryStick,
  HardDrive,
  Network,
  Activity,
  Clock,
  TrendingUp,
  TrendingDown,
  Loader2,
  AlertCircle,
  CheckCircle,
  XCircle,
} from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useApi, usePlatform, useToast } from "@/hooks";

/**
 * Service metrics interface
 */
interface ServiceMetrics {
  name: string;
  displayName: string;
  latencyMs: number;
  healthy: boolean;
}

/**
 * Format bytes to human readable. Tolerant of undefined/NaN so the page
 * does not crash when the backend hasn't populated a metric yet.
 */
function formatBytes(bytes: number | undefined | null): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = typeof bytes === "number" && Number.isFinite(bytes) ? bytes : 0;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex++;
  }
  return `${value.toFixed(1)} ${units[unitIndex]}`;
}

/**
 * Format uptime to human readable
 */
function formatUptime(seconds: number | undefined | null): string {
  if (typeof seconds !== "number" || !Number.isFinite(seconds)) seconds = 0;
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${days}d ${hours}h ${minutes}m`;
}

/**
 * Metric card with progress bar
 */
interface MetricCardProps {
  title: string;
  icon: React.ReactNode;
  value: number;
  max: number;
  unit: string;
  description: string;
  trend?: "up" | "down" | "stable";
  trendValue?: string;
}

function MetricCard({
  title,
  icon,
  value,
  max,
  unit,
  description,
  trend,
  trendValue,
}: MetricCardProps) {
  const percentage = (value / max) * 100;
  const progressColor =
    percentage > 90
      ? "bg-destructive"
      : percentage > 70
        ? "bg-yellow-500"
        : "bg-primary";

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        {icon}
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-baseline justify-between">
          <div className="text-2xl font-bold">
            {typeof value === "number" && value % 1 !== 0 ? value.toFixed(1) : value}
            <span className="text-sm font-normal text-muted-foreground ml-1">
              {unit}
            </span>
          </div>
          {trend && trendValue && (
            <div
              className={`flex items-center text-xs ${
                trend === "up" ? "text-destructive" : trend === "down" ? "text-green-500" : "text-muted-foreground"
              }`}
            >
              {trend === "up" ? (
                <TrendingUp className="h-3 w-3 mr-1" />
              ) : trend === "down" ? (
                <TrendingDown className="h-3 w-3 mr-1" />
              ) : null}
              {trendValue}
            </div>
          )}
        </div>
        <Progress value={percentage} className={`h-2 ${progressColor}`} />
        <p className="text-xs text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  );
}

/**
 * Service metrics card
 */
function ServiceMetricsCard({ metrics }: { metrics: ServiceMetrics }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">{metrics.displayName}</CardTitle>
          {metrics.healthy ? (
            <CheckCircle className="h-4 w-4 text-green-500" />
          ) : (
            <XCircle className="h-4 w-4 text-destructive" />
          )}
        </div>
        <CardDescription className="text-xs">{metrics.name}</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-muted-foreground">Status</p>
            <p className={`font-medium ${metrics.healthy ? "text-green-600" : "text-destructive"}`}>
              {metrics.healthy ? "Healthy" : "Unhealthy"}
            </p>
          </div>
          <div>
            <p className="text-muted-foreground">Latency</p>
            <p className="font-medium">{(metrics.latencyMs ?? 0).toFixed(1)} ms</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * Platform Metrics Page
 *
 * Features:
 * - System resource metrics (CPU, Memory)
 * - Service-level health metrics
 * - Auto-refresh toggle
 * - Time range selection
 */
export default function MetricsPage() {
  const { toast } = useToast();
  const platform = usePlatform();
  const [autoRefresh, setAutoRefresh] = React.useState(false);
  const [timeRange, setTimeRange] = React.useState<string>("1h");
  const [lastUpdate, setLastUpdate] = React.useState<Date>(new Date());

  // Fetch platform metrics
  const {
    data: metricsData,
    isLoading: metricsLoading,
    error: metricsError,
    refetch: refetchMetrics,
  } = useApi(
    () => platform.getMetrics({ includeHistory: false }),
    [],
    {
      onError: (err) => {
        toast({
          title: "Error loading metrics",
          description: err.message,
          variant: "destructive",
        });
      },
      onSuccess: () => {
        setLastUpdate(new Date());
      },
    }
  );

  // Fetch system info
  const {
    data: systemData,
  } = useApi(
    () => platform.getSystemInfo(),
    []
  );

  // Fetch health for service metrics
  const {
    data: healthData,
  } = useApi(
    () => platform.getHealth({ includeServices: true }),
    []
  );

  const isLoading = metricsLoading;
  const error = metricsError;

  // Transform service health into metrics
  const serviceMetrics: ServiceMetrics[] = React.useMemo(() => {
    if (!healthData?.health?.services) return [];

    return healthData.health.services.map((service) => ({
      name: service.name,
      displayName: service.name.replace(/-/g, " ").replace(/\b\w/g, (l) => l.toUpperCase()),
      latencyMs: service.latencyMs || 0,
      healthy: service.healthy,
    }));
  }, [healthData]);

  // Auto-refresh
  React.useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      refetchMetrics();
    }, 10000); // Refresh every 10 seconds

    return () => clearInterval(interval);
  }, [autoRefresh, refetchMetrics]);

  const handleRefresh = () => {
    refetchMetrics();
  };

  // Show error state
  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Platform Metrics"
          description="Monitor system and service performance metrics"
        />
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Metrics</AlertTitle>
          <AlertDescription>
            {error.message}
            <Button
              variant="outline"
              size="sm"
              className="ml-4"
              onClick={handleRefresh}
            >
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  if (isLoading && !metricsData) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Platform Metrics"
          description="Monitor system and service performance metrics"
        />
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          <span className="ml-2">Loading metrics...</span>
        </div>
      </div>
    );
  }

  const metrics = metricsData?.metrics;
  const systemInfo = systemData?.system;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Platform Metrics"
        description="Monitor system and service performance metrics"
      >
        <div className="flex items-center gap-4">
          <Select value={timeRange} onValueChange={setTimeRange}>
            <SelectTrigger className="w-[130px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="15m">Last 15 min</SelectItem>
              <SelectItem value="1h">Last hour</SelectItem>
              <SelectItem value="6h">Last 6 hours</SelectItem>
              <SelectItem value="24h">Last 24 hours</SelectItem>
              <SelectItem value="7d">Last 7 days</SelectItem>
            </SelectContent>
          </Select>
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
            onClick={handleRefresh}
            disabled={isLoading}
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </PageHeader>

      {metrics && (
        <>
          {/* System Overview Cards */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Uptime</CardTitle>
                <Clock className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {systemInfo?.uptime ? formatUptime(systemInfo.uptime) : "N/A"}
                </div>
                <p className="text-xs text-muted-foreground">
                  Since last restart
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Hostname</CardTitle>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold truncate">
                  {systemInfo?.hostname || "N/A"}
                </div>
                <p className="text-xs text-muted-foreground">
                  {systemInfo?.os || "Unknown"} {systemInfo?.arch || ""}
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">CPU Cores</CardTitle>
                <Cpu className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{systemInfo?.cpuCount || 0}</div>
                <p className="text-xs text-muted-foreground">
                  Available cores
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Connections</CardTitle>
                <Network className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{metrics.activeConnections || 0}</div>
                <p className="text-xs text-muted-foreground">
                  Active network connections
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Resource Metrics */}
          <div>
            <h2 className="text-lg font-semibold mb-4">Resource Usage</h2>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              <MetricCard
                title="CPU Usage"
                icon={<Cpu className="h-4 w-4 text-muted-foreground" />}
                value={metrics.cpuUsagePercent}
                max={100}
                unit="%"
                description={`${systemInfo?.cpuCount || 0} cores available`}
              />
              <MetricCard
                title="Memory Usage"
                icon={<MemoryStick className="h-4 w-4 text-muted-foreground" />}
                value={metrics.memoryUsagePercent}
                max={100}
                unit="%"
                description={systemInfo ? `${formatBytes(systemInfo.totalMemory)} total` : "Memory info"}
              />
              <MetricCard
                title="Disk Usage"
                icon={<HardDrive className="h-4 w-4 text-muted-foreground" />}
                value={metrics.diskUsagePercent || 0}
                max={100}
                unit="%"
                description="Storage utilization"
              />
              <MetricCard
                title="Request Rate"
                icon={<Activity className="h-4 w-4 text-muted-foreground" />}
                value={metrics.requestsPerSecond || 0}
                max={1000}
                unit="req/s"
                description={`Error rate: ${((metrics.errorRate || 0) * 100).toFixed(2)}%`}
              />
            </div>
          </div>

          {/* Service Metrics */}
          {serviceMetrics.length > 0 && (
            <div>
              <h2 className="text-lg font-semibold mb-4">Service Health</h2>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {serviceMetrics.map((service) => (
                  <ServiceMetricsCard key={service.name} metrics={service} />
                ))}
              </div>
            </div>
          )}

          {/* Last Update */}
          <p className="text-sm text-muted-foreground">
            Last updated: {lastUpdate.toLocaleTimeString()}
            {autoRefresh && " (auto-refreshing every 10s)"}
          </p>
        </>
      )}
    </div>
  );
}
