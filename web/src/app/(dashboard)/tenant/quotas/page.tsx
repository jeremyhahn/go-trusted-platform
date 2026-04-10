"use client";

import * as React from "react";
import {
  Gauge,
  Cpu,
  HardDrive,
  Network,
  Database,
  Box,
  AlertCircle,
  RefreshCw,
  Server,
  Container,
  MemoryStick,
} from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { useAuth } from "@/contexts/AuthContext";
import { useTenant, useApi } from "@/hooks";
import type {
  TenantQuotasResponse,
  TenantUsageResponse,
} from "@/types/tenant";

// Resource usage item for display
interface ResourceUsageItem {
  label: string;
  used: number;
  limit: number;
  unit: string;
  icon: React.ReactNode;
}

// Calculate usage percentage
function calculatePercentage(used: number, limit: number): number {
  if (limit === 0) return 0;
  return Math.min(Math.round((used / limit) * 100), 100);
}

// Get status color based on usage percentage
function getStatusColor(percentage: number): string {
  if (percentage >= 90) return "text-destructive";
  if (percentage >= 75) return "text-yellow-500";
  return "text-green-500";
}

// Get progress bar class based on usage percentage
function getProgressClass(percentage: number): string {
  if (percentage >= 90) return "[&>div]:bg-destructive";
  if (percentage >= 75) return "[&>div]:bg-yellow-500";
  return "[&>div]:bg-green-500";
}

// Get status badge variant based on usage percentage
function getStatusBadge(
  percentage: number
): "default" | "secondary" | "destructive" | "outline" {
  if (percentage >= 90) return "destructive";
  if (percentage >= 75) return "secondary";
  return "default";
}

export default function TenantQuotasPage() {
  const { tenantId, isLoading: authLoading } = useAuth();
  const tenant = useTenant();

  // Fetch quotas from SDK
  const {
    data: quotasResponse,
    isLoading: quotasLoading,
    error: quotasError,
    refetch: refetchQuotas,
  } = useApi(
    () => tenant.getQuotas(tenantId || ""),
    [tenantId],
    { enabled: !!tenantId && !authLoading }
  );

  // Fetch usage from SDK
  const {
    data: usageResponse,
    isLoading: usageLoading,
    error: usageError,
    refetch: refetchUsage,
  } = useApi(
    () => tenant.getUsage(tenantId || ""),
    [tenantId],
    { enabled: !!tenantId && !authLoading }
  );

  const isLoading = quotasLoading || usageLoading;
  const error = quotasError?.message || usageError?.message || null;

  // Transform SDK response to expected UI format
  const quotas: TenantQuotasResponse | null = React.useMemo(() => {
    if (!quotasResponse) return null;
    return {
      tenant_id: tenantId || "",
      compute: {
        max_vms: quotasResponse.compute?.maxVms ?? 0,
        max_containers: quotasResponse.compute?.maxContainers ?? 0,
        max_vcpus: quotasResponse.compute?.maxVcpus ?? 0,
        max_memory_mb: quotasResponse.compute?.maxMemoryMb ?? 0,
        max_disk_gb: 0, // SDK ComputeQuota does not have maxDiskGb yet
      },
      network: {
        max_bridges: quotasResponse.network?.maxBridges ?? 0,
        max_ports: quotasResponse.network?.maxPorts ?? 0,
        max_bandwidth_mbps: quotasResponse.network?.maxBandwidthMbps ?? 0,
      },
      storage: {
        max_volumes_gb: quotasResponse.storage?.maxVolumesGb ?? 0,
        max_snapshots: quotasResponse.storage?.maxSnapshots ?? 0,
      },
      timestamp: new Date().toISOString(),
    };
  }, [quotasResponse, tenantId]);

  const usage: TenantUsageResponse | null = React.useMemo(() => {
    if (!usageResponse?.usage) return null;
    const u = usageResponse.usage;
    return {
      tenant_id: u.tenantId,
      vms: u.vms ?? 0,
      containers: u.containers ?? 0,
      vcpus: u.vcpus ?? 0,
      memory_mb: u.memoryMb ?? 0,
      disk_gb: u.diskGb ?? 0,
      bridges: u.bridges ?? 0,
      ports: u.ports ?? 0,
      bandwidth_mbps: u.bandwidthMbps ?? 0,
      volumes: u.volumes ?? 0, // Fixed: property is 'volumes' not 'volumesGb'
      snapshots: u.snapshots ?? 0,
      timestamp: u.timestamp,
    };
  }, [usageResponse]);

  const fetchData = React.useCallback(async () => {
    await Promise.all([refetchQuotas(), refetchUsage()]);
  }, [refetchQuotas, refetchUsage]);

  // Build compute resources list
  const computeResources: ResourceUsageItem[] = React.useMemo(() => {
    if (!quotas || !usage) return [];
    return [
      {
        label: "Virtual Machines",
        used: usage.vms,
        limit: quotas.compute.max_vms,
        unit: "VMs",
        icon: <Server className="h-4 w-4" />,
      },
      {
        label: "Containers",
        used: usage.containers,
        limit: quotas.compute.max_containers,
        unit: "containers",
        icon: <Container className="h-4 w-4" />,
      },
      {
        label: "vCPUs",
        used: usage.vcpus,
        limit: quotas.compute.max_vcpus,
        unit: "cores",
        icon: <Cpu className="h-4 w-4" />,
      },
      {
        label: "Memory",
        used: Math.round(usage.memory_mb / 1024),
        limit: Math.round(quotas.compute.max_memory_mb / 1024),
        unit: "GB",
        icon: <MemoryStick className="h-4 w-4" />,
      },
      {
        label: "Disk",
        used: usage.disk_gb,
        limit: quotas.compute.max_disk_gb,
        unit: "GB",
        icon: <HardDrive className="h-4 w-4" />,
      },
    ];
  }, [quotas, usage]);

  // Build network resources list
  const networkResources: ResourceUsageItem[] = React.useMemo(() => {
    if (!quotas || !usage) return [];
    return [
      {
        label: "Bridges",
        used: usage.bridges,
        limit: quotas.network.max_bridges,
        unit: "bridges",
        icon: <Network className="h-4 w-4" />,
      },
      {
        label: "Ports",
        used: usage.ports,
        limit: quotas.network.max_ports,
        unit: "ports",
        icon: <Box className="h-4 w-4" />,
      },
      {
        label: "Bandwidth",
        used: usage.bandwidth_mbps,
        limit: quotas.network.max_bandwidth_mbps,
        unit: "Mbps",
        icon: <Gauge className="h-4 w-4" />,
      },
    ];
  }, [quotas, usage]);

  // Build storage resources list
  const storageResources: ResourceUsageItem[] = React.useMemo(() => {
    if (!quotas || !usage) return [];
    return [
      {
        label: "Volumes",
        used: usage.volumes,
        limit: quotas.storage.max_volumes_gb,
        unit: "GB",
        icon: <Database className="h-4 w-4" />,
      },
      {
        label: "Snapshots",
        used: usage.snapshots,
        limit: quotas.storage.max_snapshots,
        unit: "snapshots",
        icon: <HardDrive className="h-4 w-4" />,
      },
    ];
  }, [quotas, usage]);

  // Calculate overall usage percentages for summary cards
  const overallStats = React.useMemo(() => {
    if (!quotas || !usage) {
      return {
        compute: 0,
        network: 0,
        storage: 0,
      };
    }

    const computeUsage = Math.round(
      ((usage.vcpus / quotas.compute.max_vcpus) * 100 +
        (usage.memory_mb / quotas.compute.max_memory_mb) * 100 +
        (usage.disk_gb / quotas.compute.max_disk_gb) * 100) /
        3
    );

    const networkUsage = Math.round(
      ((usage.bridges / quotas.network.max_bridges) * 100 +
        (usage.ports / quotas.network.max_ports) * 100) /
        2
    );

    const storageUsage = Math.round(
      ((usage.volumes / quotas.storage.max_volumes_gb) * 100 +
        (usage.snapshots / quotas.storage.max_snapshots) * 100) /
        2
    );

    return {
      compute: computeUsage,
      network: networkUsage,
      storage: storageUsage,
    };
  }, [quotas, usage]);

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Resource Quotas"
          description="View resource limits and current usage"
        />
        <Card>
          <CardContent className="pt-6">
            <div className="flex flex-col items-center justify-center text-center space-y-4">
              <AlertCircle className="h-12 w-12 text-destructive" />
              <div>
                <p className="font-medium text-destructive">
                  Error loading quotas
                </p>
                <p className="text-sm text-muted-foreground mt-1">{error}</p>
              </div>
              <Button onClick={fetchData} variant="outline">
                <RefreshCw className="h-4 w-4 mr-2" />
                Retry
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Resource Quotas"
        description="View resource limits and current usage for your tenant"
        actions={
          <Button onClick={fetchData} variant="outline" disabled={isLoading}>
            <RefreshCw
              className={`h-4 w-4 mr-2 ${isLoading ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
        }
      />

      {isLoading || authLoading || !quotas || !usage ? (
        <div className="space-y-6">
          {/* Summary Cards Skeleton */}
          <div className="grid gap-4 md:grid-cols-3">
            <Skeleton className="h-32" />
            <Skeleton className="h-32" />
            <Skeleton className="h-32" />
          </div>
          {/* Detail Cards Skeleton */}
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            <Skeleton className="h-64" />
            <Skeleton className="h-64" />
            <Skeleton className="h-64" />
          </div>
        </div>
      ) : (
        <>
          {/* Summary Cards */}
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">
                  Compute Usage
                </CardTitle>
                <Cpu className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {overallStats.compute}%
                </div>
                <Progress
                  value={overallStats.compute}
                  className={`mt-2 ${getProgressClass(overallStats.compute)}`}
                />
                <p className="text-xs text-muted-foreground mt-2">
                  <Badge
                    variant={getStatusBadge(overallStats.compute)}
                    className="mr-1"
                  >
                    {overallStats.compute >= 90
                      ? "Critical"
                      : overallStats.compute >= 75
                        ? "Warning"
                        : "Healthy"}
                  </Badge>
                  of allocated compute resources
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">
                  Network Usage
                </CardTitle>
                <Network className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {overallStats.network}%
                </div>
                <Progress
                  value={overallStats.network}
                  className={`mt-2 ${getProgressClass(overallStats.network)}`}
                />
                <p className="text-xs text-muted-foreground mt-2">
                  <Badge
                    variant={getStatusBadge(overallStats.network)}
                    className="mr-1"
                  >
                    {overallStats.network >= 90
                      ? "Critical"
                      : overallStats.network >= 75
                        ? "Warning"
                        : "Healthy"}
                  </Badge>
                  of allocated network resources
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">
                  Storage Usage
                </CardTitle>
                <Database className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {overallStats.storage}%
                </div>
                <Progress
                  value={overallStats.storage}
                  className={`mt-2 ${getProgressClass(overallStats.storage)}`}
                />
                <p className="text-xs text-muted-foreground mt-2">
                  <Badge
                    variant={getStatusBadge(overallStats.storage)}
                    className="mr-1"
                  >
                    {overallStats.storage >= 90
                      ? "Critical"
                      : overallStats.storage >= 75
                        ? "Warning"
                        : "Healthy"}
                  </Badge>
                  of allocated storage resources
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Detailed Resource Cards */}
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {/* Compute Resources */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Cpu className="h-5 w-5" />
                  Compute Resources
                </CardTitle>
                <CardDescription>
                  Virtual machines, containers, and compute capacity
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {computeResources.map((resource) => {
                  const percentage = calculatePercentage(
                    resource.used,
                    resource.limit
                  );
                  return (
                    <div key={resource.label} className="space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          {resource.icon}
                          <span className="text-sm font-medium">
                            {resource.label}
                          </span>
                        </div>
                        <span
                          className={`text-sm font-medium ${getStatusColor(percentage)}`}
                        >
                          {resource.used} / {resource.limit} {resource.unit}
                        </span>
                      </div>
                      <Progress
                        value={percentage}
                        className={`h-2 ${getProgressClass(percentage)}`}
                      />
                    </div>
                  );
                })}
              </CardContent>
            </Card>

            {/* Network Resources */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Network className="h-5 w-5" />
                  Network Resources
                </CardTitle>
                <CardDescription>
                  Bridges, ports, and bandwidth allocation
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {networkResources.map((resource) => {
                  const percentage = calculatePercentage(
                    resource.used,
                    resource.limit
                  );
                  return (
                    <div key={resource.label} className="space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          {resource.icon}
                          <span className="text-sm font-medium">
                            {resource.label}
                          </span>
                        </div>
                        <span
                          className={`text-sm font-medium ${getStatusColor(percentage)}`}
                        >
                          {resource.used} / {resource.limit} {resource.unit}
                        </span>
                      </div>
                      <Progress
                        value={percentage}
                        className={`h-2 ${getProgressClass(percentage)}`}
                      />
                    </div>
                  );
                })}
              </CardContent>
            </Card>

            {/* Storage Resources */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Database className="h-5 w-5" />
                  Storage Resources
                </CardTitle>
                <CardDescription>
                  Volumes and snapshot allocation
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {storageResources.map((resource) => {
                  const percentage = calculatePercentage(
                    resource.used,
                    resource.limit
                  );
                  return (
                    <div key={resource.label} className="space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          {resource.icon}
                          <span className="text-sm font-medium">
                            {resource.label}
                          </span>
                        </div>
                        <span
                          className={`text-sm font-medium ${getStatusColor(percentage)}`}
                        >
                          {resource.used} / {resource.limit} {resource.unit}
                        </span>
                      </div>
                      <Progress
                        value={percentage}
                        className={`h-2 ${getProgressClass(percentage)}`}
                      />
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          </div>

          {/* Quota Limits Reference */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Gauge className="h-5 w-5" />
                Quota Limits Reference
              </CardTitle>
              <CardDescription>
                Current quota allocations for your tenant
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-6 md:grid-cols-3">
                <div className="space-y-3">
                  <h4 className="font-medium text-sm">Compute Limits</h4>
                  <Separator />
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Max VMs</span>
                      <span className="font-medium">
                        {quotas.compute.max_vms}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">
                        Max Containers
                      </span>
                      <span className="font-medium">
                        {quotas.compute.max_containers}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Max vCPUs</span>
                      <span className="font-medium">
                        {quotas.compute.max_vcpus}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Max Memory</span>
                      <span className="font-medium">
                        {Math.round(quotas.compute.max_memory_mb / 1024)} GB
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Max Disk</span>
                      <span className="font-medium">
                        {quotas.compute.max_disk_gb} GB
                      </span>
                    </div>
                  </div>
                </div>

                <div className="space-y-3">
                  <h4 className="font-medium text-sm">Network Limits</h4>
                  <Separator />
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Max Bridges</span>
                      <span className="font-medium">
                        {quotas.network.max_bridges}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Max Ports</span>
                      <span className="font-medium">
                        {quotas.network.max_ports}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">
                        Max Bandwidth
                      </span>
                      <span className="font-medium">
                        {quotas.network.max_bandwidth_mbps} Mbps
                      </span>
                    </div>
                  </div>
                </div>

                <div className="space-y-3">
                  <h4 className="font-medium text-sm">Storage Limits</h4>
                  <Separator />
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Max Volumes</span>
                      <span className="font-medium">
                        {quotas.storage.max_volumes_gb} GB
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">
                        Max Snapshots
                      </span>
                      <span className="font-medium">
                        {quotas.storage.max_snapshots}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              <Separator className="my-6" />

              <div className="flex items-center justify-between">
                <div className="text-sm text-muted-foreground">
                  Last updated:{" "}
                  {new Date(quotas.timestamp).toLocaleString("en-US", {
                    dateStyle: "medium",
                    timeStyle: "short",
                  })}
                </div>
                <Button variant="outline" asChild>
                  <a href="/tenant">Back to Tenant Overview</a>
                </Button>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
