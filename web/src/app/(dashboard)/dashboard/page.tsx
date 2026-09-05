"use client";

/**
 * Dashboard Page
 *
 * Main dashboard displaying real-time stats from the platform.
 * Fetches data from IAM, Device, CA, Attestation, and Platform services.
 */

import * as React from "react";
import { useMemo, useSyncExternalStore } from "react";
import Link from "next/link";
import {
  Users,
  Cpu,
  FileKey,
  Shield,
  Server,
  Network,
  ArrowUpRight,
  Activity,
  TrendingUp,
  Clock,
  AlertCircle,
  Loader2,
  RefreshCw,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  useApi,
  useIAM,
  useDevice,
  useCA,
  usePlatform,
  useTenant,
} from "@/hooks";
import { useAuth } from "@/contexts/AuthContext";

interface DashboardStats {
  title: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
  href: string;
  loading?: boolean;
}

interface QuickAction {
  title: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  href: string;
}

const quickActions: QuickAction[] = [
  {
    title: "Issue Certificate",
    description: "Generate a new certificate",
    icon: FileKey,
    href: "/ca/certificates",
  },
  {
    title: "Manage Devices",
    description: "View and manage devices",
    icon: Cpu,
    href: "/devices",
  },
  {
    title: "Manage Users",
    description: "Create and manage user accounts",
    icon: Users,
    href: "/iam/users",
  },
  {
    title: "View Events",
    description: "Check platform activity",
    icon: Activity,
    href: "/platform/events",
  },
];

function subscribeEveryMinute(onTick: () => void): () => void {
  const id = setInterval(onTick, 60_000);
  return () => clearInterval(id);
}

function readLocalTime(): string {
  return new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
}

function readServerTime(): string {
  return "";
}

export default function DashboardPage() {
  const { tenantId } = useAuth();
  const iam = useIAM();
  const device = useDevice();
  const ca = useCA();
  const platform = usePlatform();
  const tenant = useTenant();

  // Fetch users count
  const {
    data: usersData,
    isLoading: usersLoading,
    error: usersError,
    refetch: refetchUsers,
  } = useApi(
    () => tenantId ? iam.listUsers({ tenantId, pageSize: 1 }) : Promise.resolve({ success: true, data: null }),
    [tenantId]
  );

  // Fetch devices count
  const {
    data: devicesData,
    isLoading: devicesLoading,
    error: devicesError,
    refetch: refetchDevices,
  } = useApi(
    () => device.listDevices({ pageSize: 1 }),
    []
  );

  // Fetch certificates count
  const {
    data: certsData,
    isLoading: certsLoading,
    error: certsError,
    refetch: refetchCerts,
  } = useApi(
    () => ca.listCertificates({ limit: 1 }),
    []
  );

  // Fetch platform health
  const {
    data: healthData,
    isLoading: healthLoading,
    error: healthError,
    refetch: refetchHealth,
  } = useApi(
    () => platform.getHealth(),
    []
  );

  // Fetch platform metrics
  const {
    data: metricsData,
    isLoading: metricsLoading,
    error: metricsError,
    refetch: refetchMetrics,
  } = useApi(
    () => platform.getMetrics(),
    []
  );

  // Fetch tenant info
  const {
    data: tenantData,
    isLoading: tenantLoading,
  } = useApi(
    () => tenantId ? tenant.getTenant(tenantId) : Promise.resolve({ success: true, data: null }),
    [tenantId]
  );

  // Refresh all data
  const handleRefresh = () => {
    refetchUsers();
    refetchDevices();
    refetchCerts();
    refetchHealth();
    refetchMetrics();
  };

  // Build stats from real data
  const stats: DashboardStats[] = useMemo(() => [
    {
      title: "Total Users",
      value: usersLoading ? "..." : (usersData?.total ?? 0),
      icon: Users,
      description: "Active users in the system",
      href: "/iam/users",
      loading: usersLoading,
    },
    {
      title: "Active Devices",
      value: devicesLoading ? "..." : (devicesData?.pagination?.totalItems ?? devicesData?.devices?.length ?? 0),
      icon: Cpu,
      description: "Registered devices",
      href: "/devices",
      loading: devicesLoading,
    },
    {
      title: "Certificates",
      value: certsLoading ? "..." : (certsData?.pagination?.totalItems ?? certsData?.certificates?.length ?? 0),
      icon: FileKey,
      description: "Certificates issued",
      href: "/ca/certificates",
      loading: certsLoading,
    },
    {
      title: "Platform Health",
      value: healthLoading ? "..." : (healthData?.health?.healthy ? "Healthy" : "Degraded"),
      icon: Shield,
      description: healthData?.health?.message ?? "Platform status",
      href: "/platform/health",
      loading: healthLoading,
    },
    {
      title: "Services",
      value: healthLoading ? "..." : (healthData?.health?.services?.length ?? 0),
      icon: Server,
      description: "Running services",
      href: "/platform/services",
      loading: healthLoading,
    },
    {
      title: "Network",
      value: healthLoading ? "..." : (healthData?.health?.healthy ? "Healthy" : "Degraded"),
      icon: Network,
      description: "Network connectivity",
      href: "/networking/sdn",
      loading: healthLoading,
    },
  ], [usersData, devicesData, certsData, healthData, usersLoading, devicesLoading, certsLoading, healthLoading]);

  // Get system metrics for health section
  const cpuUsage = metricsData?.metrics?.cpuUsagePercent ?? 0;
  const memoryUsage = metricsData?.metrics?.memoryUsagePercent ?? 0;
  const diskUsage = metricsData?.metrics?.diskUsagePercent ?? 0;

  // Wall-clock text from an external store: "" during server render and
  // hydration (no timezone mismatch), the client's local time afterwards,
  // re-read every minute. Replaces a setState-in-effect that froze the time
  // at mount.
  const currentTime = useSyncExternalStore(subscribeEveryMinute, readLocalTime, readServerTime);

  const hasErrors = usersError || devicesError || certsError || healthError;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        description={`Welcome back! Here's what's happening today${currentTime ? ` at ${currentTime}` : ""}`}
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        }
      />

      {/* Error Alert */}
      {hasErrors && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error loading data</AlertTitle>
          <AlertDescription>
            Some dashboard data could not be loaded. Please try refreshing.
          </AlertDescription>
        </Alert>
      )}

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {stats.map((stat) => {
          const Icon = stat.icon;

          return (
            <Link key={stat.title} href={stat.href}>
              <Card className="hover:bg-accent/50 transition-colors cursor-pointer">
                <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
                  <CardTitle className="text-sm font-medium">
                    {stat.title}
                  </CardTitle>
                  {stat.loading ? (
                    <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                  ) : (
                    <Icon className="h-4 w-4 text-muted-foreground" />
                  )}
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">
                    {stat.loading ? (
                      <span className="text-muted-foreground">Loading...</span>
                    ) : (
                      stat.value
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">
                    {stat.description}
                  </p>
                </CardContent>
              </Card>
            </Link>
          );
        })}
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Tenant Info */}
        <Card className="col-span-1">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5" />
              Tenant Information
            </CardTitle>
            <CardDescription>Current tenant details</CardDescription>
          </CardHeader>
          <CardContent>
            {tenantLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : tenantData?.tenant ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Name</span>
                  <span className="font-medium">{tenantData.tenant.name ?? "N/A"}</span>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">ID</span>
                  <span className="font-mono text-sm">{tenantData.tenant.id ?? tenantId ?? "N/A"}</span>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Status</span>
                  <Badge variant={tenantData.tenant.state === "ACTIVE" ? "default" : "secondary"}>
                    {tenantData.tenant.state ?? "ACTIVE"}
                  </Badge>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Created</span>
                  <span className="text-sm">
                    {tenantData.tenant.createdAt
                      ? new Date(tenantData.tenant.createdAt).toLocaleDateString()
                      : "N/A"}
                  </span>
                </div>
              </div>
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                No tenant information available
              </div>
            )}
            <Button variant="outline" className="w-full mt-4" asChild>
              <Link href="/tenant">View Tenant Details</Link>
            </Button>
          </CardContent>
        </Card>

        {/* Quick Actions */}
        <Card className="col-span-1">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5" />
              Quick Actions
            </CardTitle>
            <CardDescription>Frequently used operations</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4">
              {quickActions.map((action) => {
                const Icon = action.icon;

                return (
                  <Button
                    key={action.title}
                    variant="outline"
                    className="h-auto flex items-start justify-start p-4 hover:bg-accent"
                    asChild
                  >
                    <Link href={action.href}>
                      <div className="flex items-start gap-3 w-full">
                        <div className="rounded-lg bg-primary/10 p-2">
                          <Icon className="h-5 w-5 text-primary" />
                        </div>
                        <div className="flex-1 text-left">
                          <p className="font-medium">{action.title}</p>
                          <p className="text-sm text-muted-foreground">
                            {action.description}
                          </p>
                        </div>
                        <ArrowUpRight className="h-4 w-4 text-muted-foreground" />
                      </div>
                    </Link>
                  </Button>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* System Health Overview */}
      <Card>
        <CardHeader>
          <CardTitle>System Health</CardTitle>
          <CardDescription>Overall platform status and metrics</CardDescription>
        </CardHeader>
        <CardContent>
          {metricsLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              <span className="ml-2 text-muted-foreground">Loading metrics...</span>
            </div>
          ) : metricsError ? (
            <div className="text-center py-8 text-muted-foreground">
              Unable to load system metrics
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">CPU Usage</span>
                  <Badge variant={cpuUsage > 80 ? "destructive" : cpuUsage > 60 ? "secondary" : "default"}>
                    {cpuUsage > 80 ? "High" : cpuUsage > 60 ? "Moderate" : "Normal"}
                  </Badge>
                </div>
                <div className="h-2 bg-secondary rounded-full overflow-hidden">
                  <div
                    className={`h-full ${cpuUsage > 80 ? "bg-red-500" : cpuUsage > 60 ? "bg-yellow-500" : "bg-primary"}`}
                    style={{ width: `${Math.min(cpuUsage, 100)}%` }}
                  />
                </div>
                <span className="text-xs text-muted-foreground">{cpuUsage.toFixed(1)}%</span>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Memory</span>
                  <Badge variant={memoryUsage > 80 ? "destructive" : memoryUsage > 60 ? "secondary" : "default"}>
                    {memoryUsage > 80 ? "High" : memoryUsage > 60 ? "Moderate" : "Normal"}
                  </Badge>
                </div>
                <div className="h-2 bg-secondary rounded-full overflow-hidden">
                  <div
                    className={`h-full ${memoryUsage > 80 ? "bg-red-500" : memoryUsage > 60 ? "bg-yellow-500" : "bg-primary"}`}
                    style={{ width: `${Math.min(memoryUsage, 100)}%` }}
                  />
                </div>
                <span className="text-xs text-muted-foreground">{memoryUsage.toFixed(1)}%</span>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Storage</span>
                  <Badge variant={diskUsage > 80 ? "destructive" : diskUsage > 60 ? "secondary" : "default"}>
                    {diskUsage > 80 ? "High" : diskUsage > 60 ? "Moderate" : "Normal"}
                  </Badge>
                </div>
                <div className="h-2 bg-secondary rounded-full overflow-hidden">
                  <div
                    className={`h-full ${diskUsage > 80 ? "bg-red-500" : diskUsage > 60 ? "bg-yellow-500" : "bg-primary"}`}
                    style={{ width: `${Math.min(diskUsage, 100)}%` }}
                  />
                </div>
                <span className="text-xs text-muted-foreground">{diskUsage.toFixed(1)}%</span>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Status</span>
                  <Badge variant={healthData?.health?.healthy ? "default" : "destructive"}>
                    {healthData?.health?.healthy ? "Healthy" : "Degraded"}
                  </Badge>
                </div>
                <div className="h-2 bg-secondary rounded-full overflow-hidden">
                  <div
                    className={`h-full ${healthData?.health?.healthy ? "bg-green-500" : "bg-red-500"}`}
                    style={{ width: healthData?.health?.healthy ? "100%" : "50%" }}
                  />
                </div>
                <span className="text-xs text-muted-foreground">
                  {healthData?.health?.healthy ? "All systems operational" : "Issues detected"}
                </span>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
