"use client";

import * as React from "react";
import {
  RefreshCw,
  Server,
  CheckCircle,
  XCircle,
  AlertCircle,
  Loader2,
} from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DataTable } from "@/components/ui/data-table";
import { DataTableColumnHeader } from "@/components/ui/data-table-column-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useApi, usePlatform, useToast } from "@/hooks";
import type { ColumnDef } from "@tanstack/react-table";

/**
 * Service status type
 */
type ServiceState = "running" | "stopped" | "starting" | "stopping" | "error";

/**
 * Platform service interface
 */
interface PlatformService {
  id: string;
  name: string;
  displayName: string;
  state: ServiceState;
  latencyMs: number;
  lastCheck: string | null;
  message: string;
  healthy: boolean;
}

/**
 * Get state badge variant based on service state
 */
function getStateBadge(state: ServiceState) {
  const variants: Record<ServiceState, { variant: "default" | "secondary" | "destructive" | "outline"; icon: React.ReactNode }> = {
    running: { variant: "default", icon: <CheckCircle className="h-3 w-3 mr-1" /> },
    stopped: { variant: "secondary", icon: <XCircle className="h-3 w-3 mr-1" /> },
    starting: { variant: "outline", icon: <RefreshCw className="h-3 w-3 mr-1 animate-spin" /> },
    stopping: { variant: "outline", icon: <RefreshCw className="h-3 w-3 mr-1 animate-spin" /> },
    error: { variant: "destructive", icon: <AlertCircle className="h-3 w-3 mr-1" /> },
  };

  const { variant, icon } = variants[state];
  return (
    <Badge variant={variant} className="capitalize">
      {icon}
      {state}
    </Badge>
  );
}

/**
 * Table columns for services
 */
const columns: ColumnDef<PlatformService>[] = [
  {
    accessorKey: "displayName",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Service" />
    ),
    cell: ({ row }) => (
      <div className="flex flex-col">
        <span className="font-medium">{row.original.displayName}</span>
        <span className="text-xs text-muted-foreground">{row.original.name}</span>
      </div>
    ),
  },
  {
    accessorKey: "state",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Status" />
    ),
    cell: ({ row }) => getStateBadge(row.original.state),
    filterFn: (row, id, value) => {
      return value.includes(row.getValue(id));
    },
  },
  {
    accessorKey: "latencyMs",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Latency" />
    ),
    cell: ({ row }) => (
      <span className="font-mono text-sm">
        {row.original.latencyMs.toFixed(2)} ms
      </span>
    ),
  },
  {
    accessorKey: "lastCheck",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Last Check" />
    ),
    cell: ({ row }) => {
      if (!row.original.lastCheck) return "-";
      const date = new Date(row.original.lastCheck);
      return (
        <span className="text-sm">
          {date.toLocaleTimeString()}
        </span>
      );
    },
  },
  {
    accessorKey: "message",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Message" />
    ),
    cell: ({ row }) => (
      <span className="text-sm text-muted-foreground truncate max-w-md">
        {row.original.message || "No message"}
      </span>
    ),
  },
];

/**
 * Platform Services Page
 *
 * Features:
 * - List all platform services
 * - Service health status indicators
 * - Service latency metrics
 * - Service statistics overview
 */
export default function ServicesPage() {
  const { toast } = useToast();
  const platform = usePlatform();

  // Fetch platform health with service details
  const {
    data: healthData,
    isLoading,
    error,
    refetch,
  } = useApi(
    () => platform.getHealth({ includeServices: true }),
    [],
    {
      onError: (err) => {
        toast({
          title: "Error loading services",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Transform health data into services
  const services: PlatformService[] = React.useMemo(() => {
    if (!healthData?.health?.services) return [];

    return healthData.health.services.map((service) => ({
      id: service.name,
      name: service.name,
      displayName: service.name.replace(/-/g, " ").replace(/\b\w/g, (l) => l.toUpperCase()),
      state: service.healthy ? "running" : "error",
      latencyMs: service.latencyMs || 0,
      lastCheck: service.lastCheck || null,
      message: service.message || "",
      healthy: service.healthy,
    }));
  }, [healthData]);

  // Calculate statistics
  const stats = React.useMemo(() => {
    const running = services.filter((s) => s.state === "running").length;
    const stopped = services.filter((s) => s.state === "stopped").length;
    const error = services.filter((s) => s.state === "error").length;

    return { running, stopped, error, total: services.length };
  }, [services]);

  const handleRefresh = () => {
    refetch();
  };

  // Show error state
  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Platform Services"
          description="Manage and monitor platform services"
        />
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Services</AlertTitle>
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

  return (
    <div className="space-y-6">
      <PageHeader
        title="Platform Services"
        description="Manage and monitor platform services"
      >
        <Button
          variant="outline"
          size="sm"
          onClick={handleRefresh}
          disabled={isLoading}
        >
          <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </PageHeader>

      {/* Statistics Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Services</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">
              Platform services configured
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Running</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{stats.running}</div>
            <p className="text-xs text-muted-foreground">
              Services currently active
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Stopped</CardTitle>
            <XCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.stopped}</div>
            <p className="text-xs text-muted-foreground">
              Services currently stopped
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Errors</CardTitle>
            <AlertCircle className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">{stats.error}</div>
            <p className="text-xs text-muted-foreground">
              Services with errors
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Services Table */}
      <Card>
        <CardHeader>
          <CardTitle>Services</CardTitle>
          <CardDescription>
            View and manage all platform services. Use the controls to start, stop, or restart services.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center h-64">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
              <span className="ml-2">Loading services...</span>
            </div>
          ) : services.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
              <Server className="h-12 w-12 mb-4" />
              <p>No services found</p>
              <p className="text-sm">No service health data available</p>
            </div>
          ) : (
            <DataTable
              columns={columns}
              data={services}
              searchKey="displayName"
              searchPlaceholder="Search services..."
              filterableColumns={[
                {
                  id: "state",
                  title: "Status",
                  options: [
                    { label: "Running", value: "running" },
                    { label: "Stopped", value: "stopped" },
                    { label: "Starting", value: "starting" },
                    { label: "Stopping", value: "stopping" },
                    { label: "Error", value: "error" },
                  ],
                },
              ]}
              loading={false}
              pagination
              pageSize={10}
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
