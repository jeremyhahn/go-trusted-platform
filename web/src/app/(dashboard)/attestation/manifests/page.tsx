"use client";

import * as React from "react";
import { ColumnDef } from "@tanstack/react-table";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { DataTable } from "@/components/ui/data-table";
import { DataTableColumnHeader } from "@/components/ui/data-table-column-header";
import {
  FileText,
  Plus,
  RefreshCw,
  AlertCircle,
  CheckCircle2,
  Clock,
  XCircle,
  Loader2,
} from "lucide-react";
import { useApi, useAttestation, useToast } from "@/hooks";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

/**
 * Attestation Manifest represents a reference measurement manifest
 * used for validating TPM quotes against known-good states.
 */
interface AttestationManifest {
  id: string;
  name: string;
  version: string;
  deviceType: string;
  status: "active" | "draft" | "archived";
  pcrCount: number;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

const statusConfig: Record<
  AttestationManifest["status"],
  { label: string; variant: "default" | "secondary" | "outline"; icon: React.ComponentType<{ className?: string }> }
> = {
  active: { label: "Active", variant: "default", icon: CheckCircle2 },
  draft: { label: "Draft", variant: "secondary", icon: Clock },
  archived: { label: "Archived", variant: "outline", icon: XCircle },
};

const columns: ColumnDef<AttestationManifest>[] = [
  {
    accessorKey: "name",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Name" />
    ),
    cell: ({ row }) => (
      <div className="flex items-center gap-2">
        <FileText className="h-4 w-4 text-muted-foreground" />
        <div>
          <div className="font-medium">{row.getValue("name")}</div>
          <div className="text-xs text-muted-foreground">
            v{row.original.version}
          </div>
        </div>
      </div>
    ),
  },
  {
    accessorKey: "deviceType",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Device Type" />
    ),
    cell: ({ row }) => (
      <span className="capitalize">{row.getValue("deviceType")}</span>
    ),
  },
  {
    accessorKey: "status",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Status" />
    ),
    cell: ({ row }) => {
      const status = row.getValue("status") as AttestationManifest["status"];
      const config = statusConfig[status];
      const Icon = config.icon;
      return (
        <Badge variant={config.variant} className="gap-1">
          <Icon className="h-3 w-3" />
          {config.label}
        </Badge>
      );
    },
    filterFn: (row, id, value) => {
      return value.includes(row.getValue(id));
    },
  },
  {
    accessorKey: "pcrCount",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="PCR Count" />
    ),
    cell: ({ row }) => (
      <span className="font-mono">{row.getValue("pcrCount")}</span>
    ),
  },
  {
    accessorKey: "updatedAt",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Last Updated" />
    ),
    cell: ({ row }) => {
      const date = new Date(row.getValue("updatedAt"));
      return (
        <span className="text-muted-foreground">
          {date.toLocaleDateString()}
        </span>
      );
    },
  },
  {
    accessorKey: "createdBy",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Created By" />
    ),
    cell: ({ row }) => (
      <span className="text-muted-foreground">{row.getValue("createdBy")}</span>
    ),
  },
];

/**
 * Attestation Manifests Page
 *
 * Features:
 * - View all attestation manifests
 * - Filter by status and device type
 * - Create new manifests
 * - View manifest details
 */
export default function ManifestsPage() {
  const { toast } = useToast();
  const attestation = useAttestation();

  // Fetch manifests using SDK
  const {
    data: manifestsData,
    isLoading,
    error,
    refetch,
  } = useApi(
    () => attestation.listManifests({}),
    [],
    {
      onError: (err) => {
        toast({
          title: 'Error loading manifests',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Transform SDK manifests to UI format
  const manifests = React.useMemo<AttestationManifest[]>(() => {
    if (!manifestsData?.manifests) return [];

    return manifestsData.manifests.map((manifest) => {
      // Count total PCRs from host and VMs
      let pcrCount = manifest.host?.pcrs?.length || 0;
      manifest.vms?.forEach((vm) => {
        pcrCount += vm.pcrs?.length || 0;
      });

      // Determine status based on manifest age and validity
      const manifestAge = Date.now() - new Date(manifest.timestamp).getTime();
      const oneDayMs = 24 * 60 * 60 * 1000;
      let status: "active" | "draft" | "archived" = "active";

      if (manifestAge > 30 * oneDayMs) {
        status = "archived";
      } else if (!manifest.signature) {
        status = "draft";
      }

      return {
        id: manifest.id,
        name: `Manifest ${manifest.hostId}`,
        version: manifest.version || "1.0.0",
        deviceType: manifest.vms && manifest.vms.length > 0 ? "server" : "workstation",
        status,
        pcrCount,
        createdAt: manifest.timestamp,
        updatedAt: manifest.timestamp,
        createdBy: manifest.hostId,
      };
    });
  }, [manifestsData]);

  const stats = React.useMemo(() => {
    return {
      total: manifests.length,
      active: manifests.filter((m) => m.status === "active").length,
      draft: manifests.filter((m) => m.status === "draft").length,
      archived: manifests.filter((m) => m.status === "archived").length,
    };
  }, [manifests]);

  if (error) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Manifests</AlertTitle>
          <AlertDescription>
            {error.message}
            <Button
              variant="outline"
              size="sm"
              className="ml-4"
              onClick={() => refetch()}
            >
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="container mx-auto py-6">
        <Card>
          <CardContent className="py-6 flex items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin mr-2" />
            <span>Loading manifests...</span>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">
            Attestation Manifests
          </h1>
          <p className="text-muted-foreground">
            Manage reference measurement manifests for TPM attestation
            verification
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => refetch()} disabled={isLoading}>
            <RefreshCw
              className={`mr-2 h-4 w-4 ${isLoading ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
          <Button>
            <Plus className="mr-2 h-4 w-4" />
            Create Manifest
          </Button>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Total Manifests
            </CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">
              Reference measurement profiles
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active</CardTitle>
            <CheckCircle2 className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {stats.active}
            </div>
            <p className="text-xs text-muted-foreground">
              In use for verification
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Draft</CardTitle>
            <Clock className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
              {stats.draft}
            </div>
            <p className="text-xs text-muted-foreground">Awaiting activation</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Archived</CardTitle>
            <XCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-muted-foreground">
              {stats.archived}
            </div>
            <p className="text-xs text-muted-foreground">
              No longer in active use
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Manifests Table */}
      <Card>
        <CardHeader>
          <CardTitle>Manifests</CardTitle>
          <CardDescription>
            Reference measurement manifests define the expected PCR values for
            device attestation
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={manifests}
            searchKey="name"
            searchPlaceholder="Search manifests..."
            filterableColumns={[
              {
                id: "status",
                title: "Status",
                options: [
                  { label: "Active", value: "active" },
                  { label: "Draft", value: "draft" },
                  { label: "Archived", value: "archived" },
                ],
              },
              {
                id: "deviceType",
                title: "Device Type",
                options: [
                  { label: "Server", value: "server" },
                  { label: "Workstation", value: "workstation" },
                  { label: "IoT", value: "iot" },
                ],
              },
            ]}
            loading={isLoading}
            emptyState={
              <div className="flex flex-col items-center justify-center py-8 text-center">
                <FileText className="h-12 w-12 text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold">No manifests found</h3>
                <p className="text-sm text-muted-foreground">
                  Create your first attestation manifest to get started
                </p>
              </div>
            }
          />
        </CardContent>
      </Card>
    </div>
  );
}
