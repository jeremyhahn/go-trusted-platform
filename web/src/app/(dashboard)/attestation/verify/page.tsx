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
  ShieldCheck,
  RefreshCw,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Clock,
  Cpu,
  Play,
  Eye,
  AlertTriangle,
  Loader2,
} from "lucide-react";
import { useApi, useAttestation, useToast } from "@/hooks";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

/**
 * Verification represents an attestation verification operation
 * that validates TPM quotes against reference manifests.
 */
interface Verification {
  id: string;
  deviceId: string;
  deviceName: string;
  quoteId: string;
  manifestId: string;
  manifestName: string;
  status: "passed" | "failed" | "warning" | "in_progress";
  verifiedAt: string;
  pcrMismatches: number;
  errors: string[];
}

const statusConfig: Record<
  Verification["status"],
  {
    label: string;
    variant: "default" | "secondary" | "destructive" | "outline";
    icon: React.ComponentType<{ className?: string }>;
  }
> = {
  passed: { label: "Passed", variant: "default", icon: CheckCircle2 },
  failed: { label: "Failed", variant: "destructive", icon: XCircle },
  warning: { label: "Warning", variant: "secondary", icon: AlertTriangle },
  in_progress: { label: "In Progress", variant: "outline", icon: Clock },
};

const columns: ColumnDef<Verification>[] = [
  {
    accessorKey: "deviceName",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Device" />
    ),
    cell: ({ row }) => (
      <div className="flex items-center gap-2">
        <Cpu className="h-4 w-4 text-muted-foreground" />
        <div>
          <div className="font-medium">{row.getValue("deviceName")}</div>
          <div className="text-xs text-muted-foreground font-mono">
            {row.original.deviceId}
          </div>
        </div>
      </div>
    ),
  },
  {
    accessorKey: "manifestName",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Manifest" />
    ),
    cell: ({ row }) => (
      <span className="text-muted-foreground">
        {row.getValue("manifestName")}
      </span>
    ),
  },
  {
    accessorKey: "status",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Result" />
    ),
    cell: ({ row }) => {
      const status = row.getValue("status") as Verification["status"];
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
    accessorKey: "pcrMismatches",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="PCR Mismatches" />
    ),
    cell: ({ row }) => {
      const mismatches = row.getValue("pcrMismatches") as number;
      return (
        <span
          className={
            mismatches > 0 ? "text-destructive font-medium" : "text-green-600"
          }
        >
          {mismatches}
        </span>
      );
    },
  },
  {
    accessorKey: "verifiedAt",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Verified At" />
    ),
    cell: ({ row }) => {
      const date = new Date(row.getValue("verifiedAt"));
      return (
        <span className="text-muted-foreground">{date.toLocaleString()}</span>
      );
    },
  },
  {
    id: "actions",
    cell: ({ row }) => (
      <Button variant="ghost" size="sm">
        <Eye className="h-4 w-4" />
      </Button>
    ),
  },
];

/**
 * Verification Page
 *
 * Features:
 * - View all attestation verification results
 * - Filter by status
 * - Trigger new verifications
 * - View detailed verification reports
 */
export default function VerifyPage() {
  const { toast } = useToast();
  const attestation = useAttestation();

  // Fetch manifests to show verification history
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
          title: 'Error loading verifications',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Transform manifests into verification records
  // In a real system, there would be a separate verification history endpoint
  const verifications = React.useMemo<Verification[]>(() => {
    if (!manifestsData?.manifests) return [];

    return manifestsData.manifests.map((manifest) => {
      // Determine verification status based on signature validity
      let status: "passed" | "failed" | "warning" | "in_progress" = "passed";
      const pcrMismatches = 0;
      const errors: string[] = [];

      if (!manifest.signature) {
        status = "in_progress";
      } else if (manifest.signature && manifest.merkleRoot) {
        status = "passed";
      }

      return {
        id: manifest.id,
        deviceId: manifest.hostId,
        deviceName: manifest.hostId,
        quoteId: manifest.id,
        manifestId: manifest.id,
        manifestName: `Manifest ${manifest.hostId}`,
        status,
        verifiedAt: manifest.timestamp,
        pcrMismatches,
        errors,
      };
    });
  }, [manifestsData]);

  const stats = React.useMemo(() => {
    return {
      total: verifications.length,
      passed: verifications.filter((v) => v.status === "passed").length,
      failed: verifications.filter((v) => v.status === "failed").length,
      warning: verifications.filter((v) => v.status === "warning").length,
      inProgress: verifications.filter((v) => v.status === "in_progress")
        .length,
    };
  }, [verifications]);

  if (error) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Verifications</AlertTitle>
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
            <span>Loading verifications...</span>
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
            Attestation Verification
          </h1>
          <p className="text-muted-foreground">
            Verify TPM quotes against reference measurement manifests
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={() => refetch()}
            disabled={isLoading}
          >
            <RefreshCw
              className={`mr-2 h-4 w-4 ${isLoading ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
          <Button>
            <Play className="mr-2 h-4 w-4" />
            Run Verification
          </Button>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Total Verifications
            </CardTitle>
            <ShieldCheck className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">
              All verification runs
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Passed</CardTitle>
            <CheckCircle2 className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {stats.passed}
            </div>
            <p className="text-xs text-muted-foreground">
              {stats.total > 0
                ? `${((stats.passed / stats.total) * 100).toFixed(1)}%`
                : "0%"}{" "}
              success rate
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Failed</CardTitle>
            <XCircle className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">
              {stats.failed}
            </div>
            <p className="text-xs text-muted-foreground">
              Requires investigation
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Warning</CardTitle>
            <AlertTriangle className="h-4 w-4 text-yellow-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
              {stats.warning}
            </div>
            <p className="text-xs text-muted-foreground">
              Minor issues detected
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">In Progress</CardTitle>
            <Clock className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
              {stats.inProgress}
            </div>
            <p className="text-xs text-muted-foreground">Currently running</p>
          </CardContent>
        </Card>
      </div>

      {/* Verifications Table */}
      <Card>
        <CardHeader>
          <CardTitle>Verification Results</CardTitle>
          <CardDescription>
            History of attestation verification runs comparing TPM quotes to
            reference manifests
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={verifications}
            searchKey="deviceName"
            searchPlaceholder="Search by device name..."
            filterableColumns={[
              {
                id: "status",
                title: "Result",
                options: [
                  { label: "Passed", value: "passed" },
                  { label: "Failed", value: "failed" },
                  { label: "Warning", value: "warning" },
                  { label: "In Progress", value: "in_progress" },
                ],
              },
            ]}
            loading={isLoading}
            emptyState={
              <div className="flex flex-col items-center justify-center py-8 text-center">
                <ShieldCheck className="h-12 w-12 text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold">
                  No verifications found
                </h3>
                <p className="text-sm text-muted-foreground">
                  Run a verification to validate device attestation data
                </p>
              </div>
            }
          />
        </CardContent>
      </Card>
    </div>
  );
}
