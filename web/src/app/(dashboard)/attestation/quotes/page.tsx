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
  Quote,
  RefreshCw,
  AlertCircle,
  CheckCircle2,
  Clock,
  XCircle,
  Cpu,
  Eye,
  Download,
  Loader2,
} from "lucide-react";
import { useApi, useAttestation, useToast } from "@/hooks";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

/**
 * TPM Quote represents a cryptographically signed attestation quote
 * from a device's TPM containing PCR values.
 */
interface TPMQuote {
  id: string;
  deviceId: string;
  deviceName: string;
  tpmManufacturer: string;
  status: "verified" | "pending" | "failed" | "expired";
  algorithm: string;
  nonce: string;
  pcrSelection: number[];
  quotedAt: string;
  expiresAt: string;
}

const statusConfig: Record<
  TPMQuote["status"],
  {
    label: string;
    variant: "default" | "secondary" | "destructive" | "outline";
    icon: React.ComponentType<{ className?: string }>;
  }
> = {
  verified: { label: "Verified", variant: "default", icon: CheckCircle2 },
  pending: { label: "Pending", variant: "secondary", icon: Clock },
  failed: { label: "Failed", variant: "destructive", icon: XCircle },
  expired: { label: "Expired", variant: "outline", icon: Clock },
};

const columns: ColumnDef<TPMQuote>[] = [
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
          <div className="text-xs text-muted-foreground">
            {row.original.tpmManufacturer} TPM
          </div>
        </div>
      </div>
    ),
  },
  {
    accessorKey: "status",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Status" />
    ),
    cell: ({ row }) => {
      const status = row.getValue("status") as TPMQuote["status"];
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
    accessorKey: "algorithm",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Algorithm" />
    ),
    cell: ({ row }) => (
      <span className="font-mono text-sm">{row.getValue("algorithm")}</span>
    ),
  },
  {
    accessorKey: "pcrSelection",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="PCRs" />
    ),
    cell: ({ row }) => {
      const pcrs = row.getValue("pcrSelection") as number[];
      return (
        <span className="text-muted-foreground">
          {pcrs.length} PCRs ({pcrs[0]}-{pcrs[pcrs.length - 1]})
        </span>
      );
    },
  },
  {
    accessorKey: "quotedAt",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Quoted At" />
    ),
    cell: ({ row }) => {
      const date = new Date(row.getValue("quotedAt"));
      return (
        <span className="text-muted-foreground">
          {date.toLocaleString()}
        </span>
      );
    },
  },
  {
    id: "actions",
    cell: ({ row }) => (
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm">
          <Eye className="h-4 w-4" />
        </Button>
        <Button variant="ghost" size="sm">
          <Download className="h-4 w-4" />
        </Button>
      </div>
    ),
  },
];

/**
 * TPM Quotes Page
 *
 * Features:
 * - View all TPM quotes from devices
 * - Filter by status and algorithm
 * - View quote details including PCR values
 * - Download quote data
 */
export default function QuotesPage() {
  const { toast } = useToast();
  const attestation = useAttestation();

  // Fetch manifests to extract quotes data
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
          title: 'Error loading quotes',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // One clock sample per mount (Date.now() is impure in render).
  const [now] = React.useState(() => Date.now());

  // Transform manifests to extract quote information
  const quotes = React.useMemo<TPMQuote[]>(() => {
    if (!manifestsData?.manifests) return [];

    const extractedQuotes: TPMQuote[] = [];

    manifestsData.manifests.forEach((manifest) => {
      // Extract host quote
      if (manifest.host) {
        const pcrIndices = manifest.host.pcrs?.map((p) => p.index) || [];
        const quoteAge = now - new Date(manifest.timestamp).getTime();
        const oneDayMs = 24 * 60 * 60 * 1000;

        let status: "verified" | "pending" | "failed" | "expired" = "verified";
        if (quoteAge > 7 * oneDayMs) {
          status = "expired";
        } else if (!manifest.signature) {
          status = "pending";
        }

        extractedQuotes.push({
          id: `${manifest.id}-host`,
          deviceId: manifest.hostId,
          deviceName: manifest.hostId,
          tpmManufacturer: "TPM 2.0",
          status,
          algorithm: manifest.host.hashAlgorithm,
          nonce: manifest.nonce?.substring(0, 12) || "N/A",
          pcrSelection: pcrIndices,
          quotedAt: manifest.host.timestamp,
          expiresAt: new Date(new Date(manifest.host.timestamp).getTime() + 7 * oneDayMs).toISOString(),
        });
      }

      // Extract VM quotes
      manifest.vms?.forEach((vm) => {
        const pcrIndices = vm.pcrs?.map((p) => p.index) || [];
        const quoteAge = Date.now() - new Date(vm.timestamp).getTime();
        const oneDayMs = 24 * 60 * 60 * 1000;

        let status: "verified" | "pending" | "failed" | "expired" = "verified";
        if (quoteAge > 7 * oneDayMs) {
          status = "expired";
        } else if (!vm.signature) {
          status = "pending";
        }

        extractedQuotes.push({
          id: `${manifest.id}-${vm.vmId}`,
          deviceId: vm.vmId,
          deviceName: `VM: ${vm.vmId}`,
          tpmManufacturer: "vTPM 2.0",
          status,
          algorithm: vm.hashAlgorithm,
          nonce: vm.nonce?.substring(0, 12) || "N/A",
          pcrSelection: pcrIndices,
          quotedAt: vm.timestamp,
          expiresAt: new Date(new Date(vm.timestamp).getTime() + 7 * oneDayMs).toISOString(),
        });
      });
    });

    return extractedQuotes;
  }, [manifestsData, now]);

  const stats = React.useMemo(() => {
    return {
      total: quotes.length,
      verified: quotes.filter((q) => q.status === "verified").length,
      pending: quotes.filter((q) => q.status === "pending").length,
      failed: quotes.filter((q) => q.status === "failed").length,
      expired: quotes.filter((q) => q.status === "expired").length,
    };
  }, [quotes]);

  if (error) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Quotes</AlertTitle>
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
            <span>Loading quotes...</span>
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
          <h1 className="text-3xl font-bold tracking-tight">TPM Quotes</h1>
          <p className="text-muted-foreground">
            View cryptographically signed attestation quotes from device TPMs
          </p>
        </div>
        <Button variant="outline" onClick={() => refetch()} disabled={isLoading}>
          <RefreshCw
            className={`mr-2 h-4 w-4 ${isLoading ? "animate-spin" : ""}`}
          />
          Refresh
        </Button>
      </div>

      {/* Statistics Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Quotes</CardTitle>
            <Quote className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">
              All attestation quotes
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Verified</CardTitle>
            <CheckCircle2 className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {stats.verified}
            </div>
            <p className="text-xs text-muted-foreground">
              Successfully validated
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Pending</CardTitle>
            <Clock className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
              {stats.pending}
            </div>
            <p className="text-xs text-muted-foreground">
              Awaiting verification
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
              Verification failed
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Expired</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-muted-foreground">
              {stats.expired}
            </div>
            <p className="text-xs text-muted-foreground">
              Past validity period
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Quotes Table */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Quotes</CardTitle>
          <CardDescription>
            TPM quotes contain signed PCR values that prove device integrity
            state
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={quotes}
            searchKey="deviceName"
            searchPlaceholder="Search by device name..."
            filterableColumns={[
              {
                id: "status",
                title: "Status",
                options: [
                  { label: "Verified", value: "verified" },
                  { label: "Pending", value: "pending" },
                  { label: "Failed", value: "failed" },
                  { label: "Expired", value: "expired" },
                ],
              },
              {
                id: "algorithm",
                title: "Algorithm",
                options: [
                  { label: "SHA-256", value: "SHA256" },
                  { label: "SHA-384", value: "SHA384" },
                  { label: "SHA-512", value: "SHA512" },
                  { label: "SHA-1", value: "SHA1" },
                ],
              },
            ]}
            loading={isLoading}
            emptyState={
              <div className="flex flex-col items-center justify-center py-8 text-center">
                <Quote className="h-12 w-12 text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold">No quotes found</h3>
                <p className="text-sm text-muted-foreground">
                  TPM quotes will appear here when devices report attestation
                  data
                </p>
              </div>
            }
          />
        </CardContent>
      </Card>
    </div>
  );
}
