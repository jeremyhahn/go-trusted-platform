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
  ScrollText,
  RefreshCw,
  AlertCircle,
  Cpu,
  Eye,
  Download,
  Hash,
  FileCode,
  Loader2,
} from "lucide-react";
import { useApi, useAttestation, useToast } from "@/hooks";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

/**
 * EventLog represents a TPM event log entry that records
 * measurements extended into PCRs during the boot process.
 */
interface EventLog {
  id: string;
  deviceId: string;
  deviceName: string;
  pcrIndex: number;
  eventType: string;
  eventTypeCode: number;
  digest: string;
  digestAlgorithm: string;
  dataSize: number;
  timestamp: string;
  description: string;
}

const pcrColors: Record<number, string> = {
  0: "bg-blue-500/10 text-blue-600 border-blue-500/20",
  1: "bg-green-500/10 text-green-600 border-green-500/20",
  2: "bg-purple-500/10 text-purple-600 border-purple-500/20",
  3: "bg-orange-500/10 text-orange-600 border-orange-500/20",
  4: "bg-red-500/10 text-red-600 border-red-500/20",
  5: "bg-yellow-500/10 text-yellow-600 border-yellow-500/20",
  6: "bg-pink-500/10 text-pink-600 border-pink-500/20",
  7: "bg-cyan-500/10 text-cyan-600 border-cyan-500/20",
};

const columns: ColumnDef<EventLog>[] = [
  {
    accessorKey: "deviceName",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Device" />
    ),
    cell: ({ row }) => (
      <div className="flex items-center gap-2">
        <Cpu className="h-4 w-4 text-muted-foreground" />
        <span className="font-medium">{row.getValue("deviceName")}</span>
      </div>
    ),
  },
  {
    accessorKey: "pcrIndex",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="PCR" />
    ),
    cell: ({ row }) => {
      const pcr = row.getValue("pcrIndex") as number;
      const colorClass = pcrColors[pcr] || "bg-gray-500/10 text-gray-600 border-gray-500/20";
      return (
        <Badge variant="outline" className={`font-mono ${colorClass}`}>
          PCR[{pcr}]
        </Badge>
      );
    },
    filterFn: (row, id, value) => {
      return value.includes(String(row.getValue(id)));
    },
  },
  {
    accessorKey: "eventType",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Event Type" />
    ),
    cell: ({ row }) => (
      <div>
        <div className="font-mono text-xs">{row.getValue("eventType")}</div>
        <div className="text-xs text-muted-foreground">
          {row.original.description}
        </div>
      </div>
    ),
  },
  {
    accessorKey: "digest",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Digest" />
    ),
    cell: ({ row }) => {
      const digest = row.getValue("digest") as string;
      return (
        <div className="flex items-center gap-2">
          <Hash className="h-3 w-3 text-muted-foreground" />
          <span className="font-mono text-xs truncate max-w-[200px]">
            {digest.substring(0, 16)}...
          </span>
        </div>
      );
    },
  },
  {
    accessorKey: "digestAlgorithm",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Algorithm" />
    ),
    cell: ({ row }) => (
      <span className="font-mono text-xs">
        {row.getValue("digestAlgorithm")}
      </span>
    ),
    filterFn: (row, id, value) => {
      return value.includes(row.getValue(id));
    },
  },
  {
    accessorKey: "timestamp",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Timestamp" />
    ),
    cell: ({ row }) => {
      const date = new Date(row.getValue("timestamp"));
      return (
        <span className="text-muted-foreground text-sm">
          {date.toLocaleTimeString()}
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
      </div>
    ),
  },
];

/**
 * Event Logs Page
 *
 * Features:
 * - View TPM event logs from devices
 * - Filter by PCR index, event type, and device
 * - View event details including digests
 * - Export event logs
 */
export default function EventLogsPage() {
  const { toast } = useToast();
  const attestation = useAttestation();

  // Fetch manifests to extract event log data
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
          title: 'Error loading event logs',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Transform manifests into event logs
  // Note: Event logs are embedded in manifests and quotes
  // For a complete event log viewer, we'd need to parse the eventLog field from quotes
  const eventLogs = React.useMemo<EventLog[]>(() => {
    if (!manifestsData?.manifests) return [];

    const logs: EventLog[] = [];

    // Extract PCR data from manifests as pseudo event logs
    manifestsData.manifests.forEach((manifest) => {
      // Extract host PCRs if available
      if (manifest.host?.pcrs) {
        manifest.host.pcrs.forEach((pcr, idx) => {
          logs.push({
            id: `${manifest.id}-host-pcr-${pcr.index}`,
            deviceId: manifest.hostId,
            deviceName: manifest.hostId,
            pcrIndex: pcr.index,
            eventType: 'PCR_VALUE',
            eventTypeCode: 0,
            digest: pcr.value,
            digestAlgorithm: pcr.algorithm,
            dataSize: Buffer.from(pcr.value, 'base64').length,
            timestamp: manifest.timestamp,
            description: `Host PCR ${pcr.index} value`,
          });
        });
      }

      // Extract VM PCRs if available
      manifest.vms?.forEach((vm) => {
        vm.pcrs?.forEach((pcr) => {
          logs.push({
            id: `${manifest.id}-${vm.vmId}-pcr-${pcr.index}`,
            deviceId: vm.vmId,
            deviceName: `VM: ${vm.vmId}`,
            pcrIndex: pcr.index,
            eventType: 'VM_PCR_VALUE',
            eventTypeCode: 0,
            digest: pcr.value,
            digestAlgorithm: pcr.algorithm,
            dataSize: Buffer.from(pcr.value, 'base64').length,
            timestamp: vm.timestamp,
            description: `VM ${vm.vmId} PCR ${pcr.index} value`,
          });
        });
      });
    });

    return logs;
  }, [manifestsData]);

  const stats = React.useMemo(() => {
    const pcrCounts: Record<number, number> = {};
    const deviceCounts: Record<string, number> = {};

    eventLogs.forEach((log) => {
      pcrCounts[log.pcrIndex] = (pcrCounts[log.pcrIndex] || 0) + 1;
      deviceCounts[log.deviceId] = (deviceCounts[log.deviceId] || 0) + 1;
    });

    return {
      total: eventLogs.length,
      devices: Object.keys(deviceCounts).length,
      uniquePcrs: Object.keys(pcrCounts).length,
      pcrCounts,
    };
  }, [eventLogs]);

  const handleExport = () => {
    const json = JSON.stringify(eventLogs, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `event-logs-${new Date().toISOString().split("T")[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (error) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Event Logs</AlertTitle>
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
            <span>Loading event logs...</span>
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
            TPM Event Logs
          </h1>
          <p className="text-muted-foreground">
            Browse and analyze TPM event log entries from device boot and
            runtime measurements
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={handleExport}
            disabled={eventLogs.length === 0}
          >
            <Download className="mr-2 h-4 w-4" />
            Export
          </Button>
          <Button variant="outline" onClick={() => refetch()} disabled={isLoading}>
            <RefreshCw
              className={`mr-2 h-4 w-4 ${isLoading ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Events</CardTitle>
            <ScrollText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">
              Measurement log entries
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Devices</CardTitle>
            <Cpu className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.devices}</div>
            <p className="text-xs text-muted-foreground">
              With event log data
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">PCRs Used</CardTitle>
            <Hash className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.uniquePcrs}</div>
            <p className="text-xs text-muted-foreground">
              Unique PCR indices
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Event Types</CardTitle>
            <FileCode className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {new Set(eventLogs.map((e) => e.eventType)).size}
            </div>
            <p className="text-xs text-muted-foreground">
              Unique event types
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Event Logs Table */}
      <Card>
        <CardHeader>
          <CardTitle>Event Log Entries</CardTitle>
          <CardDescription>
            TPM event logs record measurements extended into PCRs during boot
            and runtime
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={eventLogs}
            searchKey="deviceName"
            searchPlaceholder="Search by device name..."
            filterableColumns={[
              {
                id: "pcrIndex",
                title: "PCR Index",
                options: Array.from({ length: 24 }, (_, i) => ({
                  label: `PCR[${i}]`,
                  value: String(i),
                })).filter((opt) =>
                  eventLogs.some((log) => log.pcrIndex === Number(opt.value))
                ),
              },
              {
                id: "digestAlgorithm",
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
                <ScrollText className="h-12 w-12 text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold">No event logs found</h3>
                <p className="text-sm text-muted-foreground">
                  Event logs will appear here when devices report TPM
                  measurements
                </p>
              </div>
            }
          />
        </CardContent>
      </Card>
    </div>
  );
}
