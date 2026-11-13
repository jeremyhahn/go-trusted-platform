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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { DataTable, createSelectColumn } from "@/components/ui/data-table";
import { DataTableColumnHeader } from "@/components/ui/data-table-column-header";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { usePlatformClient, useMutation, useToast } from "@/hooks";
import type {
  TimeSeriesQueryResponse,
  TimeSeriesAggregateResponse,
  AggregationFunction,
  TimeBucket,
} from "trusted-platform-sdk";
import {
  Plus,
  RefreshCw,
  Activity,
  TrendingUp,
  BarChart3,
  Trash2,
  MoreHorizontal,
  Clock,
  Search,
  LineChart,
  Gauge,
  Hash,
  Info,
} from "lucide-react";

/**
 * UI representation of a time-series metric derived from query data
 */
interface TimeSeriesMetricUI {
  id: string;
  name: string;
  description?: string;
  unit: string;
  type: "counter" | "gauge" | "histogram" | "summary";
  labels: Record<string, string>;
  retention: string;
  createdAt: string;
  dataPointCount: number;
  lastValue?: number;
  lastTimestamp?: number;
}

/**
 * Form data for querying time-series data
 */
interface QueryFormData {
  metric: string;
  startTime: string;
  endTime: string;
  aggregation: AggregationFunction;
  bucket: TimeBucket;
}

/**
 * Time Series Database Viewer Page
 *
 * Features:
 * - Query time series data with aggregations
 * - View data points and aggregation results
 * - Support for various aggregation functions
 * - Delete data ranges (with confirmation)
 */
export default function TimeSeriesPage() {
  const { toast } = useToast();
  const client = usePlatformClient();
  const [isQueryDialogOpen, setIsQueryDialogOpen] = React.useState(false);
  const [isCreateDialogOpen, setIsCreateDialogOpen] = React.useState(false);
  const [queryResult, setQueryResult] = React.useState<TimeSeriesQueryResponse | null>(null);
  const [aggregateResult, setAggregateResult] = React.useState<TimeSeriesAggregateResponse | null>(null);
  const [metrics, setMetrics] = React.useState<TimeSeriesMetricUI[]>([]);
  const [queryData, setQueryData] = React.useState<QueryFormData>(() => ({
    metric: "",
    startTime: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().slice(0, 16),
    endTime: new Date().toISOString().slice(0, 16),
    aggregation: "AVG",
    bucket: "HOUR",
  }));

  // Sample metrics for demonstration (since the service doesn't have a list operation)
  // In production, these would be discovered through the query API or stored elsewhere
  const sampleMetrics: TimeSeriesMetricUI[] = React.useMemo((): TimeSeriesMetricUI[] => [
    {
      id: "1",
      name: "cpu.usage",
      description: "CPU usage percentage",
      unit: "percent",
      type: "gauge" as const,
      labels: { host: "server-1" },
      retention: "30d",
      createdAt: new Date().toISOString(),
      dataPointCount: 0,
    },
    {
      id: "2",
      name: "memory.used",
      description: "Memory usage in bytes",
      unit: "bytes",
      type: "gauge" as const,
      labels: { host: "server-1" },
      retention: "30d",
      createdAt: new Date().toISOString(),
      dataPointCount: 0,
    },
    {
      id: "3",
      name: "requests.total",
      description: "Total HTTP requests",
      unit: "count",
      type: "counter" as const,
      labels: { service: "api" },
      retention: "90d",
      createdAt: new Date().toISOString(),
      dataPointCount: 0,
    },
    {
      id: "4",
      name: "request.latency",
      description: "Request latency histogram",
      unit: "ms",
      type: "histogram" as const,
      labels: { service: "api" },
      retention: "30d",
      createdAt: new Date().toISOString(),
      dataPointCount: 0,
    },
  ], []);

  // Aggregate mutation for time-series aggregations
  const aggregateMutation = useMutation(
    async (data: QueryFormData) => {
      const startTime = new Date(data.startTime).getTime();
      const endTime = new Date(data.endTime).getTime();
      return client.quicBaaSTimeSeries.aggregate({
        metric: data.metric,
        startTime,
        endTime,
        bucket: data.bucket,
        aggregations: [{ function: data.aggregation }],
      });
    },
    {
      onSuccess: (data) => {
        setAggregateResult(data);
        setQueryResult(null);
        const resultCount = data.results?.length || 0;
        toast({
          title: "Aggregation completed",
          description: `${resultCount} buckets returned`,
          variant: "success",
        });
      },
      onError: (err) => {
        toast({
          title: "Aggregation failed",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Query mutation for fetching raw time-series data points
  const queryMutation = useMutation(
    async (data: QueryFormData) => {
      const startTime = new Date(data.startTime).getTime();
      const endTime = new Date(data.endTime).getTime();
      return client.quicBaaSTimeSeries.query({
        metric: data.metric,
        startTime,
        endTime,
        limit: 1000,
        order: "DESC",
      });
    },
    {
      onSuccess: (data) => {
        setQueryResult(data);
        setAggregateResult(null);
        const pointCount = data.dataPoints?.length || 0;
        toast({
          title: "Query completed",
          description: `${pointCount} data points returned`,
          variant: "success",
        });
      },
      onError: (err) => {
        toast({
          title: "Query failed",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Delete range mutation
  const deleteMutation = useMutation(
    async (params: { metric: string; startTime: number; endTime: number }) => {
      return client.quicBaaSTimeSeries.deleteRange({
        metric: params.metric,
        startTime: params.startTime,
        endTime: params.endTime,
      });
    },
    {
      onSuccess: (data) => {
        const deletedCount = data.deletedCount || 0;
        toast({
          title: "Data deleted",
          description: `${deletedCount} data points deleted`,
          variant: "success",
        });
      },
      onError: (err) => {
        toast({
          title: "Delete failed",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Load sample metrics on mount (state adjusted during render, not in an
  // effect).
  const [loadedSample, setLoadedSample] = React.useState<TimeSeriesMetricUI[] | null>(null);
  if (loadedSample !== sampleMetrics) {
    setLoadedSample(sampleMetrics);
    setMetrics(sampleMetrics);
  }

  const handleQuery = async () => {
    if (!queryData.metric.trim()) {
      toast({
        title: "Validation error",
        description: "Metric name is required",
        variant: "destructive",
      });
      return;
    }
    // Use aggregate mutation if aggregation is selected, otherwise use query
    if (queryData.aggregation && queryData.aggregation !== "UNSPECIFIED") {
      await aggregateMutation.mutateAsync(queryData).catch(() => undefined);
    } else {
      await queryMutation.mutateAsync(queryData).catch(() => undefined);
    }
  };

  const handleDelete = async (metric: TimeSeriesMetricUI) => {
    if (!confirm(`Delete all data for metric "${metric.name}"? This action cannot be undone.`)) {
      return;
    }
    // Delete all data for this metric (0 to now)
    await deleteMutation.mutateAsync({
      metric: metric.name,
      startTime: 0,
      endTime: Date.now(),
    }).catch(() => undefined);
  };

  const handleCreateMetric = async () => {
    toast({
      title: "Coming Soon",
      description: "Metric creation is handled automatically when data is inserted. Use the API to insert time-series data points.",
      variant: "default",
    });
    setIsCreateDialogOpen(false);
  };

  const getMetricTypeIcon = (type: string) => {
    switch (type) {
      case "counter":
        return <Hash className="h-4 w-4" />;
      case "gauge":
        return <Gauge className="h-4 w-4" />;
      case "histogram":
        return <BarChart3 className="h-4 w-4" />;
      case "summary":
        return <LineChart className="h-4 w-4" />;
      default:
        return <Activity className="h-4 w-4" />;
    }
  };

  const getMetricTypeBadge = (type: string) => {
    const variants: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
      counter: "default",
      gauge: "secondary",
      histogram: "outline",
      summary: "destructive",
    };
    return (
      <Badge variant={variants[type] || "default"}>
        {type}
      </Badge>
    );
  };

  const columns: ColumnDef<TimeSeriesMetricUI>[] = [
    createSelectColumn<TimeSeriesMetricUI>(),
    {
      accessorKey: "name",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Metric Name" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          {getMetricTypeIcon(row.original.type)}
          <span className="font-medium">{row.original.name}</span>
        </div>
      ),
    },
    {
      accessorKey: "description",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Description" />
      ),
      cell: ({ row }) => (
        <span className="text-muted-foreground">
          {row.original.description || "-"}
        </span>
      ),
    },
    {
      accessorKey: "type",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Type" />
      ),
      cell: ({ row }) => getMetricTypeBadge(row.original.type),
    },
    {
      accessorKey: "unit",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Unit" />
      ),
      cell: ({ row }) => (
        <code className="text-sm bg-muted px-1 rounded">
          {row.original.unit}
        </code>
      ),
    },
    {
      accessorKey: "retention",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Retention" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-1">
          <Clock className="h-3 w-3 text-muted-foreground" />
          <span>{row.original.retention}</span>
        </div>
      ),
    },
    {
      accessorKey: "labels",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Labels" />
      ),
      cell: ({ row }) => {
        const labels = row.original.labels || {};
        const labelCount = Object.keys(labels).length;
        return (
          <Badge variant="outline">
            {labelCount} {labelCount === 1 ? "label" : "labels"}
          </Badge>
        );
      },
    },
    {
      accessorKey: "createdAt",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Created" />
      ),
      cell: ({ row }) => new Date(row.original.createdAt).toLocaleDateString(),
    },
    {
      id: "actions",
      cell: ({ row }) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem
              onClick={() => {
                setQueryData((prev) => ({ ...prev, metric: row.original.name }));
                setIsQueryDialogOpen(true);
              }}
            >
              <Search className="mr-2 h-4 w-4" />
              Query Data
            </DropdownMenuItem>
            <DropdownMenuItem
              className="text-destructive"
              onClick={() => handleDelete(row.original)}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete Data
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ];

  // Calculate statistics
  const totalMetrics = metrics.length;
  const counterCount = metrics.filter((m) => m.type === "counter").length;
  const gaugeCount = metrics.filter((m) => m.type === "gauge").length;
  const histogramCount = metrics.filter((m) => m.type === "histogram").length;

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Time Series Database</h1>
          <p className="text-muted-foreground">
            Query and analyze time series metrics and data points
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => setMetrics(sampleMetrics)} disabled={false}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
          <Dialog open={isQueryDialogOpen} onOpenChange={setIsQueryDialogOpen}>
            <DialogTrigger asChild>
              <Button variant="outline">
                <Search className="mr-2 h-4 w-4" />
                Query Data
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Query Time Series Data</DialogTitle>
                <DialogDescription>
                  Query data points or compute aggregations for a metric
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 pt-4">
                <div className="space-y-2">
                  <Label htmlFor="queryMetric">Metric Name</Label>
                  <Input
                    id="queryMetric"
                    placeholder="cpu.usage"
                    value={queryData.metric}
                    onChange={(e) =>
                      setQueryData((prev) => ({ ...prev, metric: e.target.value }))
                    }
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="startTime">Start Time</Label>
                    <Input
                      id="startTime"
                      type="datetime-local"
                      value={queryData.startTime}
                      onChange={(e) =>
                        setQueryData((prev) => ({
                          ...prev,
                          startTime: e.target.value,
                        }))
                      }
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="endTime">End Time</Label>
                    <Input
                      id="endTime"
                      type="datetime-local"
                      value={queryData.endTime}
                      onChange={(e) =>
                        setQueryData((prev) => ({
                          ...prev,
                          endTime: e.target.value,
                        }))
                      }
                    />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="aggregation">Aggregation</Label>
                    <Select
                      value={queryData.aggregation}
                      onValueChange={(value) =>
                        setQueryData((prev) => ({
                          ...prev,
                          aggregation: value as AggregationFunction,
                        }))
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="AVG">Average</SelectItem>
                        <SelectItem value="SUM">Sum</SelectItem>
                        <SelectItem value="MIN">Minimum</SelectItem>
                        <SelectItem value="MAX">Maximum</SelectItem>
                        <SelectItem value="COUNT">Count</SelectItem>
                        <SelectItem value="FIRST">First</SelectItem>
                        <SelectItem value="LAST">Last</SelectItem>
                        <SelectItem value="STDDEV">Std Dev</SelectItem>
                        <SelectItem value="VARIANCE">Variance</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="bucket">Time Bucket</Label>
                    <Select
                      value={queryData.bucket}
                      onValueChange={(value) =>
                        setQueryData((prev) => ({
                          ...prev,
                          bucket: value as TimeBucket,
                        }))
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="SECOND">Second</SelectItem>
                        <SelectItem value="MINUTE">Minute</SelectItem>
                        <SelectItem value="HOUR">Hour</SelectItem>
                        <SelectItem value="DAY">Day</SelectItem>
                        <SelectItem value="WEEK">Week</SelectItem>
                        <SelectItem value="MONTH">Month</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <Button
                  onClick={handleQuery}
                  disabled={queryMutation.isLoading || aggregateMutation.isLoading}
                  className="w-full"
                >
                  {(queryMutation.isLoading || aggregateMutation.isLoading) ? "Querying..." : "Run Query"}
                </Button>
                {queryResult && queryResult.dataPoints && (
                  <div className="mt-4 p-4 bg-muted rounded-lg">
                    <h4 className="font-medium mb-2">Query Result</h4>
                    <p className="text-sm text-muted-foreground mb-2">
                      {queryResult.dataPoints.length} data points returned
                    </p>
                    <div className="max-h-48 overflow-y-auto space-y-1">
                      {queryResult.dataPoints.slice(0, 10).map((dp, idx) => (
                        <div key={idx} className="flex justify-between text-sm">
                          <span className="text-muted-foreground">
                            {new Date(dp.timestamp).toLocaleString()}
                          </span>
                          <span className="font-mono">{dp.value.toFixed(2)}</span>
                        </div>
                      ))}
                      {queryResult.dataPoints.length > 10 && (
                        <p className="text-xs text-muted-foreground text-center pt-2">
                          ... and {queryResult.dataPoints.length - 10} more
                        </p>
                      )}
                    </div>
                  </div>
                )}
                {aggregateResult && aggregateResult.results && (
                  <div className="mt-4 p-4 bg-muted rounded-lg">
                    <h4 className="font-medium mb-2">Aggregation Result</h4>
                    <p className="text-sm text-muted-foreground mb-2">
                      {aggregateResult.results.length} buckets, {aggregateResult.executionTimeMs}ms execution time
                    </p>
                    <div className="max-h-48 overflow-y-auto space-y-1">
                      {aggregateResult.results.slice(0, 10).map((bucket, idx) => (
                        <div key={idx} className="flex justify-between text-sm">
                          <span className="text-muted-foreground">
                            {new Date(bucket.bucketStart).toLocaleString()}
                          </span>
                          <span className="font-mono">
                            {Object.entries(bucket.values).map(([key, val]) => (
                              <span key={key}>{val?.toFixed(2) ?? "null"}</span>
                            ))}
                          </span>
                        </div>
                      ))}
                      {aggregateResult.results.length > 10 && (
                        <p className="text-xs text-muted-foreground text-center pt-2">
                          ... and {aggregateResult.results.length - 10} more
                        </p>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </DialogContent>
          </Dialog>
          <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" />
                Create Metric
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Create New Metric</DialogTitle>
                <DialogDescription>
                  Metrics are created automatically when data is inserted
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 pt-4">
                <div className="flex items-start gap-3 p-4 bg-muted rounded-lg">
                  <Info className="h-5 w-5 text-blue-500 mt-0.5" />
                  <div className="space-y-2">
                    <p className="text-sm">
                      The Time Series service creates metrics automatically when you insert data points.
                      Use the SDK or API to insert data:
                    </p>
                    <pre className="text-xs bg-background p-2 rounded overflow-x-auto">
{`client.timeseries.insert({
  metric: 'cpu.usage',
  dataPoints: [
    { timestamp: Date.now(), value: 45.2 }
  ],
  retention: 86400 * 30 // 30 days
});`}
                    </pre>
                  </div>
                </div>
                <Button
                  onClick={handleCreateMetric}
                  className="w-full"
                >
                  Got It
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Info Banner */}
      <div className="flex items-center gap-2 p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg">
        <Info className="h-4 w-4 text-blue-500" />
        <div>
          <p className="text-sm text-blue-700 dark:text-blue-300">
            Sample metrics are shown below. Use the Query Data button to fetch actual data from your time series database.
          </p>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Metrics</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalMetrics}</div>
            <p className="text-xs text-muted-foreground">
              Tracked metrics
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Counters</CardTitle>
            <Hash className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
              {counterCount}
            </div>
            <p className="text-xs text-muted-foreground">
              Monotonic counters
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Gauges</CardTitle>
            <Gauge className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {gaugeCount}
            </div>
            <p className="text-xs text-muted-foreground">
              Current values
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Histograms</CardTitle>
            <BarChart3 className="h-4 w-4 text-purple-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
              {histogramCount}
            </div>
            <p className="text-xs text-muted-foreground">
              Distribution metrics
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Metrics Table */}
      <Card>
        <CardHeader>
          <CardTitle>Metrics</CardTitle>
          <CardDescription>
            Browse and query time series metrics
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={metrics}
            searchKey="name"
            searchPlaceholder="Filter metrics..."
            loading={false}
            emptyState={
              <div className="flex flex-col items-center gap-2 py-8">
                <TrendingUp className="h-12 w-12 text-muted-foreground" />
                <p className="text-muted-foreground">No metrics found</p>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setIsCreateDialogOpen(true)}
                >
                  <Plus className="mr-2 h-4 w-4" />
                  Learn how to create metrics
                </Button>
              </div>
            }
            bulkActions={[
              {
                label: "Delete selected data",
                onClick: async (rows) => {
                  if (
                    confirm(
                      `Delete all data for ${rows.length} selected metrics? This action cannot be undone.`
                    )
                  ) {
                    for (const row of rows) {
                      await deleteMutation.mutateAsync({
                        metric: row.name,
                        startTime: 0,
                        endTime: Date.now(),
                      }).catch(() => undefined);
                    }
                  }
                },
                variant: "destructive",
              },
            ]}
          />
        </CardContent>
      </Card>
    </div>
  );
}
