"use client";

import * as React from "react";
import { Search, Download, RefreshCw, Play, Square } from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { LogViewer } from "@/components/features/platform";
// TODO: SDK doesn't have platform logs service yet - legacy API removed
import { useToast } from "@/hooks/use-toast";
import type { LogEntry, LogFilters, LogLevel } from "@/types/platform";

const LOG_LEVELS: LogLevel[] = ["DEBUG", "INFO", "WARN", "ERROR"];

/**
 * Logs Viewer Page
 *
 * Features:
 * - Log level filter (DEBUG, INFO, WARN, ERROR)
 * - Service filter
 * - Search functionality
 * - Time range selection
 * - Real-time log streaming toggle
 * - Export logs
 * - Manual refresh
 */
export default function LogsPage() {
  const { toast } = useToast();
  const [logs, setLogs] = React.useState<LogEntry[]>([]);
  const [isLoading, setIsLoading] = React.useState(false);
  const [isStreaming, setIsStreaming] = React.useState(false);
  const [selectedLevels, setSelectedLevels] = React.useState<LogLevel[]>([]);
  const [selectedService, setSelectedService] = React.useState<string>("");
  const [searchQuery, setSearchQuery] = React.useState("");
  const [timeRange, setTimeRange] = React.useState<string>("1h");
  const eventSourceRef = React.useRef<EventSource | null>(null);

  const buildFilters = React.useCallback((): LogFilters => {
    const filters: LogFilters = {
      limit: 100,
    };

    if (selectedLevels.length > 0) {
      filters.level = selectedLevels;
    }

    if (selectedService) {
      filters.service = selectedService;
    }

    if (searchQuery) {
      filters.search = searchQuery;
    }

    // Calculate time range
    if (timeRange !== "all") {
      const now = new Date();
      const startTime = new Date(now);

      switch (timeRange) {
        case "5m":
          startTime.setMinutes(now.getMinutes() - 5);
          break;
        case "15m":
          startTime.setMinutes(now.getMinutes() - 15);
          break;
        case "1h":
          startTime.setHours(now.getHours() - 1);
          break;
        case "6h":
          startTime.setHours(now.getHours() - 6);
          break;
        case "24h":
          startTime.setHours(now.getHours() - 24);
          break;
      }

      filters.startTime = startTime.toISOString();
      filters.endTime = now.toISOString();
    }

    return filters;
  }, [selectedLevels, selectedService, searchQuery, timeRange]);

  const fetchLogs = React.useCallback(async () => {
    // TODO: SDK doesn't have platform logs service yet
    // Using empty array until SDK implementation is available
    setIsLoading(true);
    setLogs([]);
    setIsLoading(false);
  }, [buildFilters, toast]);

  const startStreaming = React.useCallback(() => {
    // TODO: SDK doesn't have platform logs service yet
    toast({
      title: "Log streaming not available",
      description: "Platform logs service is currently in development",
      variant: "destructive",
    });
  }, [buildFilters, toast]);

  const stopStreaming = React.useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setIsStreaming(false);
  }, []);

  const toggleStreaming = () => {
    if (isStreaming) {
      stopStreaming();
    } else {
      startStreaming();
    }
  };

  const handleExport = () => {
    const json = JSON.stringify(logs, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `logs-${new Date().toISOString().split("T")[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    toast({
      title: "Logs exported",
      description: "Logs have been downloaded as JSON.",
    });
  };

  const toggleLevel = (level: LogLevel) => {
    setSelectedLevels((prev) =>
      prev.includes(level) ? prev.filter((l) => l !== level) : [...prev, level]
    );
  };

  // Initial fetch
  React.useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  // Cleanup on unmount
  React.useEffect(() => {
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Logs"
        description="View and search platform logs"
      >
        <div className="flex gap-2">
          <Button
            variant={isStreaming ? "destructive" : "default"}
            size="sm"
            onClick={toggleStreaming}
          >
            {isStreaming ? (
              <>
                <Square className="h-4 w-4 mr-2" />
                Stop Stream
              </>
            ) : (
              <>
                <Play className="h-4 w-4 mr-2" />
                Start Stream
              </>
            )}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={fetchLogs}
            disabled={isLoading || isStreaming}
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleExport}
            disabled={logs.length === 0}
          >
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
        </div>
      </PageHeader>

      {/* Filters */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <div className="space-y-2">
          <Label>Log Level</Label>
          <div className="flex flex-wrap gap-2">
            {LOG_LEVELS.map((level) => (
              <Badge
                key={level}
                variant={selectedLevels.includes(level) ? "default" : "outline"}
                className="cursor-pointer"
                onClick={() => toggleLevel(level)}
              >
                {level}
              </Badge>
            ))}
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="service">Service</Label>
          <Select value={selectedService} onValueChange={setSelectedService}>
            <SelectTrigger id="service">
              <SelectValue placeholder="All services" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="">All services</SelectItem>
              <SelectItem value="api-server">API Server</SelectItem>
              <SelectItem value="database">Database</SelectItem>
              <SelectItem value="tpm-service">TPM Service</SelectItem>
              <SelectItem value="ca-service">CA Service</SelectItem>
              <SelectItem value="auth-service">Auth Service</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-2">
          <Label htmlFor="timeRange">Time Range</Label>
          <Select value={timeRange} onValueChange={setTimeRange}>
            <SelectTrigger id="timeRange">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="5m">Last 5 minutes</SelectItem>
              <SelectItem value="15m">Last 15 minutes</SelectItem>
              <SelectItem value="1h">Last hour</SelectItem>
              <SelectItem value="6h">Last 6 hours</SelectItem>
              <SelectItem value="24h">Last 24 hours</SelectItem>
              <SelectItem value="all">All time</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-2">
          <Label htmlFor="search">Search</Label>
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              id="search"
              placeholder="Search logs..."
              className="pl-8"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* Status */}
      {isStreaming && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
          <span>Live streaming enabled</span>
        </div>
      )}

      {/* Logs */}
      {logs.length === 0 && !isLoading ? (
        <div className="flex items-center justify-center h-64 border-2 border-dashed rounded-lg">
          <div className="text-center">
            <p className="text-lg font-medium text-muted-foreground mb-2">
              Platform Logs Coming Soon
            </p>
            <p className="text-sm text-muted-foreground">
              SDK support for platform logs is currently in development
            </p>
          </div>
        </div>
      ) : (
        <LogViewer
          logs={logs}
          maxHeight="600px"
          emptyMessage={
            isLoading
              ? "Loading logs..."
              : "No logs found matching your filters"
          }
        />
      )}
    </div>
  );
}
