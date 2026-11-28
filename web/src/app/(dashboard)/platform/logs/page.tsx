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
import { useToast } from "@/hooks/use-toast";
import { LOG_LEVELS, toLogLevel } from "@/lib/log-level";
import type { LogEntry, LogLevel } from "@/types/platform";

interface WireEntry {
  time: string;
  level: string;
  msg: string;
  service: string;
  source?: string;
  attrs?: Record<string, unknown>;
}

/**
 * Platform Logs viewer.
 *
 * Reads from /api/v1/platform/logs — the JSON-lines structured log
 * store written by pkg/log/jsonfile during daemon boot. The store
 * captures every record from platformd's slog handler (CA issuance,
 * device enrollment, ACME flows, SDN reconciles, etc.) plus anything
 * the webserver emits via slog.Default.
 *
 * Streaming uses GET /api/v1/platform/logs/stream as SSE; each event
 * is the raw JSON-line written to disk so clients can choose their
 * own rendering without re-parsing.
 *
 * Replaces the "Coming Soon" stub that lied about the logs service
 * being in development.
 */
export default function LogsPage() {
  const { toast } = useToast();
  const [logs, setLogs] = React.useState<LogEntry[]>([]);
  const [services, setServices] = React.useState<string[]>([]);
  const [isLoading, setIsLoading] = React.useState(false);
  const [isStreaming, setIsStreaming] = React.useState(false);
  const [selectedLevel, setSelectedLevel] = React.useState<LogLevel | "all">(
    "all",
  );
  const [selectedService, setSelectedService] = React.useState<string>("all");
  const [searchQuery, setSearchQuery] = React.useState("");
  const [timeRange, setTimeRange] = React.useState<string>("1h");
  const eventSourceRef = React.useRef<EventSource | null>(null);

  const fetchOpts: RequestInit = React.useMemo(
    () => ({
      credentials: "include",
      headers: { Accept: "application/json" },
    }),
    [],
  );

  const computeSince = React.useCallback((): string | undefined => {
    if (timeRange === "all") return undefined;
    const now = new Date();
    const start = new Date(now);
    switch (timeRange) {
      case "5m":
        start.setMinutes(now.getMinutes() - 5);
        break;
      case "15m":
        start.setMinutes(now.getMinutes() - 15);
        break;
      case "1h":
        start.setHours(now.getHours() - 1);
        break;
      case "6h":
        start.setHours(now.getHours() - 6);
        break;
      case "24h":
        start.setHours(now.getHours() - 24);
        break;
      default:
        return undefined;
    }
    return start.toISOString();
  }, [timeRange]);

  const buildQuery = React.useCallback(() => {
    const params = new URLSearchParams();
    if (selectedLevel !== "all") params.set("level", selectedLevel);
    if (selectedService !== "all") params.append("service", selectedService);
    if (searchQuery) params.set("grep", searchQuery);
    const since = computeSince();
    if (since) params.set("since", since);
    params.set("limit", "200");
    return params.toString();
  }, [selectedLevel, selectedService, searchQuery, computeSince]);

  const fetchServices = React.useCallback(async () => {
    try {
      const res = await fetch("/api/v1/platform/logs/services", fetchOpts);
      if (!res.ok) return;
      const body = await res.json();
      const list: string[] =
        body.payload?.services ?? body.services ?? [];
      setServices(list);
    } catch {
      // services list is best-effort; failure is non-fatal
    }
  }, [fetchOpts]);

  const fetchLogs = React.useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await fetch(
        `/api/v1/platform/logs?${buildQuery()}`,
        fetchOpts,
      );
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      }
      const body = await res.json();
      const entries: WireEntry[] =
        body.payload?.entries ?? body.entries ?? [];
      setLogs(entries.map(toEntry));
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      toast({
        title: "Failed to load logs",
        description: msg,
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  }, [buildQuery, fetchOpts, toast]);

  const startStreaming = React.useCallback(() => {
    const url = `/api/v1/platform/logs/stream?${buildQuery()}`;
    const es = new EventSource(url, { withCredentials: true });
    es.onmessage = (e) => {
      try {
        const wire = JSON.parse(e.data) as WireEntry;
        setLogs((prev) => {
          const next = [toEntry(wire), ...prev];
          // bound the in-memory buffer; the WebUI never needs more
          // than a few hundred lines on screen
          return next.length > 500 ? next.slice(0, 500) : next;
        });
      } catch {
        // ignore malformed lines
      }
    };
    es.onerror = () => {
      // EventSource auto-reconnects; we just surface state
    };
    eventSourceRef.current = es;
    setIsStreaming(true);
  }, [buildQuery]);

  const stopStreaming = React.useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setIsStreaming(false);
  }, []);

  const toggleStreaming = () => {
    if (isStreaming) stopStreaming();
    else startStreaming();
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
      description: "Logs downloaded as JSON.",
    });
  };

  React.useEffect(() => {
    void fetchServices();
  }, [fetchServices]);

  React.useEffect(() => {
    void fetchLogs();
  }, [fetchLogs]);

  React.useEffect(() => {
    return () => {
      if (eventSourceRef.current) eventSourceRef.current.close();
    };
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader title="Logs" description="Structured platform logs">
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
            <RefreshCw
              className={`h-4 w-4 mr-2 ${isLoading ? "animate-spin" : ""}`}
            />
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

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <div className="space-y-2">
          <Label>Min Level</Label>
          <div className="flex flex-wrap gap-2">
            <Badge
              variant={selectedLevel === "all" ? "default" : "outline"}
              className="cursor-pointer"
              onClick={() => setSelectedLevel("all")}
            >
              ALL
            </Badge>
            {LOG_LEVELS.map((level) => (
              <Badge
                key={level}
                variant={selectedLevel === level ? "default" : "outline"}
                className="cursor-pointer"
                onClick={() => setSelectedLevel(level)}
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
              <SelectItem value="all">All services</SelectItem>
              {services.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
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
              placeholder="Substring filter on message…"
              className="pl-8"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>
      </div>

      {isStreaming && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
          <span>Live streaming enabled</span>
        </div>
      )}

      <LogViewer
        logs={logs}
        maxHeight="600px"
        emptyMessage={
          isLoading
            ? "Loading logs…"
            : "No log entries match the current filters."
        }
      />
    </div>
  );
}

// toEntry adapts the on-disk JSON-line shape to the LogViewer's
// LogEntry contract. Fields not present on the wire fall back to
// stable defaults so the renderer never has to nil-guard. The id
// is synthesized from time+message since the JSON-lines store has
// no separate identifier (entries are append-only).
let __entrySeq = 0;
function toEntry(w: WireEntry): LogEntry {
  __entrySeq = (__entrySeq + 1) & 0x7fffffff;
  return {
    id: `${w.time}-${__entrySeq}`,
    timestamp: w.time,
    level: toLogLevel(w.level),
    service: w.service ?? "platformd",
    message: w.msg ?? "",
    metadata: w.attrs,
  };
}
