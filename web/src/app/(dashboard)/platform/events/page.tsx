"use client";

import * as React from "react";
import {
  RefreshCw,
  Play,
  Square,
  Download,
  Bell,
  AlertTriangle,
  Info,
  CheckCircle,
  XCircle,
  Filter,
  Loader2,
  AlertCircle,
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
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useApi, usePlatform, useToast } from "@/hooks";

/**
 * Event severity type
 */
type EventSeverity = "info" | "warning" | "error" | "success";

/**
 * Event category type
 */
type EventCategory =
  | "system"
  | "security"
  | "service"
  | "certificate"
  | "attestation"
  | "user";

/**
 * Platform event interface
 */
interface PlatformEvent {
  id: string;
  timestamp: string;
  severity: EventSeverity;
  category: EventCategory;
  source: string;
  title: string;
  message: string;
  metadata?: Record<string, string>;
}


/**
 * Get severity icon based on event severity
 */
function getSeverityIcon(severity: EventSeverity) {
  const icons: Record<EventSeverity, React.ReactNode> = {
    info: <Info className="h-4 w-4 text-blue-500" />,
    warning: <AlertTriangle className="h-4 w-4 text-yellow-500" />,
    error: <XCircle className="h-4 w-4 text-destructive" />,
    success: <CheckCircle className="h-4 w-4 text-green-500" />,
  };
  return icons[severity];
}

/**
 * Get severity badge variant
 */
function getSeverityBadge(severity: EventSeverity) {
  const variants: Record<EventSeverity, "default" | "secondary" | "destructive" | "outline"> = {
    info: "secondary",
    warning: "outline",
    error: "destructive",
    success: "default",
  };
  return variants[severity];
}

/**
 * Format timestamp for display
 */
function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  return date.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/**
 * Event card component
 */
function EventCard({ event }: { event: PlatformEvent }) {
  return (
    <div className="flex gap-3 p-4 border-b last:border-b-0 hover:bg-muted/50 transition-colors">
      <div className="flex-shrink-0 mt-0.5">
        {getSeverityIcon(event.severity)}
      </div>
      <div className="flex-1 min-w-0 space-y-1">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-sm">{event.title}</span>
            <Badge variant={getSeverityBadge(event.severity)} className="capitalize text-xs">
              {event.severity}
            </Badge>
            <Badge variant="outline" className="text-xs">
              {event.category}
            </Badge>
          </div>
          <span className="text-xs text-muted-foreground whitespace-nowrap">
            {formatTimestamp(event.timestamp)}
          </span>
        </div>
        <p className="text-sm text-muted-foreground">{event.message}</p>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span>Source: {event.source}</span>
          {event.metadata && Object.keys(event.metadata).length > 0 && (
            <>
              <span>|</span>
              {Object.entries(event.metadata).slice(0, 2).map(([key, value]) => (
                <span key={key}>
                  {key}: {value}
                </span>
              ))}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * Platform Events Page
 *
 * Features:
 * - Real-time event stream
 * - Event filtering by severity and category
 * - Event statistics overview
 * - Export events functionality
 * - Live streaming toggle
 *
 * Note: Currently displays service health events from the platform health API.
 * A dedicated events API endpoint should be implemented for full event logging.
 */
export default function EventsPage() {
  const { toast } = useToast();
  const platform = usePlatform();
  const [isStreaming, setIsStreaming] = React.useState(false);
  const [selectedSeverity, setSelectedSeverity] = React.useState<string>("");
  const [selectedCategory, setSelectedCategory] = React.useState<string>("");

  // Fetch platform health data to generate events
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
          title: "Error loading platform events",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Transform health data into events
  const events = React.useMemo(() => {
    if (!healthData?.health?.services) return [];

    const timestamp = healthData.health.timestamp || new Date().toISOString();

    return healthData.health.services.map((service, index) => {
      const severity: EventSeverity = service.healthy ? "success" : "error";
      const category: EventCategory = "service";

      return {
        id: `evt-${service.name}-${index}`,
        timestamp: service.lastCheck || timestamp,
        severity,
        category,
        source: service.name,
        title: service.healthy ? `Service Healthy: ${service.name}` : `Service Unhealthy: ${service.name}`,
        message: service.message || (service.healthy ? `Service ${service.name} is operating normally` : `Service ${service.name} is experiencing issues`),
        metadata: {
          latencyMs: service.latencyMs?.toString() || "N/A",
          lastCheck: service.lastCheck || timestamp,
        },
      } as PlatformEvent;
    });
  }, [healthData]);

  // Calculate statistics
  const stats = React.useMemo(() => {
    return {
      total: events.length,
      info: events.filter((e) => e.severity === "info").length,
      warning: events.filter((e) => e.severity === "warning").length,
      error: events.filter((e) => e.severity === "error").length,
      success: events.filter((e) => e.severity === "success").length,
    };
  }, [events]);

  // Filter events
  const filteredEvents = React.useMemo(() => {
    return events.filter((event) => {
      if (selectedSeverity && event.severity !== selectedSeverity) return false;
      if (selectedCategory && event.category !== selectedCategory) return false;
      return true;
    });
  }, [events, selectedSeverity, selectedCategory]);

  const handleRefresh = () => {
    refetch();
  };

  const toggleStreaming = () => {
    setIsStreaming(!isStreaming);
    toast({
      title: isStreaming ? "Streaming stopped" : "Streaming started",
      description: isStreaming
        ? "Live event stream has been paused"
        : "Now receiving live events",
    });
  };

  const handleExport = () => {
    const json = JSON.stringify(filteredEvents, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `platform-events-${new Date().toISOString().split("T")[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    toast({
      title: "Events exported",
      description: `Exported ${filteredEvents.length} events to JSON file`,
    });
  };

  // Auto-refresh when streaming is enabled
  React.useEffect(() => {
    if (!isStreaming) return;

    const interval = setInterval(() => {
      refetch();
    }, 5000); // Refresh every 5 seconds

    return () => clearInterval(interval);
  }, [isStreaming, refetch]);

  // Show error state
  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Platform Events"
          description="Monitor real-time platform events and notifications"
        />
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Events</AlertTitle>
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
        title="Platform Events"
        description="Monitor real-time platform events and notifications"
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
            onClick={handleRefresh}
            disabled={isLoading || isStreaming}
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleExport}
            disabled={filteredEvents.length === 0}
          >
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
        </div>
      </PageHeader>

      {/* Statistics Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Events</CardTitle>
            <Bell className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">Events recorded</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Info</CardTitle>
            <Info className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600">{stats.info}</div>
            <p className="text-xs text-muted-foreground">Informational</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Warnings</CardTitle>
            <AlertTriangle className="h-4 w-4 text-yellow-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-600">{stats.warning}</div>
            <p className="text-xs text-muted-foreground">Need attention</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Errors</CardTitle>
            <XCircle className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">{stats.error}</div>
            <p className="text-xs text-muted-foreground">Require action</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Success</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{stats.success}</div>
            <p className="text-xs text-muted-foreground">Completed</p>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-base">Filters</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-4">
            <div className="space-y-2">
              <Label htmlFor="severity">Severity</Label>
              <Select value={selectedSeverity} onValueChange={setSelectedSeverity}>
                <SelectTrigger id="severity" className="w-[150px]">
                  <SelectValue placeholder="All" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="">All</SelectItem>
                  <SelectItem value="info">Info</SelectItem>
                  <SelectItem value="warning">Warning</SelectItem>
                  <SelectItem value="error">Error</SelectItem>
                  <SelectItem value="success">Success</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="category">Category</Label>
              <Select value={selectedCategory} onValueChange={setSelectedCategory}>
                <SelectTrigger id="category" className="w-[150px]">
                  <SelectValue placeholder="All" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="">All</SelectItem>
                  <SelectItem value="system">System</SelectItem>
                  <SelectItem value="security">Security</SelectItem>
                  <SelectItem value="service">Service</SelectItem>
                  <SelectItem value="certificate">Certificate</SelectItem>
                  <SelectItem value="attestation">Attestation</SelectItem>
                  <SelectItem value="user">User</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Streaming Status */}
      {isStreaming && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
          <span>Live streaming enabled - new events will appear automatically</span>
        </div>
      )}

      {/* Events List */}
      <Card>
        <CardHeader>
          <CardTitle>Event Stream</CardTitle>
          <CardDescription>
            {filteredEvents.length} event{filteredEvents.length !== 1 ? "s" : ""} matching filters
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="flex items-center justify-center h-64">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
              <span className="ml-2">Loading events...</span>
            </div>
          ) : filteredEvents.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
              <Bell className="h-12 w-12 mb-4" />
              <p>No events found</p>
              <p className="text-sm">
                {events.length === 0
                  ? "No events available from platform services"
                  : "Try adjusting your filters"}
              </p>
            </div>
          ) : (
            <ScrollArea className="h-[500px]">
              <div className="divide-y">
                {filteredEvents.map((event) => (
                  <EventCard key={event.id} event={event} />
                ))}
              </div>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
