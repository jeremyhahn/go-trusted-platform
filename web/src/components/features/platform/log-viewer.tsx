"use client";

import * as React from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { LogEntry } from "./log-entry";
import type { LogEntry as LogEntryType } from "@/types/platform";

interface LogViewerProps {
  logs: LogEntryType[];
  maxHeight?: string;
  emptyMessage?: string;
}

/**
 * Log viewer component
 * Displays a scrollable list of log entries
 *
 * @example
 * ```tsx
 * <LogViewer
 *   logs={logs}
 *   maxHeight="600px"
 *   emptyMessage="No logs found matching your filters"
 * />
 * ```
 */
export function LogViewer({
  logs,
  maxHeight = "600px",
  emptyMessage = "No logs available",
}: LogViewerProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Log Entries</CardTitle>
        <CardDescription>{logs.length} entries</CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="w-full" style={{ maxHeight }}>
          {logs.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground">
              {emptyMessage}
            </div>
          ) : (
            <div>
              {logs.map((log) => (
                <LogEntry key={log.id} entry={log} />
              ))}
            </div>
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
