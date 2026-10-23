"use client";

import * as React from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import type { LogEntry as LogEntryType, LogLevel } from "@/types/platform";

interface LogEntryProps {
  entry: LogEntryType;
}

const levelConfig: Record<LogLevel, { className: string }> = {
  DEBUG: {
    className: "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300",
  },
  INFO: {
    className: "bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400",
  },
  WARN: {
    className: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400",
  },
  ERROR: {
    className: "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400",
  },
  FATAL: {
    className: "bg-red-200 text-red-900 dark:bg-red-900/40 dark:text-red-300",
  },
  SECURITY: {
    className: "bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-400",
  },
};

/**
 * Expandable log entry row
 * Shows log details with expandable metadata and stack trace
 *
 * @example
 * ```tsx
 * <LogEntry
 *   entry={{
 *     id: "1",
 *     timestamp: "2025-01-19T10:00:00Z",
 *     level: "ERROR",
 *     service: "api-server",
 *     message: "Failed to connect to database",
 *     metadata: { attempt: 3, timeout: 5000 },
 *     stackTrace: "Error: Connection timeout\n  at ..."
 *   }}
 * />
 * ```
 */
export function LogEntry({ entry }: LogEntryProps) {
  const [isOpen, setIsOpen] = React.useState(false);
  const hasDetails = entry.metadata || entry.stackTrace;
  const levelClass = (levelConfig[entry.level] ?? levelConfig.INFO).className;

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <div className="border-b last:border-b-0 hover:bg-muted/50 transition-colors">
        <div className="flex items-center gap-4 p-4">
          {hasDetails && (
            <CollapsibleTrigger asChild>
              <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
                {isOpen ? (
                  <ChevronDown className="h-4 w-4" />
                ) : (
                  <ChevronRight className="h-4 w-4" />
                )}
                <span className="sr-only">Toggle details</span>
              </Button>
            </CollapsibleTrigger>
          )}
          {!hasDetails && <div className="w-6" />}

          <div className="flex-1 grid grid-cols-[140px_80px_120px_1fr] gap-4 items-start">
            <span className="text-sm text-muted-foreground font-mono">
              {new Date(entry.timestamp).toLocaleString()}
            </span>
            <Badge className={levelClass} variant="secondary">
              {entry.level}
            </Badge>
            <span className="text-sm font-medium">{entry.service}</span>
            <p className="text-sm break-words">{entry.message}</p>
          </div>
        </div>

        {hasDetails && (
          <CollapsibleContent>
            <div className="px-4 pb-4 ml-10 space-y-3">
              {entry.metadata && (
                <div className="rounded-md bg-muted p-3">
                  <p className="text-xs font-semibold mb-2 text-muted-foreground">
                    Metadata
                  </p>
                  <pre className="text-xs font-mono overflow-x-auto">
                    {JSON.stringify(entry.metadata, null, 2)}
                  </pre>
                </div>
              )}
              {entry.stackTrace && (
                <div className="rounded-md bg-destructive/10 p-3">
                  <p className="text-xs font-semibold mb-2 text-destructive">
                    Stack Trace
                  </p>
                  <pre className="text-xs font-mono overflow-x-auto text-destructive">
                    {entry.stackTrace}
                  </pre>
                </div>
              )}
            </div>
          </CollapsibleContent>
        )}
      </div>
    </Collapsible>
  );
}
