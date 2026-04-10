"use client";

import * as React from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { EventLogEntry } from "@/types/security";
import { Search } from "lucide-react";

interface EventLogViewerProps {
  eventLog: EventLogEntry[];
}

/**
 * TPM Event Log viewer component
 *
 * Features:
 * - Searchable event log entries
 * - Filter by PCR index or event type
 * - Expandable event data
 * - Timestamp display
 * - Color-coded event types
 */
export function EventLogViewer({ eventLog }: EventLogViewerProps) {
  const [searchTerm, setSearchTerm] = React.useState("");
  const [expandedRows, setExpandedRows] = React.useState<Set<number>>(new Set());

  const toggleRow = (index: number) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(index)) {
        next.delete(index);
      } else {
        next.add(index);
      }
      return next;
    });
  };

  const filteredLog = React.useMemo(() => {
    if (!searchTerm) return eventLog;

    const term = searchTerm.toLowerCase();
    return eventLog.filter(
      (entry) =>
        entry.eventType.toLowerCase().includes(term) ||
        entry.pcrIndex.toString().includes(term) ||
        entry.digest.toLowerCase().includes(term) ||
        entry.data.toLowerCase().includes(term)
    );
  }, [eventLog, searchTerm]);

  if (eventLog.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-muted-foreground">
          No event log entries available
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div>
            <CardTitle>TPM Event Log</CardTitle>
            <CardDescription>
              Detailed log of measurements and events
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search events..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-64"
            />
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-16">PCR</TableHead>
                <TableHead className="w-[200px]">Event Type</TableHead>
                <TableHead>Digest</TableHead>
                <TableHead className="w-[150px]">Timestamp</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredLog.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-center py-8">
                    <p className="text-muted-foreground">No events match your search</p>
                  </TableCell>
                </TableRow>
              ) : (
                filteredLog.map((entry, index) => {
                  const isExpanded = expandedRows.has(index);
                  return (
                    <React.Fragment key={index}>
                      <TableRow
                        className="cursor-pointer hover:bg-accent"
                        onClick={() => toggleRow(index)}
                      >
                        <TableCell>
                          <Badge variant="outline">{entry.pcrIndex}</Badge>
                        </TableCell>
                        <TableCell>
                          <code className="text-xs">{entry.eventType}</code>
                        </TableCell>
                        <TableCell>
                          <code className="text-xs bg-muted px-2 py-1 rounded break-all">
                            {entry.digest.substring(0, 32)}...
                          </code>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {entry.timestamp
                            ? new Date(entry.timestamp).toLocaleString()
                            : "N/A"}
                        </TableCell>
                      </TableRow>
                      {isExpanded && (
                        <TableRow>
                          <TableCell colSpan={4} className="bg-muted/50">
                            <div className="space-y-3 p-4">
                              <div>
                                <div className="text-sm font-medium mb-1">
                                  Full Digest
                                </div>
                                <code className="text-xs bg-background px-2 py-1 rounded block break-all">
                                  {entry.digest}
                                </code>
                              </div>
                              <div>
                                <div className="text-sm font-medium mb-1">
                                  Event Data
                                </div>
                                <pre className="text-xs bg-background p-3 rounded overflow-x-auto border max-h-48">
                                  {entry.data}
                                </pre>
                              </div>
                            </div>
                          </TableCell>
                        </TableRow>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </TableBody>
          </Table>
        </div>

        <div className="mt-4 flex items-center justify-between text-xs text-muted-foreground">
          <p>
            Showing {filteredLog.length} of {eventLog.length} events
          </p>
          <p>Click on a row to view full details</p>
        </div>
      </CardContent>
    </Card>
  );
}
