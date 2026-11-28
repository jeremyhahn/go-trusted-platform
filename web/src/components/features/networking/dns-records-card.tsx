'use client';

/**
 * DNSRecordsCard lists one zone's records through useDNSRecords, which calls
 * the SDK DNSService ListRecords (GET /dns/zones/{zone}/records). The card is
 * read-only. A refusal from the control plane is shown verbatim as a
 * destructive toast.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import type { RecordType } from 'trusted-platform-sdk';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useToast } from '@/hooks/use-toast';
import { recordRow, useDNSRecords, type DNSRecordRow } from '@/hooks/use-dns-records';

/** The record types the filter offers; '' (All types) sends no filter. */
const RECORD_TYPE_FILTERS = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV', 'CAA'] as const;

export interface DNSRecordsCardProps {
  zoneName: string;
}

export function DNSRecordsCard({ zoneName }: DNSRecordsCardProps) {
  const ops = useDNSRecords();
  const { toast } = useToast();
  const [rows, setRows] = useState<DNSRecordRow[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [type, setType] = useState('');

  const reload = useCallback(async () => {
    setBusy(true);
    try {
      const res = await ops.listRecords(zoneName, type ? (type as RecordType) : undefined);
      if (res.success && res.data) {
        setRows((res.data.records ?? []).map(recordRow));
      } else {
        toast({
          title: 'Records unavailable',
          description: res.error?.message ?? 'An error occurred',
          variant: 'destructive',
        });
      }
    } finally {
      setBusy(false);
    }
  }, [ops, zoneName, type, toast]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const counts = useMemo(() => {
    const byType = new Map<string, number>();
    for (const row of rows ?? []) byType.set(row.type, (byType.get(row.type) ?? 0) + 1);
    return Array.from(byType.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([t, n]) => `${t} ${n}`)
      .join(' · ');
  }, [rows]);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Records — {zoneName}</CardTitle>
        <CardDescription>The records the control plane holds for this zone.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-2">
          <select
            aria-label="Record type"
            className="h-9 rounded-md border border-input bg-background px-2 text-sm"
            value={type}
            onChange={(e) => setType(e.target.value)}
          >
            <option value="">All types</option>
            {RECORD_TYPE_FILTERS.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <span className="text-sm text-muted-foreground" data-testid="dns-record-counts">
            {counts}
          </span>
          <Button variant="outline" disabled={busy} onClick={() => void reload()}>
            Refresh
          </Button>
        </div>
        {rows !== null && rows.length === 0 ? (
          <p className="text-sm text-muted-foreground">No records in {zoneName}</p>
        ) : null}
        {rows !== null && rows.length > 0 ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Type</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Value</TableHead>
                <TableHead>TTL</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((row, i) => (
                <TableRow key={`${row.type}-${row.name}-${row.value}-${i}`} data-testid="dns-record-row">
                  <TableCell>{row.type}</TableCell>
                  <TableCell>{row.name}</TableCell>
                  <TableCell>{row.value}</TableCell>
                  <TableCell>{row.ttl}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : null}
      </CardContent>
    </Card>
  );
}
