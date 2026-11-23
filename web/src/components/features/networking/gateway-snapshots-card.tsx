'use client';

/**
 * GatewaySnapshotsCard — the state snapshots the gateways reported (#2051).
 * It reads ListGatewaySnapshots (`GET /api/v1/gateway/state`) and, on View,
 * GetGatewaySnapshot (`GET /api/v1/gateway/state/{id}`) through
 * `useGatewayMode`, the SDK GatewayService, not a hand-written fetch.
 *
 * The card is read-only; the opened snapshot is shown in the existing
 * GatewaySnapshotDetail. A refusal is shown verbatim.
 */

import { useCallback, useEffect, useState } from 'react';
import { Gated } from '@/components/features/capabilities/gated';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useToast } from '@/hooks/use-toast';
import { useGatewayMode } from '@/hooks/use-gateway-mode';
import type { GatewaySnapshot } from 'trusted-platform-sdk';
import { GatewaySnapshotDetail } from './gateway-snapshot-detail';

export function GatewaySnapshotsCard() {
  const { listSnapshots, getSnapshot } = useGatewayMode();
  const { toast } = useToast();
  const [snapshots, setSnapshots] = useState<GatewaySnapshot[] | null>(null);
  const [open, setOpen] = useState<GatewaySnapshot | null>(null);
  const [busy, setBusy] = useState(false);
  // The list refusal, shown in the card as well as the toast so the
  // real-server spec can tell it from an empty list.
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setBusy(true);
    try {
      const res = await listSnapshots();
      if (res.success) {
        setSnapshots(res.data?.gateways ?? []);
        setError(null);
      } else {
        setError(res.error?.message ?? 'request failed');
        toast({ title: 'Gateway snapshots unavailable', description: res.error?.message, variant: 'destructive' });
      }
    } finally {
      setBusy(false);
    }
  }, [listSnapshots, toast]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const view = async (gatewayId: string) => {
    setBusy(true);
    try {
      const res = await getSnapshot(gatewayId);
      if (res.success && res.data) {
        setOpen(res.data);
      } else {
        toast({ title: 'Snapshot unavailable', description: res.error?.message, variant: 'destructive' });
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="gateway-snapshots-card">
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle>Gateway snapshots</CardTitle>
          <CardDescription>The last state each gateway reported.</CardDescription>
        </div>
        <Gated op="GET /api/v1/gateway/state">
          <Button variant="outline" disabled={busy} onClick={() => void reload()}>
            Refresh
          </Button>
        </Gated>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <p role="alert" data-testid="gateway-snapshots-error" className="text-sm text-destructive">
            {error}
          </p>
        )}
        {snapshots !== null && snapshots.length === 0 ? (
          <p data-testid="gateway-snapshots-empty" className="text-sm text-muted-foreground">
            No gateway has reported state
          </p>
        ) : error && snapshots === null ? null : (
          <Table data-testid="gateway-snapshots-table">
            <TableHeader>
              <TableRow>
                <TableHead>Gateway</TableHead>
                <TableHead>Hostname</TableHead>
                <TableHead>Mode</TableHead>
                <TableHead>Reported at</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {(snapshots ?? []).map((s) => (
                <TableRow key={s.gateway_id} data-testid="gateway-snapshot-row">
                  <TableCell>{s.gateway_id}</TableCell>
                  <TableCell>{s.hostname ?? '-'}</TableCell>
                  <TableCell>{s.mode ?? '-'}</TableCell>
                  <TableCell>{s.reported_at}</TableCell>
                  <TableCell>
                    <Gated op="GET /api/v1/gateway/state/{id}">
                      <Button
                        variant="outline"
                        size="sm"
                        aria-label={`View ${s.gateway_id}`}
                        disabled={busy}
                        onClick={() => void view(s.gateway_id)}
                      >
                        View
                      </Button>
                    </Gated>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        {open && (
          <div className="space-y-2">
            <GatewaySnapshotDetail snapshot={open} />
            <Button variant="ghost" onClick={() => setOpen(null)}>
              Close
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
