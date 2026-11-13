'use client';

/**
 * NTP Page
 *
 * Shows the node's clock synchronisation status and its time sources, and
 * steps the clock behind a confirmation (docs/ntp/api.md: GetStatus,
 * ListSources, Step).
 */

import { useState } from 'react';
import { Clock, Loader2, RefreshCw } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { useApi, useNTP, useToast } from '@/hooks';
import type { NTPStatus } from '@/hooks';

/** `lastSyncUnix` is seconds since the epoch; 0 means never. */
function formatLastSync(value: number | string | undefined): string {
  const seconds = Number(value ?? 0);
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return 'Never';
  }
  return new Date(seconds * 1000).toISOString();
}

function formatOffset(seconds: number | undefined): string {
  return `${((seconds ?? 0) * 1000).toFixed(3)} ms`;
}

export default function NTPPage() {
  const { toast } = useToast();
  const ntp = useNTP();
  const [stepOpen, setStepOpen] = useState(false);
  const [stepping, setStepping] = useState(false);
  const [steppedStatus, setSteppedStatus] = useState<NTPStatus | null>(null);
  // The last status read failure, kept until a status read or a Step succeeds.
  // useApi clears its own error as each request starts, so it cannot carry this.
  const [staleError, setStaleError] = useState<{ message: string } | null>(null);

  const {
    data: statusData,
    isLoading: statusLoading,
    isFetching: statusFetching,
    refetch: fetchStatus,
  } = useApi(() => ntp.getStatus(), [], {
    onSuccess: () => {
      setStaleError(null);
    },
    onError: (err) => {
      setStaleError({ message: err.message });
      toast({
        title: 'Error',
        description: `Failed to fetch NTP status: ${err.message}`,
        variant: 'destructive',
      });
    },
  });

  const {
    data: sourcesData,
    error: sourcesError,
    isLoading: sourcesLoading,
    isFetching: sourcesFetching,
    refetch: fetchSources,
  } = useApi(() => ntp.listSources(), [], {
    onError: (err) => {
      toast({
        title: 'Error',
        description: `Failed to fetch NTP sources: ${err.message}`,
        variant: 'destructive',
      });
    },
  });

  const status = steppedStatus ?? statusData?.status;
  // useApi keeps the last good data when a refresh fails: mark that cached
  // status stale from the failure until a status read or a Step succeeds, so a
  // failed clock service never reads as synchronised, even while a retry is
  // pending.
  const statusStale = Boolean(staleError && status);
  const sources = sourcesData?.sources ?? [];
  // useApi applies responses in completion order, so a refresh never starts
  // while a read is in flight: an older response cannot overwrite a newer one.
  const loading = statusLoading || sourcesLoading || statusFetching || sourcesFetching;

  const refresh = () => {
    if (loading) return;
    setSteppedStatus(null);
    void fetchStatus();
    void fetchSources();
  };

  const handleStep = async () => {
    setStepping(true);
    try {
      const res = await ntp.step();
      if (!res.success) {
        throw new Error(res.error?.message ?? 'step failed');
      }
      if (res.data?.status) {
        setSteppedStatus(res.data.status);
        setStaleError(null);
      }
      toast({ title: 'Clock stepped', description: 'The clock was stepped to the selected source.' });
      setStepOpen(false);
    } catch (err) {
      toast({
        title: 'Error',
        description: `Failed to step the clock: ${err instanceof Error ? err.message : String(err)}`,
        variant: 'destructive',
      });
    } finally {
      setStepping(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">NTP</h1>
          <p className="text-muted-foreground mt-1">Clock synchronisation status and time sources</p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="icon"
            aria-label="Refresh"
            onClick={refresh}
            disabled={loading}
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
          <Button onClick={() => setStepOpen(true)}>
            <Clock className="mr-2 h-4 w-4" />
            Step Clock
          </Button>
        </div>
      </div>

      <Dialog open={stepOpen} onOpenChange={setStepOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Step the clock?</DialogTitle>
            <DialogDescription>
              The node&apos;s clock jumps to the selected source at once instead of slewing.
              Running workloads can see time move backwards.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setStepOpen(false)} disabled={stepping}>
              Cancel
            </Button>
            <Button onClick={handleStep} disabled={stepping}>
              {stepping && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Confirm Step
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Card data-testid="ntp-status-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            Status
            {status && (
              <Badge variant={status.synced ? 'default' : 'destructive'}>
                {status.synced ? 'Synced' : 'Not synced'}
              </Badge>
            )}
            {statusStale && (
              <Badge variant="destructive" data-testid="ntp-status-stale">
                Stale
              </Badge>
            )}
            {status?.anomaly && <Badge variant="destructive">Anomaly</Badge>}
          </CardTitle>
          <CardDescription>{status?.anomalyReason || 'Reported by chronyd on this node'}</CardDescription>
        </CardHeader>
        <CardContent>
          {statusStale && staleError && (
            <p className="mb-4 text-sm text-destructive">
              Status refresh failed: {staleError.message}. The values shown are from the last successful read.
            </p>
          )}
          {status ? (
            <dl className="grid grid-cols-2 gap-4 md:grid-cols-4">
              <div>
                <dt className="text-sm text-muted-foreground">Stratum</dt>
                <dd className="text-lg font-medium">{status.stratum}</dd>
              </div>
              <div>
                <dt className="text-sm text-muted-foreground">Offset</dt>
                <dd className="text-lg font-medium">{formatOffset(status.offsetSeconds)}</dd>
              </div>
              <div>
                <dt className="text-sm text-muted-foreground">Reference</dt>
                <dd className="text-lg font-medium">{status.referenceName || status.referenceId || '—'}</dd>
              </div>
              <div>
                <dt className="text-sm text-muted-foreground">Sources reachable</dt>
                <dd className="text-lg font-medium">
                  {status.sourcesReachable} / {status.sourcesTotal}
                </dd>
              </div>
              <div>
                <dt className="text-sm text-muted-foreground">Leap status</dt>
                <dd className="text-lg font-medium">{status.leapStatus || '—'}</dd>
              </div>
              <div>
                <dt className="text-sm text-muted-foreground">Mode</dt>
                <dd className="text-lg font-medium">{status.mode || '—'}</dd>
              </div>
              <div className="col-span-2">
                <dt className="text-sm text-muted-foreground">Last sync</dt>
                <dd className="text-lg font-medium">{formatLastSync(status.lastSyncUnix)}</dd>
              </div>
            </dl>
          ) : (
            <p className="text-muted-foreground">{statusLoading ? 'Loading…' : 'No status available'}</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Sources</CardTitle>
          <CardDescription>Configured time sources</CardDescription>
        </CardHeader>
        <CardContent>
          <Table data-testid="ntp-sources-table">
            <TableHeader>
              <TableRow>
                <TableHead>Address</TableHead>
                <TableHead>Mode</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Stratum</TableHead>
                <TableHead>Poll (s)</TableHead>
                <TableHead>Reach</TableHead>
                <TableHead>Offset</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sourcesError && !sourcesLoading ? (
                <TableRow data-testid="ntp-sources-error">
                  <TableCell colSpan={7} className="text-center text-destructive">
                    Failed to load NTP sources: {sourcesError.message}
                  </TableCell>
                </TableRow>
              ) : sources.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground">
                    {sourcesLoading ? 'Loading…' : 'No sources configured'}
                  </TableCell>
                </TableRow>
              ) : (
                sources.map((s) => (
                  <TableRow key={s.address}>
                    <TableCell className="font-mono">{s.address}</TableCell>
                    <TableCell>{s.mode}</TableCell>
                    <TableCell>
                      <Badge variant={s.reachable ? 'secondary' : 'destructive'}>{s.state}</Badge>
                    </TableCell>
                    <TableCell>{s.stratum}</TableCell>
                    <TableCell>{s.pollSeconds}</TableCell>
                    <TableCell>{s.reach.toString(8)}</TableCell>
                    <TableCell>{formatOffset(s.offsetSeconds)}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
