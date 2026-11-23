'use client';

/**
 * GatewayPerfFlowsCard — the gateway's flow-programming benchmark
 * (GatewayService.GetPerfFlows, POST /api/v1/gateway/perf/flows, #2052).
 *
 * The run installs temporary drop flows in OpenFlow table 250 and times the
 * install; the server deletes them when the run ends, also when it fails.
 * Per the Tenant Agent ruling it is one admin-only action behind a confirm
 * dialog that says what it installs and when the flows expire. A non-admin
 * sees it disabled with the reason; a refused run shows the server's message
 * and can be run again. The Run and confirm buttons are also gated on the
 * server's capability for POST /api/v1/gateway/perf/flows.
 */

import { useState } from 'react';
import { Gauge } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
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
import { useGateway, useOptionalAuth } from '@/hooks';
import type { GetPerfFlowsResponse } from 'trusted-platform-sdk';
import { Gated } from '@/components/features/capabilities/gated';

/** The server's capability op for a benchmark run. */
const FLOWS_OP = 'POST /api/v1/gateway/perf/flows';

/** Flows one run installs. */
export const PERF_FLOW_COUNT = 1000;
/** The OpenFlow table the benchmark writes; no pipeline table resubmits to it. */
export const PERF_FLOW_TABLE = 250;
/** OVS removes each benchmark flow this long after install (the server's FlowHardTimeout). */
export const PERF_FLOW_HARD_TIMEOUT_SECONDS = 60;

const EXPIRY_TEXT = `The switch expires any left behind within ${PERF_FLOW_HARD_TIMEOUT_SECONDS} seconds.`;

const CONFIRM_TEXT =
  `This installs ${PERF_FLOW_COUNT} temporary drop flows in OpenFlow table ${PERF_FLOW_TABLE} ` +
  `on the gateway's default bridge and times the install. The server deletes them when the run ends, ` +
  `also when it fails, and the switch expires any left behind within ${PERF_FLOW_HARD_TIMEOUT_SECONDS} ` +
  `seconds. Table ${PERF_FLOW_TABLE} carries no production traffic.`;

export function GatewayPerfFlowsCard() {
  const gateway = useGateway();
  const auth = useOptionalAuth();
  const isAdmin = auth?.user?.roles.includes('admin') ?? false;
  const [dialogOpen, setDialogOpen] = useState(false);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<GetPerfFlowsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleConfirm = async () => {
    setDialogOpen(false);
    setRunning(true);
    setError(null);
    setResult(null);
    try {
      const res = await gateway.getPerfFlows({ count: PERF_FLOW_COUNT, batch: true });
      if (res.error) {
        setError(res.error.message || 'The gateway did not run the benchmark');
      } else if (res.data) {
        setResult(res.data);
      } else {
        setError('The gateway returned no result');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRunning(false);
    }
  };

  return (
    <Card data-testid="perf-flows-card">
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Gauge className="h-5 w-5" />
            Flow-programming benchmark
          </CardTitle>
          <CardDescription>Measures how fast this gateway&apos;s switch installs flows.</CardDescription>
        </div>
        <Gated op={FLOWS_OP}>
          <Button
            variant="outline"
            size="sm"
            data-testid="perf-flows-run"
            disabled={!isAdmin || running}
            onClick={() => setDialogOpen(true)}
          >
            {running ? 'Running…' : 'Run flow benchmark'}
          </Button>
        </Gated>
      </CardHeader>
      <CardContent className="space-y-3">
        {!isAdmin && (
          <p className="text-sm text-muted-foreground" data-testid="perf-flows-admin-only">
            Requires the admin role: the benchmark installs switch flows.
          </p>
        )}
        {error !== null && (
          <Alert variant="destructive">
            <AlertTitle>Benchmark not run</AlertTitle>
            <AlertDescription data-testid="perf-flows-error" className="whitespace-pre-wrap break-words">
              {error}
              {"\n"}
              {EXPIRY_TEXT}
            </AlertDescription>
          </Alert>
        )}
        {result && (
          <dl className="grid grid-cols-2 gap-2 text-sm md:grid-cols-5" data-testid="perf-flows-result">
            <div>
              <dt className="text-muted-foreground">Installed</dt>
              <dd className="font-bold">{result.installed}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Flows/s</dt>
              <dd className="font-bold">{Math.round(result.flowsPerSecond)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Duration</dt>
              <dd className="font-bold">{(Number(result.durationNs) / 1e6).toFixed(1)} ms</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Bridge</dt>
              <dd className="font-mono">{result.bridge}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Batched</dt>
              <dd>{result.batched ? 'yes' : 'no'}</dd>
            </div>
          </dl>
        )}
      </CardContent>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="sm:max-w-[560px]" data-testid="perf-flows-dialog">
          <DialogHeader>
            <DialogTitle>Install temporary switch flows?</DialogTitle>
            <DialogDescription>{CONFIRM_TEXT}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" data-testid="perf-flows-cancel" onClick={() => setDialogOpen(false)}>
              Cancel
            </Button>
            <Gated op={FLOWS_OP}>
              <Button data-testid="perf-flows-confirm" onClick={handleConfirm}>
                Install and measure
              </Button>
            </Gated>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
