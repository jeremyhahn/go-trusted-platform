'use client';

import { useCallback, useEffect, useState } from 'react';
import type { AttestVMResponse, VM, VMMetrics } from 'trusted-platform-sdk';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  canResume,
  canSuspend,
  useVMLifecycle,
  vmStateLabel,
  wireNumber,
} from '@/hooks/use-vm-lifecycle';

/** Wire-level metrics: protojson sends the uint64 fields as decimal strings. */
type WireMetrics = { [K in keyof VMMetrics]?: number | string };

interface Refusal {
  success: boolean;
  error?: { message?: string };
}

function refusalMessage(res: Refusal): string {
  return res.error?.message || 'The server refused the request.';
}

/**
 * The lifecycle of one VM: its recorded state and metrics, Suspend (behind a
 * confirm), Resume and Attest, all through the SDK client.
 */
export function VMLifecycleCard({ vmId }: { vmId: string }) {
  const ops = useVMLifecycle(vmId);
  const [vm, setVM] = useState<VM | undefined>();
  const [metrics, setMetrics] = useState<WireMetrics | undefined>();
  const [metricsError, setMetricsError] = useState<string | undefined>();
  const [error, setError] = useState<string | undefined>();
  const [attestation, setAttestation] = useState<AttestVMResponse | undefined>();
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  const readVM = useCallback(async () => {
    const res = await ops.getVM();
    if (res.success && res.data) {
      setVM(res.data.vm);
    } else {
      setError(refusalMessage(res));
    }
  }, [ops]);

  useEffect(() => {
    let live = true;
    void (async () => {
      const [vmRes, metricsRes] = await Promise.all([ops.getVM(), ops.getMetrics()]);
      if (!live) {
        return;
      }
      if (vmRes.success && vmRes.data) {
        setVM(vmRes.data.vm);
      } else {
        setError(refusalMessage(vmRes));
      }
      if (metricsRes.success && metricsRes.data) {
        setMetrics(metricsRes.data.metrics as WireMetrics);
      } else {
        setMetricsError(refusalMessage(metricsRes));
      }
    })();
    return () => {
      live = false;
    };
  }, [ops]);

  const runStateChange = async (op: () => Promise<Refusal>) => {
    setBusy(true);
    setError(undefined);
    try {
      const res = await op();
      if (res.success) {
        await readVM();
      } else {
        setError(refusalMessage(res));
      }
    } finally {
      setBusy(false);
    }
  };

  const onConfirmSuspend = async () => {
    setConfirmOpen(false);
    await runStateChange(ops.suspend);
  };

  const onResume = () => runStateChange(ops.resume);

  const onAttest = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const res = await ops.attest();
      if (res.success && res.data) {
        setAttestation(res.data);
      } else {
        setError(refusalMessage(res));
      }
    } finally {
      setBusy(false);
    }
  };

  const state = vm?.state;
  const used = wireNumber(metrics?.memoryUsedMb);
  const total = used + wireNumber(metrics?.memoryAvailableMb);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          VM lifecycle
          <Badge variant="outline" data-testid="vm-lifecycle-state">
            {vmStateLabel(state)}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <Alert variant="destructive" data-testid="vm-lifecycle-error">
            <AlertTitle>Request refused</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {metricsError ? (
          <p className="text-sm text-destructive" data-testid="vm-lifecycle-metrics-error">
            {metricsError}
          </p>
        ) : (
          <dl className="grid grid-cols-3 gap-2 text-sm" data-testid="vm-lifecycle-metrics">
            <div>
              <dt className="text-muted-foreground">CPU</dt>
              <dd>{`${wireNumber(metrics?.cpuUsagePercent).toFixed(1)}%`}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Memory</dt>
              <dd>{`${used} / ${total} MB`}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Uptime</dt>
              <dd>{`${Math.floor(wireNumber(metrics?.uptimeSeconds) / 60)} min`}</dd>
            </div>
          </dl>
        )}

        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            data-testid="vm-suspend"
            disabled={busy || !canSuspend(state)}
            onClick={() => setConfirmOpen(true)}
          >
            Suspend
          </Button>
          <Button
            variant="outline"
            data-testid="vm-resume"
            disabled={busy || !canResume(state)}
            onClick={() => void onResume()}
          >
            Resume
          </Button>
          <Button variant="outline" data-testid="vm-attest" disabled={busy} onClick={() => void onAttest()}>
            Attest
          </Button>
        </div>

        {attestation && (
          <p className="text-sm" data-testid="vm-attest-result">
            {`Quote received, ${attestation.pcrValues?.length ?? 0} PCRs, ${attestation.signatureAlgorithm || 'unknown scheme'}`}
          </p>
        )}
      </CardContent>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent data-testid="vm-suspend-dialog">
          <DialogHeader>
            <DialogTitle>Suspend this VM?</DialogTitle>
            <DialogDescription>The VM stops running and keeps its memory until it is resumed.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button data-testid="vm-suspend-confirm" onClick={() => void onConfirmSuspend()}>
              Suspend
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
