'use client';

/**
 * Container detail page (#1721): GetContainer, GetContainerMetrics,
 * ExecContainer and AttestContainer. Exec and attest run only after a
 * confirm dialog.
 */

import { useState } from 'react';
import { useParams, usePathname, useRouter } from 'next/navigation';
import { ArrowLeft, RefreshCw, ShieldCheck, Terminal } from 'lucide-react';
import { resolveDynamicId } from '@/utils/dynamic-route';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  useContainerOps,
  useToast,
  decodeOutput,
  splitCommand,
} from '@/hooks';
import type { AttestContainerResponse, ExecContainerResponse } from 'trusted-platform-sdk';
import { containerStatus } from '@/lib/compute-state';

type PendingAction = 'exec' | 'attest' | null;

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium text-right break-all">{children}</span>
    </div>
  );
}

export default function ContainerDetailPage() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const containerId = resolveDynamicId(params, pathname, 'containers');
  const { toast } = useToast();
  const { container, metrics, loading, error, refresh, refreshMetrics, exec, attest } =
    useContainerOps(containerId);

  const [command, setCommand] = useState('');
  const [pending, setPending] = useState<PendingAction>(null);
  const [busy, setBusy] = useState(false);
  const [execResult, setExecResult] = useState<ExecContainerResponse | null>(null);
  const [attestResult, setAttestResult] = useState<AttestContainerResponse | null>(null);

  const runPending = async () => {
    const action = pending;
    setPending(null);
    if (!action) return;
    setBusy(true);
    try {
      if (action === 'exec') {
        setExecResult(await exec(splitCommand(command)));
      } else {
        setAttestResult(await attest());
      }
    } catch (err) {
      toast({
        title: 'Error',
        description: `${action === 'exec' ? 'Exec' : 'Attestation'} failed: ${
          err instanceof Error ? err.message : String(err)
        }`,
        variant: 'destructive',
      });
    } finally {
      setBusy(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!container) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" onClick={() => router.push('/compute/containers')}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to containers
        </Button>
        <p className="text-destructive" role="alert">
          Failed to load container: {error ?? 'not found'}
        </p>
      </div>
    );
  }

  const name = container.config?.name || container.id;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button
            variant="ghost"
            size="icon"
            aria-label="Back to containers"
            onClick={() => router.push('/compute/containers')}
          >
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold">{name}</h1>
            <p className="text-muted-foreground mt-1">Container Details</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => {
              void refresh();
              void refreshMetrics();
            }}
          >
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
          <Button variant="outline" disabled={busy} onClick={() => setPending('attest')}>
            <ShieldCheck className="mr-2 h-4 w-4" />
            Attest
          </Button>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Container Information</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Row label="Status">
              <Badge variant="outline">{containerStatus(container.state)}</Badge>
            </Row>
            <Row label="ID">
              <span className="font-mono text-sm">{container.id}</span>
            </Row>
            <Row label="Image">{container.config?.image ?? '-'}</Row>
            <Row label="Host">{container.hostId || '-'}</Row>
            <Row label="Created">{container.createdAt || '-'}</Row>
          </CardContent>
        </Card>

        <Card data-testid="container-metrics">
          <CardHeader>
            <CardTitle>Metrics</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {metrics ? (
              <>
                <Row label="CPU">{metrics.cpuUsagePercent.toFixed(1)}%</Row>
                <Row label="Memory">
                  {metrics.memoryUsedMb} / {metrics.memoryLimitMb} MB
                </Row>
                <Row label="Network RX">{metrics.networkRxBytes} B</Row>
                <Row label="Network TX">{metrics.networkTxBytes} B</Row>
                <Row label="Uptime">{metrics.uptimeSeconds} s</Row>
              </>
            ) : (
              <p className="text-muted-foreground">No metrics available</p>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Exec</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <form
            className="flex items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (splitCommand(command).length > 0) setPending('exec');
            }}
          >
            <div className="flex-1 space-y-2">
              <Label htmlFor="exec-command">Command</Label>
              <Input
                id="exec-command"
                value={command}
                placeholder="ls -la /"
                onChange={(e) => setCommand(e.target.value)}
              />
            </div>
            <Button type="submit" disabled={busy || splitCommand(command).length === 0}>
              <Terminal className="mr-2 h-4 w-4" />
              Run
            </Button>
          </form>
          {execResult && (
            <div data-testid="exec-result" className="space-y-2">
              <p>Exit code: {execResult.exitCode ?? 0}</p>
              <pre className="rounded bg-muted p-3 text-sm whitespace-pre-wrap">
                {decodeOutput(execResult.stdout)}
              </pre>
              {execResult.stderr && (
                <pre className="rounded bg-muted p-3 text-sm text-destructive whitespace-pre-wrap">
                  {decodeOutput(execResult.stderr)}
                </pre>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {attestResult && (
        <Card data-testid="attest-result">
          <CardHeader>
            <CardTitle>Attestation</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Row label="Verified">{attestResult.verified ? 'Verified' : 'Not verified'}</Row>
            <Row label="Image digest">
              <span className="font-mono text-xs">{attestResult.imageDigest || '-'}</span>
            </Row>
            <Row label="Config digest">
              <span className="font-mono text-xs">{attestResult.configDigest || '-'}</span>
            </Row>
            <Row label="PCR values">{attestResult.pcrValues?.length ?? 0}</Row>
          </CardContent>
        </Card>
      )}

      <Dialog open={pending !== null} onOpenChange={(open) => !open && setPending(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {pending === 'exec' ? 'Run command in container?' : 'Attest container?'}
            </DialogTitle>
            <DialogDescription>
              {pending === 'exec'
                ? `This runs "${command.trim()}" inside ${name}.`
                : `This asks the host TPM for a quote over ${name}.`}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPending(null)}>
              Cancel
            </Button>
            <Button onClick={() => void runPending()}>Confirm</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
