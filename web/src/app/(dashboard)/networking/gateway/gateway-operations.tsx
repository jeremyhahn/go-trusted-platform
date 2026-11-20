'use client';

/**
 * Gateway operations on the gateway page (#2051): set the gateway mode,
 * look up one gateway snapshot, list and look up admitted VTEPs, and look
 * up or delete one IPAM pool. Every call goes through the SDK gateway
 * service (useGatewayOps). A control whose server answers "not
 * configured" (a node that runs no gatewayd) is disabled with that reason.
 */

import * as React from 'react';
import { Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useGatewayOps } from '@/hooks/use-gateway-ops';
import type { GatewayOpResult } from '@/hooks/use-gateway-ops';
import type { GatewayAdmittedVTEP } from 'trusted-platform-sdk';

const NOT_CONFIGURED =
  'The gateway service is not configured on this node (gatewayd does not run here).';

function failureText(res: GatewayOpResult<unknown>): string {
  if (res.ok) return '';
  return res.notConfigured ? `${NOT_CONFIGURED} ${res.error}` : res.error;
}

export interface GatewayOperationsProps {
  /** Why the mode control is off, or null when it is usable. */
  modeGateReason: string | null;
  /** True while the gateway status is still loading. */
  statusLoading: boolean;
  /** The mode bitmask the server reports now. */
  currentModes?: number;
  /** Called after a mode change so the page reloads the status. */
  onModeChanged?: () => void;
}

export function GatewayOperations({
  modeGateReason,
  statusLoading,
  currentModes,
  onModeChanged,
}: GatewayOperationsProps) {
  const ops = useGatewayOps();

  // Gateway mode
  const [modeInput, setModeInput] = React.useState('');
  const [modeBusy, setModeBusy] = React.useState(false);
  const [modeResult, setModeResult] = React.useState<string | null>(null);
  const modeDisabled = statusLoading || modeGateReason !== null || modeBusy;

  const submitMode = async (e: React.FormEvent) => {
    e.preventDefault();
    const raw = modeInput.trim() === '' ? String(currentModes ?? 0) : modeInput.trim();
    const modes = Number(raw);
    if (!Number.isInteger(modes) || modes < 0) {
      setModeResult('Mode bitmask must be a non-negative integer.');
      return;
    }
    setModeBusy(true);
    const res = await ops.setMode(modes);
    setModeBusy(false);
    if (res.ok) {
      const reported = res.data?.gatewayStatus?.modes ?? modes;
      setModeResult(`Gateway modes set to ${reported}. ${res.data?.status ?? ''}`.trim());
      onModeChanged?.();
    } else {
      setModeResult(`Set mode failed: ${failureText(res)}`);
    }
  };

  // Snapshot lookup
  const [snapshotId, setSnapshotId] = React.useState('');
  const [snapshotBusy, setSnapshotBusy] = React.useState(false);
  const [snapshotText, setSnapshotText] = React.useState<string | null>(null);

  const lookupSnapshot = async (e: React.FormEvent) => {
    e.preventDefault();
    const id = snapshotId.trim();
    if (!id) return;
    setSnapshotBusy(true);
    const res = await ops.getSnapshot(id);
    setSnapshotBusy(false);
    setSnapshotText(
      res.ok
        ? JSON.stringify(res.data, null, 2)
        : `No gateway snapshot for ${id}: ${failureText(res)}`
    );
  };

  // Admitted VTEPs
  const [vteps, setVteps] = React.useState<GatewayAdmittedVTEP[]>([]);
  const [vtepsState, setVtepsState] = React.useState<
    { kind: 'loading' } | { kind: 'ready' } | { kind: 'failed'; text: string; gated: boolean }
  >({ kind: 'loading' });
  const [vtepInput, setVtepInput] = React.useState('');
  const [vtepLookup, setVtepLookup] = React.useState<string | null>(null);
  const [vtepBusy, setVtepBusy] = React.useState(false);

  React.useEffect(() => {
    let live = true;
    void ops.listAdmittedVTEPs().then((res) => {
      if (!live) return;
      if (res.ok) {
        setVteps(res.data?.vteps ?? []);
        setVtepsState({ kind: 'ready' });
      } else {
        setVtepsState({ kind: 'failed', text: failureText(res), gated: res.notConfigured });
      }
    });
    return () => {
      live = false;
    };
  }, [ops]);

  const vtepGated = vtepsState.kind === 'failed' && vtepsState.gated;

  const findVtep = async (e: React.FormEvent) => {
    e.preventDefault();
    const vtep = vtepInput.trim();
    if (!vtep) return;
    setVtepBusy(true);
    const res = await ops.getAdmittedVTEP(vtep);
    setVtepBusy(false);
    if (res.ok && res.data?.vtep) {
      const v = res.data.vtep;
      setVtepLookup(`${v.vtep} admitted${v.hostname ? ` (host ${v.hostname})` : ''}`);
    } else if (res.ok) {
      setVtepLookup(`${vtep}: not found`);
    } else {
      setVtepLookup(`${vtep}: ${failureText(res)}`);
    }
  };

  // IPAM pool lookup and delete
  const [poolId, setPoolId] = React.useState('');
  const [poolBusy, setPoolBusy] = React.useState(false);
  const [poolText, setPoolText] = React.useState<string | null>(null);
  const [poolFound, setPoolFound] = React.useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = React.useState(false);

  const getPool = async (e?: React.FormEvent) => {
    e?.preventDefault();
    const id = poolId.trim();
    if (!id) return;
    setPoolBusy(true);
    const res = await ops.getIPAMPool(id);
    setPoolBusy(false);
    setConfirmDelete(false);
    if (res.ok && res.data) {
      const p = res.data;
      setPoolFound(p.id || id);
      setPoolText(
        [
          `${p.name || p.id} — ${p.cidr}`,
          p.description ? `Description: ${p.description}` : '',
          `Allocated ${p.allocated ?? 0} of ${p.total ?? 0}, ${p.available ?? 0} available`,
        ]
          .filter(Boolean)
          .join('\n')
      );
    } else {
      setPoolFound(null);
      setPoolText(`Pool ${id}: ${res.ok ? 'not found' : failureText(res)}`);
    }
  };

  const deletePool = async () => {
    if (!poolFound) return;
    setPoolBusy(true);
    const res = await ops.deleteIPAMPool(poolFound);
    setPoolBusy(false);
    setConfirmDelete(false);
    if (res.ok) {
      setPoolText(`Pool ${poolFound} deleted.`);
      setPoolFound(null);
    } else {
      setPoolText(`Delete pool ${poolFound} failed: ${failureText(res)}`);
    }
  };

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Gateway Mode</CardTitle>
          <CardDescription>
            Set the gateway mode bitmask (SetGatewayMode). Current modes:{' '}
            <span className="font-mono">{currentModes ?? '—'}</span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="flex items-end gap-2" onSubmit={submitMode}>
            <div className="grid gap-1 flex-1">
              <Label htmlFor="gateway-mode-bitmask">Mode bitmask</Label>
              <Input
                id="gateway-mode-bitmask"
                inputMode="numeric"
                placeholder={String(currentModes ?? 0)}
                value={modeInput}
                onChange={(e) => setModeInput(e.target.value)}
                disabled={modeGateReason !== null}
              />
            </div>
            <Button type="submit" disabled={modeDisabled}>
              {modeBusy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Set mode
            </Button>
          </form>
          {modeGateReason && (
            <p className="mt-2 text-sm text-muted-foreground" data-testid="gateway-mode-reason">
              {modeGateReason}
            </p>
          )}
          {modeResult && (
            <p className="mt-2 text-sm" data-testid="gateway-mode-result" role="status">
              {modeResult}
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Gateway Snapshot</CardTitle>
          <CardDescription>Look up the last telemetry snapshot of one gateway.</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="flex items-end gap-2" onSubmit={lookupSnapshot}>
            <div className="grid gap-1 flex-1">
              <Label htmlFor="gateway-snapshot-id">Snapshot gateway ID</Label>
              <Input
                id="gateway-snapshot-id"
                value={snapshotId}
                onChange={(e) => setSnapshotId(e.target.value)}
              />
            </div>
            <Button type="submit" disabled={snapshotBusy || snapshotId.trim() === ''}>
              Get snapshot
            </Button>
          </form>
          {snapshotText && (
            <pre
              className="mt-2 max-h-64 overflow-auto rounded bg-muted p-2 text-xs"
              data-testid="gateway-snapshot-lookup"
            >
              {snapshotText}
            </pre>
          )}
        </CardContent>
      </Card>

      <Card data-testid="gateway-admitted-vteps">
        <CardHeader>
          <CardTitle>Admitted VTEPs</CardTitle>
          <CardDescription>VTEPs this gateway admitted after attestation.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {vtepsState.kind === 'loading' ? (
            <p className="text-sm text-muted-foreground">Loading admitted VTEPs…</p>
          ) : vtepsState.kind === 'failed' ? (
            <p className="text-sm text-muted-foreground">{vtepsState.text}</p>
          ) : vteps.length === 0 ? (
            <p className="text-sm text-muted-foreground">No VTEPs admitted.</p>
          ) : (
            <ul className="space-y-1 text-sm">
              {vteps.map((v) => (
                <li key={v.vtep} className="font-mono">
                  {v.vtep}
                  {v.hostname ? ` — ${v.hostname}` : ''}
                </li>
              ))}
            </ul>
          )}
          <form className="flex items-end gap-2" onSubmit={findVtep}>
            <div className="grid gap-1 flex-1">
              <Label htmlFor="gateway-vtep-address">VTEP address</Label>
              <Input
                id="gateway-vtep-address"
                value={vtepInput}
                onChange={(e) => setVtepInput(e.target.value)}
                disabled={vtepGated}
              />
            </div>
            <Button type="submit" disabled={vtepGated || vtepBusy || vtepInput.trim() === ''}>
              Find VTEP
            </Button>
          </form>
          {vtepLookup && (
            <p className="text-sm" data-testid="gateway-vtep-lookup">
              {vtepLookup}
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>IPAM Pool</CardTitle>
          <CardDescription>Look up or delete one IPAM pool by ID.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <form className="flex items-end gap-2" onSubmit={getPool}>
            <div className="grid gap-1 flex-1">
              <Label htmlFor="gateway-pool-id">IPAM pool ID</Label>
              <Input id="gateway-pool-id" value={poolId} onChange={(e) => setPoolId(e.target.value)} />
            </div>
            <Button type="submit" disabled={poolBusy || poolId.trim() === ''}>
              Get pool
            </Button>
          </form>
          {poolText && (
            <pre className="whitespace-pre-wrap text-sm" data-testid="gateway-pool-lookup">
              {poolText}
            </pre>
          )}
          {poolFound && !confirmDelete && (
            <Button variant="destructive" onClick={() => setConfirmDelete(true)} disabled={poolBusy}>
              Delete pool
            </Button>
          )}
          {poolFound && confirmDelete && (
            <div className="flex gap-2">
              <Button variant="destructive" onClick={deletePool} disabled={poolBusy}>
                Confirm delete
              </Button>
              <Button variant="outline" onClick={() => setConfirmDelete(false)}>
                Cancel
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
