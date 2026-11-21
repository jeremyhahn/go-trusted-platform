'use client';

import * as React from 'react';
import { RefreshCw } from 'lucide-react';
import { PageHeader } from '@/components/layout/page-header';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { useToast } from '@/hooks';
import { useGatewayIPAM } from '@/hooks/use-gateway-ipam';

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/**
 * GatewayIPAMPage lists the addresses leased from the gateway's IP pools,
 * filters them by pool, allocates a new one and releases one behind a
 * confirm, through the SDK GatewayService (useGatewayIPAM).
 */
export default function GatewayIPAMPage() {
  const { toast } = useToast();
  const [poolInput, setPoolInput] = React.useState('');
  const [poolId, setPoolId] = React.useState('');
  const [allocPool, setAllocPool] = React.useState('');
  const [allocHost, setAllocHost] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [confirmIP, setConfirmIP] = React.useState<string | null>(null);

  const ipam = useGatewayIPAM(poolId || undefined);

  const onAllocate = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const host = allocHost.trim();
      const a = await ipam.allocate({ poolId: allocPool.trim(), ...(host ? { hostname: host } : {}) });
      toast({ title: 'IP allocated', description: a?.ip ?? 'allocated' });
    } catch (err) {
      toast({ title: 'Allocation refused', description: message(err), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  const onRelease = async () => {
    const ip = confirmIP;
    setConfirmIP(null);
    if (!ip) return;
    try {
      await ipam.release(ip);
      toast({ title: 'IP released', description: ip });
    } catch (err) {
      toast({ title: 'Release refused', description: message(err), variant: 'destructive' });
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Gateway IP allocations"
        description="Addresses leased from the gateway's IP pools"
        actions={
          <Button variant="outline" size="icon" aria-label="Refresh" onClick={() => void ipam.refetch()}>
            <RefreshCw className={`h-4 w-4 ${ipam.isLoading ? 'animate-spin' : ''}`} />
          </Button>
        }
      />

      <div className="flex items-end gap-2">
        <div className="space-y-1">
          <Label htmlFor="pool-filter">Pool</Label>
          <Input id="pool-filter" value={poolInput} onChange={(e) => setPoolInput(e.target.value)} />
        </div>
        <Button variant="outline" onClick={() => setPoolId(poolInput.trim())}>
          Filter
        </Button>
      </div>

      <form aria-label="Allocate an IP" className="flex items-end gap-2" onSubmit={(e) => void onAllocate(e)}>
        <div className="space-y-1">
          <Label htmlFor="alloc-pool">Pool ID</Label>
          <Input id="alloc-pool" value={allocPool} onChange={(e) => setAllocPool(e.target.value)} />
        </div>
        <div className="space-y-1">
          <Label htmlFor="alloc-host">Hostname</Label>
          <Input id="alloc-host" value={allocHost} onChange={(e) => setAllocHost(e.target.value)} />
        </div>
        <Button type="submit" disabled={busy || !allocPool.trim()}>
          Allocate
        </Button>
      </form>

      {ipam.error ? (
        <p role="alert" className="text-sm text-destructive">
          {ipam.error}
        </p>
      ) : ipam.allocations.length === 0 ? (
        <p className="text-sm text-muted-foreground py-4">{ipam.isLoading ? 'Loading…' : 'No allocations'}</p>
      ) : (
        <Table data-testid="gateway-allocations">
          <TableHeader>
            <TableRow>
              <TableHead>IP</TableHead>
              <TableHead>Pool</TableHead>
              <TableHead>Hostname</TableHead>
              <TableHead>Device</TableHead>
              <TableHead>Allocated</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {ipam.allocations.map((a) => (
              <TableRow key={a.ip}>
                <TableCell className="font-mono text-sm">{a.ip}</TableCell>
                <TableCell>{a.poolId}</TableCell>
                <TableCell>{a.hostname ?? '—'}</TableCell>
                <TableCell>{a.deviceId ?? '—'}</TableCell>
                <TableCell className="text-xs">
                  {a.allocatedAt ? new Date(a.allocatedAt).toLocaleString() : '—'}
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    size="sm"
                    variant="destructive"
                    aria-label={`Release ${a.ip}`}
                    onClick={() => setConfirmIP(a.ip)}
                  >
                    Release
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <Dialog
        open={confirmIP !== null}
        onOpenChange={(o) => {
          if (!o) setConfirmIP(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Release this address?</DialogTitle>
            <DialogDescription>{`${confirmIP} is returned to its pool.`}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmIP(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={() => void onRelease()}>
              Release
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
