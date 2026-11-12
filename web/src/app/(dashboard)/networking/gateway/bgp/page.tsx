'use client';
import * as React from 'react';
import { AlertCircle, Loader2, Plus, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
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
import { useGatewayBgp, useToast } from '@/hooks';

type Pending =
  | { kind: 'withdraw'; prefix: string }
  | { kind: 'release'; ip: string }
  | null;

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export default function GatewayBgpPage() {
  const {
    peers,
    prefixes,
    allocations,
    isLoading,
    error,
    refetch,
    announcePrefix,
    withdrawPrefix,
    allocateIP,
    releaseIP,
  } = useGatewayBgp();
  const { toast } = useToast();

  const [prefix, setPrefix] = React.useState('');
  const [nextHop, setNextHop] = React.useState('');
  const [poolId, setPoolId] = React.useState('');
  const [hostname, setHostname] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [pending, setPending] = React.useState<Pending>(null);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      toast({ title: 'Request failed', description: errText(e), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  const onAnnounce = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await announcePrefix(prefix.trim(), nextHop.trim());
      toast({ title: 'Prefix announced', description: prefix.trim() });
      setPrefix('');
      setNextHop('');
    });
  };

  const onAllocate = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const alloc = await allocateIP(poolId.trim(), hostname.trim());
      toast({ title: 'IP allocated', description: alloc?.ip || poolId.trim() });
      setPoolId('');
      setHostname('');
    });
  };

  const onConfirm = () => {
    const p = pending;
    if (!p) return;
    void run(async () => {
      if (p.kind === 'withdraw') {
        await withdrawPrefix(p.prefix);
        toast({ title: 'Prefix withdrawn', description: p.prefix });
      } else {
        await releaseIP(p.ip);
        toast({ title: 'IP released', description: p.ip });
      }
      setPending(null);
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Gateway BGP &amp; IPAM</h1>
          <p className="text-muted-foreground">
            BGP peers, announced prefixes and IP allocations of the gateway.
          </p>
        </div>
        <Button variant="outline" onClick={() => void refetch()} disabled={isLoading}>
          <RefreshCw className="mr-2 h-4 w-4" />
          Refresh
        </Button>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Could not load gateway data</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {isLoading && (
        <div className="flex items-center gap-2 text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading…
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>BGP Peers</CardTitle>
        </CardHeader>
        <CardContent>
          <Table aria-label="BGP peers">
            <TableHeader>
              <TableRow>
                <TableHead>Address</TableHead>
                <TableHead>ASN</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Prefixes received</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {peers.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-muted-foreground">
                    No BGP peers.
                  </TableCell>
                </TableRow>
              ) : (
                peers.map((p) => (
                  <TableRow key={p.address}>
                    <TableCell className="font-mono text-sm">{p.address}</TableCell>
                    <TableCell>{p.asn}</TableCell>
                    <TableCell>
                      <Badge variant={p.state === 'established' ? 'default' : 'secondary'}>
                        {p.state || 'unknown'}
                      </Badge>
                    </TableCell>
                    <TableCell>{p.prefixesReceived}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Announced Prefixes</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <form className="flex flex-wrap items-end gap-3" onSubmit={onAnnounce}>
            <div className="space-y-1">
              <Label htmlFor="announce-prefix">Prefix</Label>
              <Input
                id="announce-prefix"
                value={prefix}
                onChange={(e) => setPrefix(e.target.value)}
                placeholder="CIDR"
                required
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="announce-next-hop">Next hop</Label>
              <Input
                id="announce-next-hop"
                value={nextHop}
                onChange={(e) => setNextHop(e.target.value)}
                placeholder="optional"
              />
            </div>
            <Button type="submit" disabled={busy || !prefix.trim()}>
              <Plus className="mr-2 h-4 w-4" />
              Announce
            </Button>
          </form>
          <Table aria-label="Announced prefixes">
            <TableHeader>
              <TableRow>
                <TableHead>Prefix</TableHead>
                <TableHead>Next hop</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {prefixes.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={3} className="text-muted-foreground">
                    No announced prefixes.
                  </TableCell>
                </TableRow>
              ) : (
                prefixes.map((p) => (
                  <TableRow key={p.prefix}>
                    <TableCell className="font-mono text-sm">{p.prefix}</TableCell>
                    <TableCell className="font-mono text-sm">{p.nextHop || '—'}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="destructive"
                        size="sm"
                        aria-label={`Withdraw ${p.prefix}`}
                        onClick={() => setPending({ kind: 'withdraw', prefix: p.prefix })}
                      >
                        Withdraw
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>IP Allocations</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <form className="flex flex-wrap items-end gap-3" onSubmit={onAllocate}>
            <div className="space-y-1">
              <Label htmlFor="allocate-pool">Pool ID</Label>
              <Input
                id="allocate-pool"
                value={poolId}
                onChange={(e) => setPoolId(e.target.value)}
                required
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="allocate-hostname">Hostname</Label>
              <Input
                id="allocate-hostname"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
              />
            </div>
            <Button type="submit" disabled={busy || !poolId.trim()}>
              <Plus className="mr-2 h-4 w-4" />
              Allocate
            </Button>
          </form>
          <Table aria-label="IP allocations">
            <TableHeader>
              <TableRow>
                <TableHead>IP</TableHead>
                <TableHead>Pool</TableHead>
                <TableHead>Hostname</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {allocations.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-muted-foreground">
                    No allocations.
                  </TableCell>
                </TableRow>
              ) : (
                allocations.map((a) => (
                  <TableRow key={a.ip}>
                    <TableCell className="font-mono text-sm">{a.ip}</TableCell>
                    <TableCell>{a.poolId}</TableCell>
                    <TableCell>{a.hostname || '—'}</TableCell>
                    <TableCell>{a.status || '—'}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="destructive"
                        size="sm"
                        aria-label={`Release ${a.ip}`}
                        onClick={() => setPending({ kind: 'release', ip: a.ip })}
                      >
                        Release
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={pending !== null} onOpenChange={(open) => !open && setPending(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {pending?.kind === 'withdraw' ? 'Withdraw prefix' : 'Release IP'}
            </DialogTitle>
            <DialogDescription>
              {pending?.kind === 'withdraw'
                ? `Withdraw ${pending.prefix} from every BGP peer?`
                : pending?.kind === 'release'
                  ? `Release ${pending.ip} back to its pool?`
                  : ''}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPending(null)} disabled={busy}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={onConfirm} disabled={busy}>
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
