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
import { useToast } from '@/hooks';
import {
  parseBackends,
  useGatewayVIPs,
  type GatewayVIPBackendRow,
  type GatewayVIPRow,
} from '@/hooks/use-gateway-vips';
import { counterEntries } from '@/hooks/use-gateway-perf';

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function vipLabel(v: { address: string; port: number }): string {
  return `${v.address}:${v.port}`;
}

function backendText(backends: GatewayVIPBackendRow[]): string {
  return backends
    .map((b) => {
      const host = b.address.includes(':') ? `[${b.address}]` : b.address;
      return `${host}:${b.port}${b.weight ? `@${b.weight}` : ''}`;
    })
    .join('\n');
}

/** A status card that reports the server's fields, or why it has none. */
function StatusCard({
  title,
  testId,
  data,
  error,
  isLoading,
}: {
  title: string;
  testId: string;
  data: Record<string, unknown> | undefined;
  error: Error | undefined;
  isLoading: boolean;
}) {
  const entries = counterEntries(data);
  return (
    <Card data-testid={testId}>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        {error ? (
          <p className="text-sm text-muted-foreground">
            {title} unavailable: {error.message}
          </p>
        ) : isLoading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : entries.length === 0 ? (
          <p className="text-sm text-muted-foreground">No status reported.</p>
        ) : (
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
            {entries.map(([k, v]) => (
              <React.Fragment key={k}>
                <dt className="text-muted-foreground">{k}</dt>
                <dd className="font-mono">{String(v)}</dd>
              </React.Fragment>
            ))}
          </dl>
        )}
      </CardContent>
    </Card>
  );
}

export default function GatewayVIPsPage() {
  const {
    vips,
    isLoading,
    error,
    lbStatus,
    lbError,
    nat64Status,
    nat64Error,
    refetch,
    getVIP,
    addVIP,
    removeVIP,
    setVIPBackends,
  } = useGatewayVIPs();
  const { toast } = useToast();

  const [address, setAddress] = React.useState('');
  const [port, setPort] = React.useState('');
  const [protocol, setProtocol] = React.useState('tcp');
  const [backends, setBackends] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [pendingRemove, setPendingRemove] = React.useState<GatewayVIPRow | null>(null);
  const [editing, setEditing] = React.useState<GatewayVIPRow | null>(null);
  const [editText, setEditText] = React.useState('');

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

  const onAdd = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const p = Number(port);
      if (!Number.isInteger(p) || p < 1 || p > 65535) {
        throw new Error('VIP port must be 1-65535');
      }
      await addVIP({
        address: address.trim(),
        port: p,
        protocol,
        backends: parseBackends(backends),
      });
      toast({ title: 'VIP added' });
      setAddress('');
      setPort('');
      setBackends('');
    });
  };

  const onOpenBackends = (v: GatewayVIPRow) => {
    setEditing(v);
    setEditText(backendText(v.backends));
    // Refresh from GetVIP so the dialog shows the current health.
    void getVIP(v.address, v.port, v.protocol)
      .then((fresh) => {
        if (fresh) {
          setEditing(fresh);
          setEditText(backendText(fresh.backends));
        }
      })
      .catch((e) => toast({ title: 'Could not load VIP', description: errText(e), variant: 'destructive' }));
  };

  const onSaveBackends = () => {
    const v = editing;
    if (!v) return;
    void run(async () => {
      await setVIPBackends({
        address: v.address,
        port: v.port,
        protocol: v.protocol,
        backends: parseBackends(editText),
      });
      toast({ title: 'Backends updated' });
      setEditing(null);
    });
  };

  const onConfirmRemove = () => {
    const v = pendingRemove;
    if (!v) return;
    void run(async () => {
      await removeVIP(v.address, v.port, v.protocol);
      toast({ title: 'VIP removed' });
      setPendingRemove(null);
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Virtual IPs</h1>
          <p className="text-muted-foreground">
            Load-balanced virtual IPs of the gateway, their backends, and the LB and NAT64 status.
          </p>
        </div>
        <Button variant="outline" onClick={() => void refetch()} disabled={isLoading}>
          <RefreshCw className="mr-2 h-4 w-4" />
          Refresh
        </Button>
      </div>

      {isLoading && (
        <div className="flex items-center gap-2 text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading…
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <StatusCard
          title="Load balancer"
          testId="gateway-lb-status"
          data={lbStatus}
          error={lbError}
          isLoading={isLoading}
        />
        <StatusCard
          title="NAT64"
          testId="gateway-nat64-status"
          data={nat64Status}
          error={nat64Error}
          isLoading={isLoading}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>VIPs</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <form className="flex flex-wrap items-end gap-3" onSubmit={onAdd}>
            <div className="space-y-1">
              <Label htmlFor="vip-address">VIP address</Label>
              <Input
                id="vip-address"
                value={address}
                onChange={(e) => setAddress(e.target.value)}
                placeholder="IPv4 or IPv6"
                required
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="vip-port">VIP port</Label>
              <Input
                id="vip-port"
                type="number"
                min={1}
                max={65535}
                value={port}
                onChange={(e) => setPort(e.target.value)}
                required
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="vip-protocol">Protocol</Label>
              <select
                id="vip-protocol"
                className="flex h-10 rounded-md border border-input bg-background px-3 py-2 text-sm"
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
              >
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
              </select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="vip-backends">Backends</Label>
              <Input
                id="vip-backends"
                value={backends}
                onChange={(e) => setBackends(e.target.value)}
                placeholder="10.0.0.11:443, 10.0.0.12:443"
              />
            </div>
            <Button type="submit" disabled={busy || !address.trim() || !port.trim()}>
              <Plus className="mr-2 h-4 w-4" />
              Add VIP
            </Button>
          </form>

          {error && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Could not load VIPs</AlertTitle>
              <AlertDescription>{error.message}</AlertDescription>
            </Alert>
          )}

          <Table aria-label="Virtual IPs">
            <TableHeader>
              <TableRow>
                <TableHead>Address</TableHead>
                <TableHead>Port</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead>Algorithm</TableHead>
                <TableHead>Backends</TableHead>
                <TableHead>CT zone</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {vips.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-muted-foreground">
                    No virtual IPs.
                  </TableCell>
                </TableRow>
              ) : (
                vips.map((v) => (
                  <TableRow key={`${v.protocol}/${v.address}/${v.port}`}>
                    <TableCell className="font-mono text-sm">{v.address}</TableCell>
                    <TableCell>{v.port}</TableCell>
                    <TableCell>{v.protocol}</TableCell>
                    <TableCell>{v.algorithm || '—'}</TableCell>
                    <TableCell>
                      <Badge variant="secondary">
                        {v.backends.filter((b) => b.healthy !== false).length}/{v.backends.length}
                      </Badge>
                    </TableCell>
                    <TableCell>{v.ctZone ?? '—'}</TableCell>
                    <TableCell className="space-x-2 text-right">
                      <Button
                        variant="outline"
                        size="sm"
                        aria-label={`Backends of ${vipLabel(v)}`}
                        onClick={() => onOpenBackends(v)}
                      >
                        Backends
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        aria-label={`Remove ${vipLabel(v)}`}
                        onClick={() => setPendingRemove(v)}
                      >
                        Remove
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={editing !== null} onOpenChange={(open) => !open && setEditing(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>VIP backends</DialogTitle>
            <DialogDescription>
              {editing ? `${editing.protocol} ${vipLabel(editing)}` : ''}
            </DialogDescription>
          </DialogHeader>
          <Table aria-label="VIP backends">
            <TableHeader>
              <TableRow>
                <TableHead>Backend</TableHead>
                <TableHead>Weight</TableHead>
                <TableHead>Health</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(editing?.backends ?? []).map((b) => (
                <TableRow key={`${b.address}:${b.port}`}>
                  <TableCell className="font-mono text-sm">{b.address}</TableCell>
                  <TableCell>{b.weight || 1}</TableCell>
                  <TableCell>
                    {b.healthy === undefined ? 'unknown' : b.healthy ? 'healthy' : 'down'}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <div className="space-y-1">
            <Label htmlFor="vip-backends-edit">New backends</Label>
            <textarea
              id="vip-backends-edit"
              className="min-h-[80px] w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm"
              value={editText}
              onChange={(e) => setEditText(e.target.value)}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditing(null)} disabled={busy}>
              Cancel
            </Button>
            <Button onClick={onSaveBackends} disabled={busy}>
              Save backends
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={pendingRemove !== null} onOpenChange={(open) => !open && setPendingRemove(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remove VIP</DialogTitle>
            <DialogDescription>
              Stop balancing this virtual IP and remove its flows?
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPendingRemove(null)} disabled={busy}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={onConfirmRemove} disabled={busy}>
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
