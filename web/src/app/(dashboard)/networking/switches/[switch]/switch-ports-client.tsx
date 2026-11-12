"use client";

import { useState } from 'react';
import { useParams, usePathname } from 'next/navigation';
import { resolveDynamicId } from '@/utils/dynamic-route';
import { AlertCircle, Cable, Loader2, RefreshCw } from 'lucide-react';
import type { SwitchPortStatus } from 'trusted-platform-sdk';
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
import { useSwitchPorts, useToast } from '@/hooks';

type PendingAction = { port: string; action: 'enable' | 'disable' } | null;

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : 'Unknown error';
}

export default function SwitchPortsClient() {
  const params = useParams();
  const pathname = usePathname();
  const switchName = resolveDynamicId(params, pathname, 'switches', 'switch');
  const { toast } = useToast();
  const { ports, isLoading, error, refetch, getPortStatus, enablePort, disablePort, setPortVLAN } =
    useSwitchPorts(switchName);

  const [status, setStatus] = useState<SwitchPortStatus | null>(null);
  const [pending, setPending] = useState<PendingAction>(null);
  const [vlanPort, setVlanPort] = useState<string | null>(null);
  const [vlanValue, setVlanValue] = useState('');
  const [busy, setBusy] = useState(false);

  const showStatus = async (port: string) => {
    try {
      const result = await getPortStatus(port);
      setStatus(result ?? null);
    } catch (err) {
      toast({ title: 'Error loading port status', description: errorMessage(err), variant: 'destructive' });
    }
  };

  const confirmAction = async () => {
    if (!pending) return;
    setBusy(true);
    try {
      if (pending.action === 'enable') {
        await enablePort(pending.port);
      } else {
        await disablePort(pending.port);
      }
      toast({ title: `Port ${pending.port} ${pending.action}d`, variant: 'success' });
      setPending(null);
      refetch();
    } catch (err) {
      toast({ title: `Failed to ${pending.action} port`, description: errorMessage(err), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  // The single-port status never reports link state: take it from the port list.
  const listed = status ? ports.find((p) => p.port === status.port) : undefined;
  const statusLink = listed ? (listed.link_up ? 'up' : 'down') : 'unavailable';

  const vlanId = Number(vlanValue);
  const vlanValid = Number.isInteger(vlanId) && vlanId >= 1 && vlanId <= 4094;

  const submitVLAN = async () => {
    if (!vlanPort || !vlanValid) return;
    setBusy(true);
    try {
      await setPortVLAN(vlanPort, vlanId);
      toast({ title: `Port ${vlanPort} set to VLAN ${vlanId}`, variant: 'success' });
      setVlanPort(null);
      setVlanValue('');
      refetch();
    } catch (err) {
      toast({ title: 'Failed to set VLAN', description: errorMessage(err), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertTitle>Error Loading Switch Ports</AlertTitle>
        <AlertDescription>
          {error.message}
          <Button variant="outline" size="sm" className="ml-4" onClick={refetch}>
            Retry
          </Button>
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Switch {switchName}</h1>
          <p className="text-muted-foreground mt-1">Port status, enable and disable, and VLAN</p>
        </div>
        <Button variant="outline" size="icon" aria-label="Refresh" onClick={refetch} disabled={isLoading}>
          <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Cable className="h-5 w-5" />
            Ports
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading && ports.length === 0 ? (
            <div className="flex items-center justify-center py-6">
              <Loader2 className="h-6 w-6 animate-spin mr-2" />
              <span>Loading ports...</span>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Port</TableHead>
                  <TableHead>Mode</TableHead>
                  <TableHead>VLAN</TableHead>
                  <TableHead>Admin</TableHead>
                  <TableHead>Link</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ports.map((p) => (
                  <TableRow key={p.port} data-testid={`port-row-${p.port}`}>
                    <TableCell className="font-mono">{p.port}</TableCell>
                    <TableCell>{p.mode}</TableCell>
                    <TableCell>{p.access_vlan}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{p.enabled ? 'enabled' : 'disabled'}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{p.link_up ? 'up' : 'down'}</Badge>
                    </TableCell>
                    <TableCell className="space-x-2">
                      <Button size="sm" variant="outline" onClick={() => showStatus(p.port)}>
                        Status
                      </Button>
                      {p.enabled ? (
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => setPending({ port: p.port, action: 'disable' })}
                        >
                          Disable
                        </Button>
                      ) : (
                        <Button size="sm" onClick={() => setPending({ port: p.port, action: 'enable' })}>
                          Enable
                        </Button>
                      )}
                      {p.mode === 'access' && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            setVlanPort(p.port);
                            setVlanValue(String(p.access_vlan || ''));
                          }}
                        >
                          Set VLAN
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
                {ports.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground">
                      No ports
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog open={status !== null} onOpenChange={(open) => !open && setStatus(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Port {status?.port}</DialogTitle>
            <DialogDescription>Status reported by the switch.</DialogDescription>
          </DialogHeader>
          {status && (
            <dl className="grid grid-cols-2 gap-2 text-sm" data-testid="port-status">
              <dt>Mode</dt>
              <dd>{status.mode}</dd>
              <dt>Access VLAN</dt>
              <dd>{status.access_vlan}</dd>
              <dt>Native VLAN</dt>
              <dd>{status.native_vlan ?? '-'}</dd>
              <dt>Trunk VLANs</dt>
              <dd>{status.trunk_vlans?.join(', ') || '-'}</dd>
              <dt>Admin</dt>
              <dd>{status.enabled ? 'enabled' : 'disabled'}</dd>
              <dt>Link</dt>
              <dd>{statusLink}</dd>
              <dt>Description</dt>
              <dd>{status.description || '-'}</dd>
            </dl>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={pending !== null} onOpenChange={(open) => !open && setPending(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {pending?.action === 'enable' ? 'Enable' : 'Disable'} port {pending?.port}?
            </DialogTitle>
            <DialogDescription>
              {pending?.action === 'disable'
                ? 'Traffic through this port stops until it is enabled again.'
                : 'The port starts forwarding traffic.'}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPending(null)}>
              Cancel
            </Button>
            <Button
              variant={pending?.action === 'disable' ? 'destructive' : 'default'}
              disabled={busy}
              onClick={confirmAction}
            >
              {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={vlanPort !== null} onOpenChange={(open) => !open && setVlanPort(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Set VLAN on {vlanPort}</DialogTitle>
            <DialogDescription>Access VLAN id of this access port, 1 to 4094.</DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="vlan-id">VLAN ID</Label>
            <Input
              id="vlan-id"
              type="number"
              min={1}
              max={4094}
              value={vlanValue}
              onChange={(e) => setVlanValue(e.target.value)}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setVlanPort(null)}>
              Cancel
            </Button>
            <Button disabled={!vlanValid || busy} onClick={submitVLAN}>
              {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
