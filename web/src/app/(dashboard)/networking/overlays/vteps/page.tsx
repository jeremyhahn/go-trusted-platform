'use client';

import { useState } from 'react';
import { Loader2, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
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
import { Badge } from '@/components/ui/badge';
import { useOverlayVteps, useToast } from '@/hooks';
import type { TunnelInfo, VTEPInfo } from 'trusted-platform-sdk';

interface PendingAction {
  title: string;
  description: string;
  confirmLabel: string;
  run: () => Promise<void>;
  success: string;
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : 'Unknown error';
}

/**
 * Overlay VTEPs, VNIs, tunnels and remote MACs (#1722).
 */
export default function OverlayVtepsPage() {
  const { toast } = useToast();
  const {
    vteps,
    vnis,
    tunnels,
    isLoading,
    refetchAll,
    getVTEP,
    getTunnelStats,
    deleteVNI,
    forgetMAC,
  } = useOverlayVteps();

  const [vtepDetail, setVtepDetail] = useState<VTEPInfo | null>(null);
  const [tunnelStats, setTunnelStats] = useState<TunnelInfo | null>(null);
  const [pending, setPending] = useState<PendingAction | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [macAddress, setMacAddress] = useState('');
  const [macVni, setMacVni] = useState('');

  const showVtep = async (nodeId: string) => {
    try {
      const v = await getVTEP(nodeId);
      if (v) setVtepDetail(v);
    } catch (err) {
      toast({ title: 'Failed to load VTEP', description: errorText(err), variant: 'destructive' });
    }
  };

  const showStats = async (t: TunnelInfo) => {
    try {
      const s = await getTunnelStats(t.remoteVtep, t.vni);
      if (s) setTunnelStats(s);
    } catch (err) {
      toast({ title: 'Failed to load tunnel stats', description: errorText(err), variant: 'destructive' });
    }
  };

  const askForgetMac = () => {
    const vni = Number.parseInt(macVni, 10);
    if (!macAddress || !Number.isFinite(vni) || vni < 1) {
      toast({ title: 'Enter a MAC address and a VNI', variant: 'destructive' });
      return;
    }
    setPending({
      title: 'Forget MAC',
      description: `Forget MAC ${macAddress} on VNI ${vni}?`,
      confirmLabel: 'Forget',
      run: async () => {
        await forgetMAC(macAddress, vni);
        setMacAddress('');
        setMacVni('');
      },
      success: 'MAC forgotten',
    });
  };

  const confirmPending = async () => {
    if (!pending) return;
    setSubmitting(true);
    try {
      await pending.run();
      toast({ title: pending.success, variant: 'success' });
      setPending(null);
    } catch (err) {
      toast({ title: `${pending.title} failed`, description: errorText(err), variant: 'destructive' });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Overlay VTEPs</h1>
          <p className="text-muted-foreground mt-1">
            VXLAN tunnel endpoints, VNIs, tunnels and remote MAC entries
          </p>
        </div>
        <Button
          variant="outline"
          size="icon"
          aria-label="Refresh"
          onClick={refetchAll}
          disabled={isLoading}
        >
          <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
        </Button>
      </div>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">VTEPs</h2>
        <div className="rounded-md border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Node</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>Health</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {vteps.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-muted-foreground">
                    No VTEPs found
                  </TableCell>
                </TableRow>
              ) : (
                vteps.map((v) => (
                  <TableRow key={v.nodeId}>
                    <TableCell className="font-medium">{v.nodeId}</TableCell>
                    <TableCell className="font-mono">{v.ip}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{v.healthy ? 'healthy' : 'unhealthy'}</Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        aria-label={`Details ${v.nodeId}`}
                        onClick={() => void showVtep(v.nodeId)}
                      >
                        Details
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">VNIs</h2>
        <div className="rounded-md border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>VNI</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>MACs</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {vnis.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-muted-foreground">
                    No VNIs found
                  </TableCell>
                </TableRow>
              ) : (
                vnis.map((v) => (
                  <TableRow key={v.id || v.config.vni}>
                    <TableCell className="font-mono">{v.config.vni}</TableCell>
                    <TableCell>{v.config.name || '-'}</TableCell>
                    <TableCell>{v.macCount}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        aria-label={`Delete VNI ${v.config.vni}`}
                        onClick={() =>
                          setPending({
                            title: 'Delete VNI',
                            description: `Delete VNI ${v.config.vni}? Its tunnels and MAC entries go with it.`,
                            confirmLabel: 'Delete',
                            run: () => deleteVNI(v.config.vni),
                            success: 'VNI deleted',
                          })
                        }
                      >
                        Delete
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Tunnels</h2>
        <div className="rounded-md border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Local VTEP</TableHead>
                <TableHead>Remote VTEP</TableHead>
                <TableHead>VNI</TableHead>
                <TableHead>State</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {tunnels.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-muted-foreground">
                    No tunnels found
                  </TableCell>
                </TableRow>
              ) : (
                tunnels.map((t) => (
                  <TableRow key={`${t.remoteVtep}-${t.vni}`}>
                    <TableCell>{t.localVtep}</TableCell>
                    <TableCell>{t.remoteVtep}</TableCell>
                    <TableCell className="font-mono">{t.vni}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{t.state}</Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        aria-label={`Stats ${t.remoteVtep} ${t.vni}`}
                        onClick={() => void showStats(t)}
                      >
                        Stats
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Forget a remote MAC</h2>
        <div className="flex items-end gap-2">
          <div className="space-y-2">
            <Label htmlFor="forget-mac">MAC address</Label>
            <Input
              id="forget-mac"
              value={macAddress}
              onChange={(e) => setMacAddress(e.target.value)}
              placeholder="aa:bb:cc:dd:ee:ff"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="forget-vni">VNI</Label>
            <Input
              id="forget-vni"
              type="number"
              min={1}
              value={macVni}
              onChange={(e) => setMacVni(e.target.value)}
              placeholder="10000"
            />
          </div>
          <Button variant="destructive" onClick={askForgetMac}>
            Forget MAC
          </Button>
        </div>
      </section>

      <Dialog open={vtepDetail !== null} onOpenChange={(o) => !o && setVtepDetail(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>VTEP {vtepDetail?.nodeId}</DialogTitle>
            <DialogDescription>Tunnel endpoint details</DialogDescription>
          </DialogHeader>
          <dl className="grid grid-cols-2 gap-2 text-sm">
            <dt className="text-muted-foreground">IP</dt>
            <dd className="font-mono">{vtepDetail?.ip}</dd>
            <dt className="text-muted-foreground">Health</dt>
            <dd>{vtepDetail?.healthy ? 'healthy' : 'unhealthy'}</dd>
            <dt className="text-muted-foreground">Last seen</dt>
            <dd>{vtepDetail?.lastSeen}</dd>
          </dl>
        </DialogContent>
      </Dialog>

      <Dialog open={tunnelStats !== null} onOpenChange={(o) => !o && setTunnelStats(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Tunnel statistics</DialogTitle>
            <DialogDescription>
              {tunnelStats?.remoteVtep} on VNI {tunnelStats?.vni}
            </DialogDescription>
          </DialogHeader>
          <dl className="grid grid-cols-2 gap-2 text-sm">
            <dt className="text-muted-foreground">State</dt>
            <dd>{tunnelStats?.state}</dd>
            <dt className="text-muted-foreground">Bytes sent</dt>
            <dd className="font-mono">{tunnelStats?.bytesTx}</dd>
            <dt className="text-muted-foreground">Bytes received</dt>
            <dd className="font-mono">{tunnelStats?.bytesRx}</dd>
          </dl>
        </DialogContent>
      </Dialog>

      <Dialog open={pending !== null} onOpenChange={(o) => !o && setPending(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{pending?.title}</DialogTitle>
            <DialogDescription>{pending?.description}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPending(null)}>
              Cancel
            </Button>
            <Button variant="destructive" disabled={submitting} onClick={() => void confirmPending()}>
              {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {pending?.confirmLabel}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
