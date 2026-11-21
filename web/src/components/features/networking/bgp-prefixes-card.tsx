'use client';

/**
 * BGPPrefixesCard lists the prefixes the gateway announces
 * (GatewayService.ListAnnouncedPrefixes), announces a new one
 * (AnnouncePrefix) and withdraws one (WithdrawPrefix), all through
 * useBGPPrefixes. Withdraw asks first in a dialog; a refusal from the
 * control plane is shown verbatim.
 */
import { useCallback, useEffect, useState } from 'react';
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
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useToast } from '@/hooks/use-toast';
import { normalizePrefix, useBGPPrefixes } from '@/hooks/use-bgp-prefixes';

/** The SDK root does not export AnnouncedPrefix; this is its wire shape. */
interface AnnouncedPrefixRow {
  prefix: string;
  nextHop: string;
  announcedAt: string;
}

export function BGPPrefixesCard() {
  const ops = useBGPPrefixes();
  const { toast } = useToast();
  const [prefixes, setPrefixes] = useState<AnnouncedPrefixRow[] | null>(null);
  const [prefix, setPrefix] = useState('');
  const [nextHop, setNextHop] = useState('');
  const [busy, setBusy] = useState(false);
  const [pendingWithdraw, setPendingWithdraw] = useState<string | null>(null);

  const reload = useCallback(async () => {
    const res = await ops.listAnnounced();
    if (res.success) {
      setPrefixes((res.data?.prefixes as AnnouncedPrefixRow[] | undefined) ?? []);
    } else {
      toast({ title: 'Announced prefixes unavailable', description: res.error?.message, variant: 'destructive' });
    }
  }, [ops, toast]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const normalized = normalizePrefix(prefix);

  const onAnnounce = async () => {
    if (normalized === null) return;
    setBusy(true);
    try {
      const res = await ops.announce(prefix, nextHop);
      if (res.success) {
        toast({ title: 'Prefix announced', description: prefix.trim(), variant: 'success' });
        setPrefix('');
        setNextHop('');
        await reload();
      } else {
        toast({ title: 'Announce failed', description: res.error?.message, variant: 'destructive' });
      }
    } finally {
      setBusy(false);
    }
  };

  const onConfirmWithdraw = async () => {
    const target = pendingWithdraw;
    setPendingWithdraw(null);
    if (target === null) return;
    setBusy(true);
    try {
      const res = await ops.withdraw(target);
      if (res.success) {
        toast({ title: 'Prefix withdrawn', description: target, variant: 'success' });
        await reload();
      } else {
        toast({ title: 'Withdraw failed', description: res.error?.message, variant: 'destructive' });
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Announced prefixes</CardTitle>
        <CardDescription>Routes the gateway announces to every BGP peer.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {prefixes !== null && prefixes.length === 0 && <p>No prefixes announced</p>}
        {prefixes !== null && prefixes.length > 0 && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Prefix</TableHead>
                <TableHead>Next hop</TableHead>
                <TableHead>Announced at</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {prefixes.map((p) => (
                <TableRow key={p.prefix} data-testid="bgp-prefix-row">
                  <TableCell>{p.prefix}</TableCell>
                  <TableCell>{p.nextHop || '-'}</TableCell>
                  <TableCell>{p.announcedAt}</TableCell>
                  <TableCell>
                    <Button
                      variant="destructive"
                      size="sm"
                      aria-label={`Withdraw ${p.prefix}`}
                      disabled={busy}
                      onClick={() => setPendingWithdraw(p.prefix)}
                    >
                      Withdraw
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}

        <div className="grid gap-2 sm:grid-cols-2">
          <div className="space-y-1">
            <Label htmlFor="bgp-prefix">Prefix</Label>
            <Input id="bgp-prefix" value={prefix} onChange={(e) => setPrefix(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="bgp-next-hop">Next hop</Label>
            <Input id="bgp-next-hop" value={nextHop} onChange={(e) => setNextHop(e.target.value)} />
          </div>
        </div>
        {prefix.trim() !== '' && normalized === null && (
          <p data-testid="bgp-prefix-invalid" className="text-sm text-destructive">
            Not a CIDR prefix
          </p>
        )}
        <Button disabled={busy || normalized === null} onClick={() => void onAnnounce()}>
          Announce
        </Button>
      </CardContent>

      <Dialog
        open={pendingWithdraw !== null}
        onOpenChange={(open) => {
          if (!open) setPendingWithdraw(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{`Withdraw ${pendingWithdraw}?`}</DialogTitle>
            <DialogDescription>Every BGP peer stops receiving this route.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPendingWithdraw(null)}>
              Cancel
            </Button>
            <Button variant="destructive" disabled={busy} onClick={() => void onConfirmWithdraw()}>
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
