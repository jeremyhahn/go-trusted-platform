'use client';

/**
 * BGPPeersCard lists the gateway's BGP peers (GatewayService.ListBGPPeers
 * through useBGPPrefixes) and counts the ones not ESTABLISHED. It is
 * read-only; a refusal from the control plane is shown verbatim.
 */
import { useCallback, useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useToast } from '@/hooks/use-toast';
import { peersDown, useBGPPrefixes, type BGPPeer } from '@/hooks/use-bgp-prefixes';
import { Gated } from '@/components/features/capabilities/gated';

export function BGPPeersCard() {
  const ops = useBGPPrefixes();
  const { toast } = useToast();
  const [peers, setPeers] = useState<BGPPeer[] | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    setBusy(true);
    try {
      const res = await ops.listPeers();
      if (res.success) {
        setPeers((res.data?.peers as BGPPeer[] | undefined) ?? []);
      } else {
        toast({ title: 'BGP peers unavailable', description: res.error?.message, variant: 'destructive' });
      }
    } finally {
      setBusy(false);
    }
  }, [ops, toast]);

  useEffect(() => {
    void reload();
  }, [reload]);

  return (
    <Card>
      <CardHeader>
        <CardTitle>BGP peers</CardTitle>
        <CardDescription>
          {peers !== null && (
            <span data-testid="bgp-peers-down">{`${peersDown(peers).length} of ${peers.length} peers down`}</span>
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {peers !== null && peers.length === 0 && <p>No BGP peers</p>}
        {peers !== null && peers.length > 0 && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Address</TableHead>
                <TableHead>ASN</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Received</TableHead>
                <TableHead>Sent</TableHead>
                <TableHead>Uptime</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {peers.map((p) => (
                <TableRow key={p.address} data-testid="bgp-peer-row">
                  <TableCell>{p.address}</TableCell>
                  <TableCell>{p.asn}</TableCell>
                  <TableCell>{p.state}</TableCell>
                  <TableCell>{p.prefixesReceived}</TableCell>
                  <TableCell>{p.prefixesSent}</TableCell>
                  <TableCell>{p.uptime ?? '-'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <Gated op="GET /api/v1/gateway/bgp/peers">
          <Button variant="outline" disabled={busy} onClick={() => void reload()}>
            Refresh
          </Button>
        </Gated>
      </CardContent>
    </Card>
  );
}
