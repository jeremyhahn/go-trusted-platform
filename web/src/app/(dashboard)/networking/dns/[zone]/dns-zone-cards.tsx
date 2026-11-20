'use client';

import { useEffect, useState } from 'react';
import type { DNSSECStatus } from 'trusted-platform-sdk';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast, type UseDnsOpsResult } from '@/hooks';

export interface DNSZoneSettingsCardProps {
  zoneName: string;
  ttl: number;
  description?: string;
  ops: UseDnsOpsResult;
  onSaved?: () => void;
}

/** Zone TTL and description, saved with UpdateZone (row #2060). */
export function DNSZoneSettingsCard({ zoneName, ttl, description, ops, onSaved }: DNSZoneSettingsCardProps) {
  const { toast } = useToast();
  const [ttlText, setTTLText] = useState(String(ttl));
  const [desc, setDesc] = useState(description ?? '');
  // The parent keys this card on the server's ttl and description, so a
  // refetched zone remounts it with fresh fields.

  const ttlValue = Number.parseInt(ttlText, 10);
  const valid = Number.isFinite(ttlValue) && ttlValue > 0;

  const onSave = async () => {
    const out = await ops.updateZone({ name: zoneName, ttl: ttlValue, description: desc });
    if (!out) {
      toast({ title: 'Failed to update zone', variant: 'destructive' });
      return;
    }
    toast({ title: 'Zone updated', variant: 'success' });
    onSaved?.();
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Zone Settings</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1">
          <Label htmlFor="dns-zone-ttl">Default TTL (seconds)</Label>
          <Input
            id="dns-zone-ttl"
            data-testid="dns-zone-ttl"
            type="number"
            min={1}
            value={ttlText}
            onChange={(e) => setTTLText(e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="dns-zone-description">Description</Label>
          <Input
            id="dns-zone-description"
            data-testid="dns-zone-description"
            value={desc}
            onChange={(e) => setDesc(e.target.value)}
          />
        </div>
        <Button onClick={onSave} disabled={!valid || ops.busy}>
          Save zone settings
        </Button>
      </CardContent>
    </Card>
  );
}

export interface DNSSECCardProps {
  zoneName: string;
  /** A useDnsOps instance used by this card alone, so its error is the DNSSEC reason. */
  ops: UseDnsOpsResult;
}

/**
 * DNSSEC status of a zone (GetDNSSECStatus) and the SignZone control. When the
 * server cannot report a status (no signer configured), the control is gated
 * off and the server's reason is shown.
 */
export function DNSSECCard({ zoneName, ops }: DNSSECCardProps) {
  const { toast } = useToast();
  const [status, setStatus] = useState<DNSSECStatus | null>(null);
  const [loaded, setLoaded] = useState(false);
  const { getDNSSECStatus, signZone } = ops;

  const load = async () => {
    const out = await getDNSSECStatus(zoneName);
    setStatus(out);
    setLoaded(true);
    return out;
  };

  useEffect(() => {
    let cancelled = false;
    void getDNSSECStatus(zoneName).then((out) => {
      if (cancelled) return;
      setStatus(out);
      setLoaded(true);
    });
    return () => {
      cancelled = true;
    };
    // Re-read only when the zone changes; the ops object changes with its busy flag.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [zoneName]);

  const available = loaded && status !== null;
  // The server's reason for an unavailable status. `ops` is this card's own
  // useDnsOps instance, so no other control clears its error.
  const reason = available ? null : ops.error;

  const onSign = async () => {
    const ok = await signZone(zoneName);
    if (!ok) {
      toast({ title: 'Failed to sign zone', variant: 'destructive' });
      return;
    }
    toast({ title: 'Zone signed', variant: 'success' });
    await load();
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>DNSSEC</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div data-testid="dns-dnssec-status" className="space-y-1 text-sm">
          {!loaded && <span className="text-muted-foreground">Loading…</span>}
          {loaded && !status && <span className="text-muted-foreground">Status unavailable</span>}
          {status && (
            <>
              <div className="flex justify-between">
                <span className="text-muted-foreground">State</span>
                <span className="font-medium">{status.zoneSigned ? 'Signed' : 'Unsigned'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Enabled</span>
                <span>{status.enabled ? 'Yes' : 'No'}</span>
              </div>
              {status.algorithm && (
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Algorithm</span>
                  <span className="font-mono">{status.algorithm}</span>
                </div>
              )}
              <div className="flex justify-between">
                <span className="text-muted-foreground">Keys</span>
                <span>{status.keys?.length ?? 0}</span>
              </div>
            </>
          )}
        </div>
        {loaded && !available && (
          <p data-testid="dns-dnssec-reason" className="text-sm text-muted-foreground">
            DNSSEC signing is unavailable on this server{reason ? `: ${reason}` : '.'}
          </p>
        )}
        <Button onClick={onSign} disabled={!available || ops.busy}>
          Sign zone
        </Button>
      </CardContent>
    </Card>
  );
}
