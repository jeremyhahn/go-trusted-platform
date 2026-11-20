'use client';

import { useState } from 'react';
import type { DNSRecord, RecordType, ResolveResponse } from 'trusted-platform-sdk';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast, type UseDnsOpsResult } from '@/hooks';

const RESOLVE_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV', 'CAA', 'TLSA', 'SOA'] as const;

function recordLine(r: DNSRecord): string {
  const type = String(r.type).replace(/^RECORD_TYPE_/, '');
  const p = (r as unknown as Record<string, { name?: string; value?: string; ttl?: number } | undefined>)[
    type.toLowerCase()
  ];
  if (!p) return type;
  return `${p.name ?? ''} ${p.ttl ?? ''} ${type} ${p.value ?? ''}`.replace(/\s+/g, ' ').trim();
}

export interface DNSRegisterResolveProps {
  ops: UseDnsOpsResult;
  /** Called after a registration so the zone list can refresh. */
  onRegistered?: () => void;
}

/** Register (fqdn -> IP) and Resolve (fqdn + type) controls for the zones page (row #2060). */
export function DNSRegisterResolve({ ops, onRegistered }: DNSRegisterResolveProps) {
  const { toast } = useToast();
  const [regFqdn, setRegFqdn] = useState('');
  const [regIP, setRegIP] = useState('');
  const [resFqdn, setResFqdn] = useState('');
  const [resType, setResType] = useState<RecordType>('A');
  const [result, setResult] = useState<ResolveResponse | null>(null);
  const [resolved, setResolved] = useState(false);

  const onRegister = async () => {
    const ok = await ops.register(regFqdn, regIP);
    if (!ok) {
      toast({ title: 'Failed to register name', variant: 'destructive' });
      return;
    }
    toast({ title: 'Name registered', variant: 'success' });
    onRegistered?.();
  };

  const onResolve = async () => {
    const out = await ops.resolve(resFqdn, resType);
    setResult(out);
    setResolved(true);
  };

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Register Name</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="dns-register-fqdn">FQDN</Label>
            <Input
              id="dns-register-fqdn"
              data-testid="dns-register-fqdn"
              placeholder="host.example.com"
              value={regFqdn}
              onChange={(e) => setRegFqdn(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="dns-register-ip">IP address</Label>
            <Input
              id="dns-register-ip"
              data-testid="dns-register-ip"
              placeholder="192.0.2.1"
              value={regIP}
              onChange={(e) => setRegIP(e.target.value)}
            />
          </div>
          <Button onClick={onRegister} disabled={!regFqdn || !regIP || ops.busy}>
            Register
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Resolve Name</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-end gap-2">
            <div className="flex-1 space-y-1">
              <Label htmlFor="dns-resolve-fqdn">FQDN</Label>
              <Input
                id="dns-resolve-fqdn"
                data-testid="dns-resolve-fqdn"
                placeholder="host.example.com"
                value={resFqdn}
                onChange={(e) => setResFqdn(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="dns-resolve-type">Type</Label>
              <select
                id="dns-resolve-type"
                data-testid="dns-resolve-type"
                className="h-9 rounded-md border border-input bg-background px-2 text-sm"
                value={resType}
                onChange={(e) => setResType(e.target.value as RecordType)}
              >
                {RESOLVE_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <Button onClick={onResolve} disabled={!resFqdn || ops.busy}>
            Resolve
          </Button>
          <div data-testid="dns-resolve-results" className="space-y-1 font-mono text-sm">
            {resolved && !result && <p className="text-destructive">{ops.error ?? 'Resolution failed'}</p>}
            {result && (result.records ?? []).length === 0 && <p className="text-muted-foreground">No records</p>}
            {(result?.records ?? []).map((r, i) => <div key={i}>{recordLine(r)}</div>)}
            {result && (
              <p className="text-xs text-muted-foreground">{result.authoritative ? 'Authoritative' : 'Not authoritative'}</p>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
