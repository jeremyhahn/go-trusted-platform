'use client';

import { useState } from 'react';
import type { DNSRecord, ResolveRequest, ResolveResponse } from 'trusted-platform-sdk';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks';
import { useDNSLookup } from '@/hooks/use-dns-lookup';

const RECORD_TYPES: ResolveRequest['type'][] = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV', 'CAA', 'TLSA'];

function errorMessage(err: unknown): string {
  if (err !== null && typeof err === 'object' && 'message' in err) {
    const message = (err as { message: unknown }).message;
    if (typeof message === 'string') {
      return message;
    }
  }
  return 'Unknown error';
}

/** One resolved record as "<TYPE> <name> <value>" (the type without its RECORD_TYPE_ prefix). */
function describeRecord(record: DNSRecord): string {
  const type = String(record.type).replace(/^RECORD_TYPE_/, '');
  const body = (record.a ??
    record.aaaa ??
    record.cname ??
    record.mx ??
    record.ns ??
    record.txt ??
    record.srv ??
    record.caa ??
    record.tlsa) as { name?: string; value?: string } | undefined;
  return [type, body?.name ?? '', body?.value ?? ''].filter(Boolean).join(' ');
}

/**
 * Resolve a name against the managed zones (client.dns.resolve) and register
 * a host name (client.dns.register) (#2060).
 */
export function DNSLookupCard({ onRegistered }: { onRegistered?: () => void }) {
  const { resolve, isResolving, register, isRegistering } = useDNSLookup();
  const { toast } = useToast();

  const [fqdn, setFqdn] = useState('');
  const [type, setType] = useState<ResolveRequest['type']>('A');
  const [result, setResult] = useState<ResolveResponse | undefined>(undefined);
  const [resolveError, setResolveError] = useState<string | undefined>(undefined);

  const [hostName, setHostName] = useState('');
  const [ip, setIp] = useState('');

  const handleResolve = async () => {
    try {
      const res = await resolve({ fqdn, type });
      setResult(res);
      setResolveError(undefined);
    } catch (err) {
      setResolveError(errorMessage(err));
      setResult(undefined);
    }
  };

  const handleRegister = async () => {
    try {
      await register({ fqdn: hostName, ip });
      toast({ title: 'Registered', description: `${hostName} -> ${ip}`, variant: 'success' });
      setHostName('');
      setIp('');
      onRegistered?.();
    } catch (err) {
      toast({ title: 'Failed to register', description: errorMessage(err), variant: 'destructive' });
    }
  };

  const records = result?.records ?? [];

  return (
    <Card data-testid="dns-lookup-card">
      <CardHeader>
        <CardTitle>Resolve and register</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-[1fr_auto_auto] sm:items-end">
            <div className="space-y-2">
              <Label htmlFor="dns-resolve-fqdn">Name</Label>
              <Input
                id="dns-resolve-fqdn"
                value={fqdn}
                onChange={(e) => setFqdn(e.target.value)}
                placeholder="www.example.com."
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="dns-resolve-type">Type</Label>
              <select
                id="dns-resolve-type"
                value={type}
                onChange={(e) => setType(e.target.value as ResolveRequest['type'])}
                className="flex h-10 rounded-md border border-input bg-background px-3 py-2 text-sm"
              >
                {RECORD_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>
            <Button onClick={handleResolve} disabled={fqdn === '' || isResolving}>
              Resolve
            </Button>
          </div>
          {resolveError !== undefined && (
            <p data-testid="dns-resolve-error" className="text-sm text-destructive">
              Resolve failed: {resolveError}
            </p>
          )}
          {result && (
            <div className="space-y-2">
              <Badge data-testid="dns-resolve-authoritative" variant="outline">
                {result.authoritative ? 'Authoritative' : 'Not authoritative'}
              </Badge>
              {records.length === 0 ? (
                <p data-testid="dns-resolve-empty" className="text-sm text-muted-foreground">
                  No records
                </p>
              ) : (
                records.map((r, index) => (
                  <div key={index} data-testid="dns-resolve-record" className="font-mono text-sm">
                    {describeRecord(r)}
                  </div>
                ))
              )}
            </div>
          )}
        </div>
        <div className="grid gap-3 border-t border-border pt-4 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
          <div className="space-y-2">
            <Label htmlFor="dns-register-fqdn">Host name</Label>
            <Input id="dns-register-fqdn" value={hostName} onChange={(e) => setHostName(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="dns-register-ip">IP address</Label>
            <Input
              id="dns-register-ip"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="10.0.0.10"
            />
          </div>
          <Button onClick={handleRegister} disabled={hostName === '' || ip === '' || isRegistering}>
            Register
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
