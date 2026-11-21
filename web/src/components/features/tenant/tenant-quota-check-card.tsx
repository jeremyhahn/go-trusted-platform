'use client';

/**
 * TenantQuotaCheckCard — asks the control plane's CheckQuota whether an
 * amount of a resource fits the tenant's quota (#2067).
 *
 * A quota refusal is an answer (`available: false`) and shows as "Over
 * quota"; a request the control plane refuses (an unknown resource, a bad
 * amount) is shown verbatim.
 */

import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';
import { QUOTA_RESOURCES, useTenantChecks, type QuotaCheckResult } from '@/hooks/use-tenant-checks';

export function TenantQuotaCheckCard({ tenantId }: { tenantId: string }): JSX.Element {
  const checks = useTenantChecks();
  const { toast } = useToast();
  const [resource, setResource] = useState<string>('vms');
  const [amount, setAmount] = useState('1');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<QuotaCheckResult | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);

  const handleCheck = async () => {
    const trimmed = amount.trim();
    if (!/^\d+$/.test(trimmed) || Number(trimmed) <= 0) {
      toast({ title: 'Invalid amount', description: 'the amount is a whole number above 0', variant: 'destructive' });
      return;
    }
    setBusy(true);
    setRefusal(null);
    try {
      const res = await checks.checkQuota(tenantId, resource, Number(trimmed));
      if (res.success && res.data) {
        setResult(res.data);
      } else {
        setResult(null);
        setRefusal(res.error?.message || 'The control plane did not answer the quota check');
      }
    } catch (err) {
      setResult(null);
      setRefusal(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="tenant-quota-check-card">
      <CardHeader>
        <CardTitle>Check quota</CardTitle>
        <CardDescription>Does this amount fit tenant {tenantId}&apos;s quota?</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <select
            aria-label="Resource"
            className="h-10 rounded-md border border-input bg-background px-3 text-sm"
            value={resource}
            onChange={(e) => setResource(e.target.value)}
          >
            {QUOTA_RESOURCES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          <Input
            aria-label="Amount"
            inputMode="numeric"
            className="w-32"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
          />
          <Button onClick={handleCheck} disabled={busy}>
            Check
          </Button>
        </div>
        {result && (
          <div className="flex items-center gap-2">
            <Badge data-testid="quota-check-verdict" variant={result.available ? 'default' : 'destructive'}>
              {result.available ? 'Fits' : 'Over quota'}
            </Badge>
            <span className="text-sm text-muted-foreground" data-testid="quota-check-message">
              {result.message}
            </span>
          </div>
        )}
        {refusal !== null && (
          <p role="alert" className="text-sm text-destructive whitespace-pre-wrap break-words">
            {refusal}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
