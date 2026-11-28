'use client';

/**
 * TenantQuotaCheck asks the server whether the tenant's quota has room for an
 * amount of one resource (POST /api/v1/tenants/{id}/quota-check, through the
 * SDK's TenantService.checkQuota), in the capability gate on that op (#2067).
 */

import { useState } from 'react';

import { Gated } from '@/components/features/capabilities/gated';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useTenant } from '@/hooks';

/** The resources the tenant manager checks (pkg/tenant/quota/types.go). */
export const QUOTA_CHECK_RESOURCES = [
  'vms',
  'containers',
  'vcpus',
  'memory',
  'disk',
  'bridges',
  'ports',
  'bandwidth',
  'snapshots',
] as const;

interface CheckAnswer {
  available: boolean;
  message?: string;
}

export function TenantQuotaCheck({ tenantId }: { tenantId: string }) {
  const tenant = useTenant();
  const [resource, setResource] = useState<string>(QUOTA_CHECK_RESOURCES[0]);
  const [amount, setAmount] = useState('1');
  const [busy, setBusy] = useState(false);
  const [answer, setAnswer] = useState<CheckAnswer | null>(null);
  const [error, setError] = useState<string | null>(null);

  const parsed = Number(amount);
  const amountValid = Number.isInteger(parsed) && parsed >= 1;

  const check = async () => {
    setBusy(true);
    setError(null);
    setAnswer(null);
    try {
      const res = await tenant.checkQuota({ tenantId, resource, amount: parsed });
      if (res.success && res.data) {
        setAnswer({ available: Boolean(res.data.available), message: res.data.message });
      } else {
        setError(res.error?.message ?? 'request failed');
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'request failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Check quota</CardTitle>
        <CardDescription>Ask whether the tenant&apos;s quota has room for an amount of one resource.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap items-end gap-4">
          <div className="space-y-1">
            <Label htmlFor="tenant-quota-check-resource">Resource</Label>
            <select
              id="tenant-quota-check-resource"
              className="flex h-10 rounded-md border border-input bg-background px-3 py-2 text-sm"
              value={resource}
              onChange={(e) => setResource(e.target.value)}
            >
              {QUOTA_CHECK_RESOURCES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="tenant-quota-check-amount">Amount</Label>
            <Input
              id="tenant-quota-check-amount"
              type="number"
              min={1}
              step={1}
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
            />
          </div>
          <Gated op="POST /api/v1/tenants/{id}/quota-check">
            <Button disabled={busy || !amountValid} onClick={() => void check()}>
              Check quota
            </Button>
          </Gated>
        </div>

        <div data-testid="tenant-quota-check-result" className="text-sm">
          {answer &&
            (answer.available ? (
              <span>Available{answer.message ? `: ${answer.message}` : ''}</span>
            ) : (
              <span className="text-destructive">{answer.message || 'Not available'}</span>
            ))}
          {error && (
            <span role="alert" className="text-destructive">
              {error}
            </span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
