'use client';

/**
 * TenantStateCard — find a tenant by name (GetTenantByName on the SDK
 * TenantService, #2067) and show its recorded state. Refusals are shown
 * verbatim, because the control plane's text says why it refused.
 */

import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import { useTenantState, tenantStateLabel } from '@/hooks/use-tenant-state';
import type { Tenant } from 'trusted-platform-sdk';

function badgeVariant(label: string): 'default' | 'destructive' | 'secondary' {
  if (label === 'ACTIVE') return 'default';
  if (label === 'SUSPENDED') return 'destructive';
  return 'secondary';
}

export function TenantStateCard(): JSX.Element {
  const tenants = useTenantState();
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [tenant, setTenant] = useState<Tenant | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const handleFind = async () => {
    const wanted = name.trim();
    if (!wanted) {
      toast({ title: 'Name required', description: 'enter the tenant name', variant: 'destructive' });
      return;
    }
    setBusy(true);
    try {
      const res = await tenants.getByName(wanted);
      if (res.success && res.data) {
        setTenant(res.data.tenant);
        setLookupError(null);
      } else {
        setTenant(null);
        setLookupError(res.error?.message || 'The control plane did not answer with a tenant');
      }
    } catch (err) {
      setTenant(null);
      setLookupError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const label = tenant ? tenantStateLabel(String(tenant.state)) : '';

  return (
    <Card data-testid="tenant-state-card">
      <CardHeader>
        <CardTitle>Tenant state</CardTitle>
        <CardDescription>Find a tenant by name, then suspend or resume it.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-end gap-2">
          <div className="flex-1 space-y-1">
            <Label htmlFor="tenant-state-name-input">Name</Label>
            <Input
              id="tenant-state-name-input"
              aria-label="Tenant name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={busy}
            />
          </div>
          <Button onClick={handleFind} disabled={busy}>
            Find
          </Button>
        </div>

        {lookupError !== null && (
          <p role="alert" className="text-sm text-destructive whitespace-pre-wrap break-words">
            {lookupError}
          </p>
        )}

        {tenant && (
          <div className="space-y-1 text-sm">
            <div>
              <span className="text-muted-foreground">ID: </span>
              <code data-testid="tenant-state-id">{tenant.id}</code>
            </div>
            <div>
              <span className="text-muted-foreground">Name: </span>
              <span data-testid="tenant-state-name">{tenant.displayName || tenant.name}</span>
            </div>
            <div>
              <span className="text-muted-foreground">State: </span>
              <Badge data-testid="tenant-state-badge" variant={badgeVariant(label)}>
                {label}
              </Badge>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
