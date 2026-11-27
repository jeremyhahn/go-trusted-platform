'use client';

/**
 * DNS Zones Page
 *
 * Displays all DNS zones with management capabilities.
 * Uses the trusted-platform-sdk for API interactions.
 * Add Zone and the dialog's Create are gated on the server's
 * POST /api/v1/dns/zones capability (#2033). The zone list and Refresh
 * are gated on GET /api/v1/dns/zones: when the server does not offer it the
 * page reads nothing and says DNS is not enabled on this server (#2033).
 */

import { useMemo, useState } from 'react';
import { Loader2, Plus, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Gated } from '@/components/features/capabilities/gated';
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
import { DNSZoneTable } from '@/components/features/networking/dns-zone-table';
import { useDNS, useApi, useToast } from '@/hooks';
import { DNSLookupCard } from '@/components/features/networking/dns-lookup-card';
import type { DNSZone } from '@/types/infrastructure';
import { readZone } from '@/lib/dns-wire';
import { Gated } from '@/components/features/capabilities/gated';
import { useCapabilities } from '@/hooks/use-capabilities';

export default function DNSZonesPage() {
  const { toast } = useToast();
  const dns = useDNS();
  const { loading: capsLoading, capability } = useCapabilities();
  const listCap = capability('GET /api/v1/dns/zones');
  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState('');
  const [createTTL, setCreateTTL] = useState('3600');
  const [createInternal, setCreateInternal] = useState(true);
  const [createSubmitting, setCreateSubmitting] = useState(false);

  // Fetch DNS zones using SDK
  const {
    data: zonesData,
    isLoading: loading,
    refetch: fetchZones,
  } = useApi(
    () => dns.listZones(),
    [],
    {
      enabled: !capsLoading && listCap.enabled,
      onError: (err) => {
        toast({
          title: 'Error',
          description: `Failed to fetch DNS zones: ${err.message}`,
          variant: 'destructive',
        });
      },
    }
  );

  // Each zone is the proto Zone in protojson (#445). It carries no
  // timestamps, so the table renders "—" for them; never fall back to
  // `new Date()` — that made every zone look freshly minted on every render.
  const zones: DNSZone[] = useMemo(() => (zonesData?.zones ?? []).map(readZone), [zonesData]);

  const stats = {
    total: zones.length,
    primary: zones.filter((z) => z.type === 'primary').length,
    secondary: zones.filter((z) => z.type === 'secondary').length,
    records: zones.reduce((sum, z) => sum + z.recordCount, 0),
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">DNS Zones</h1>
          <p className="text-muted-foreground mt-1">
            Manage DNS zones and records
          </p>
        </div>
        <div className="flex gap-2">
          <Gated op="GET /api/v1/dns/zones">
            <Button variant="outline" size="icon" onClick={() => fetchZones()} disabled={loading}>
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            </Button>
          </Gated>
          <Gated op="POST /api/v1/dns/zones">
            <Button onClick={() => setCreateOpen(true)}>
              <Plus className="mr-2 h-4 w-4" />
              Add Zone
            </Button>
          </Gated>
        </div>
      </div>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add DNS Zone</DialogTitle>
            <DialogDescription>
              Create a new authoritative DNS zone.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="zone-name">Zone Name *</Label>
              <Input
                id="zone-name"
                value={createName}
                onChange={(e) => setCreateName(e.target.value)}
                placeholder="example.com"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="zone-ttl">Default TTL (seconds)</Label>
              <Input
                id="zone-ttl"
                type="number"
                min={60}
                value={createTTL}
                onChange={(e) => setCreateTTL(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-2">
              <input
                id="zone-internal"
                type="checkbox"
                checked={createInternal}
                onChange={(e) => setCreateInternal(e.target.checked)}
              />
              <Label htmlFor="zone-internal">Internal (split-horizon)</Label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Gated op="POST /api/v1/dns/zones">
              <Button
                disabled={!createName || createSubmitting}
                onClick={async () => {
                  setCreateSubmitting(true);
                  try {
                    await dns.createZone({
                      name: createName.endsWith('.') ? createName : `${createName}.`,
                      ttl: Number.parseInt(createTTL, 10) || 3600,
                      internal: createInternal,
                    });
                    toast({ title: 'Zone created', variant: 'success' });
                    setCreateOpen(false);
                    setCreateName('');
                    fetchZones();
                  } catch (err) {
                    toast({
                      title: 'Failed to create zone',
                      description: err instanceof Error ? err.message : 'Unknown error',
                      variant: 'destructive',
                    });
                  } finally {
                    setCreateSubmitting(false);
                  }
                }}
              >
                {createSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Create
              </Button>
            </Gated>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {!capsLoading && !listCap.enabled ? (
        <div data-testid="dns-not-enabled" className="rounded-lg border border-border bg-card p-6">
          <div className="font-medium">DNS is not enabled on this server</div>
          <p className="text-sm text-muted-foreground mt-1">{listCap.reason}</p>
        </div>
      ) : null}

      <div className="grid gap-4 md:grid-cols-4">
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Total Zones</div>
          <div className="text-3xl font-bold mt-2">{stats.total}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Primary</div>
          <div className="text-3xl font-bold mt-2 text-blue-500">{stats.primary}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Secondary</div>
          <div className="text-3xl font-bold mt-2 text-gray-500">
            {stats.secondary}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Total Records</div>
          <div className="text-3xl font-bold mt-2">{stats.records}</div>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <DNSZoneTable zones={zones} onRefresh={() => fetchZones()} />
      )}
      <DNSLookupCard onRegistered={() => fetchZones()} />
    </div>
  );
}
