'use client';

/**
 * DNS Zones Page
 *
 * Displays all DNS zones with management capabilities.
 * Uses the trusted-platform-sdk for API interactions.
 */

import { useMemo } from 'react';
import { Plus, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { DNSZoneTable } from '@/components/features/networking/dns-zone-table';
import { useDNS, useApi, useToast } from '@/hooks';
import type { DNSZone } from '@/types/infrastructure';

export default function DNSZonesPage() {
  const { toast } = useToast();
  const dns = useDNS();

  // Fetch DNS zones using SDK
  const {
    data: zonesData,
    isLoading: loading,
    refetch: fetchZones,
  } = useApi(
    () => dns.listZones(),
    [],
    {
      onError: (err) => {
        toast({
          title: 'Error',
          description: `Failed to fetch DNS zones: ${err.message}`,
          variant: 'destructive',
        });
      },
    }
  );

  // Transform SDK zones to local DNSZone type for UI compatibility
  const zones: DNSZone[] = useMemo(() => {
    if (!zonesData?.zones) return [];
    return zonesData.zones.map((zone) => ({
      id: String(zone.id),
      name: zone.name,
      type: (zone.internal ? 'primary' : 'secondary') as DNSZone['type'],
      status: 'active',
      recordCount: zone.records ? Object.keys(zone.records).reduce((count, key) => {
        const records = zone.records?.[key as keyof typeof zone.records];
        return count + (Array.isArray(records) ? records.length : (records ? 1 : 0));
      }, 0) : 0,
      ttl: zone.ttl || 3600,
      serial: zone.records?.soa?.serial || 0,
      refresh: zone.records?.soa?.refresh || 3600,
      retry: zone.records?.soa?.retry || 600,
      expire: zone.records?.soa?.expire || 604800,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }));
  }, [zonesData]);

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
          <Button variant="outline" size="icon" onClick={() => fetchZones()} disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
          <Button>
            <Plus className="mr-2 h-4 w-4" />
            Add Zone
          </Button>
        </div>
      </div>

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
    </div>
  );
}
