'use client';

import { useState } from 'react';
import { useParams, usePathname, useRouter } from 'next/navigation';
import { resolveDynamicId } from '@/utils/dynamic-route';
import { ArrowLeft, Plus, RefreshCw, Download, Upload } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { DNSRecordTable } from '@/components/features/networking/dns-record-table';
import { DNSRecordForm } from '@/components/features/networking/dns-record-form';
import { useDNS, useApi, useToast } from '@/hooks';
import type { DNSZoneDetail, DNSRecord } from '@/types/infrastructure';
import type { GetZoneResponse } from 'trusted-platform-sdk';
import { readZoneDetail } from '@/lib/dns-wire';

export default function DNSZoneDetailPage() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const [formOpen, setFormOpen] = useState(false);
  const [editingRecord, setEditingRecord] = useState<DNSRecord | undefined>();
  const { toast } = useToast();
  const dns = useDNS();

  const zoneName = resolveDynamicId(params, pathname, 'dns', 'zone');

  // Fetch zone data and transform to UI format
  const {
    data: zoneResponse,
    isLoading,
    refetch: fetchZone,
  } = useApi<GetZoneResponse>(() => dns.getZone(zoneName), [zoneName]);

  // Transform the SDK Zone to the UI DNSZoneDetail format. The api-client
  // unwraps the {payload} envelope, so `zoneResponse` is the protojson
  // GetZoneResponse and the zone is its `zone` field (#445).
  const zone: DNSZoneDetail | null = zoneResponse?.zone ? readZoneDetail(zoneResponse.zone) : null;

  const handleEdit = (record: DNSRecord) => {
    setEditingRecord(record);
    setFormOpen(true);
  };

  const handleFormClose = (open: boolean) => {
    setFormOpen(open);
    if (!open) {
      setEditingRecord(undefined);
    }
  };

  if (isLoading || !zone) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const recordsByType = zone.records.reduce(
    (acc, record) => {
      acc[record.type] = (acc[record.type] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => router.back()}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold font-mono">{zone.name}</h1>
            <p className="text-muted-foreground mt-1">DNS Zone Details</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="icon" onClick={fetchZone} disabled={isLoading}>
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>
          <Button variant="outline">
            <Download className="mr-2 h-4 w-4" />
            Export
          </Button>
          <Button variant="outline">
            <Upload className="mr-2 h-4 w-4" />
            Import
          </Button>
          <Button onClick={() => setFormOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Add Record
          </Button>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Zone Information</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Type</span>
              <Badge
                variant="outline"
                className={
                  zone.type === 'primary'
                    ? 'bg-blue-500/10 text-blue-500 border-blue-500/20'
                    : 'bg-gray-500/10 text-gray-500 border-gray-500/20'
                }
              >
                {zone.type}
              </Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Serial</span>
              <span className="font-mono">{zone.serial}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Refresh</span>
              <span className="font-mono">{zone.refresh}s</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Retry</span>
              <span className="font-mono">{zone.retry}s</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Expire</span>
              <span className="font-mono">{zone.expire}s</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">TTL</span>
              <span className="font-mono">{zone.ttl}s</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Admin Email</span>
              <span className="font-mono text-sm">{zone.adminEmail}</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Record Statistics</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Total Records</span>
              <span className="text-2xl font-bold">{zone.recordCount}</span>
            </div>
            <div className="space-y-2">
              {Object.entries(recordsByType).map(([type, count]) => (
                <div key={type} className="flex items-center justify-between">
                  <span className="text-sm font-medium">{type} Records</span>
                  <span className="font-medium">{count}</span>
                </div>
              ))}
            </div>
            <div className="pt-4 border-t border-border">
              <div className="text-sm text-muted-foreground">Nameservers</div>
              <div className="mt-2 space-y-1">
                {zone.nameservers.map((ns, index) => (
                  <div key={index} className="font-mono text-sm">
                    {ns}
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>DNS Records</CardTitle>
        </CardHeader>
        <CardContent>
          <DNSRecordTable
            zoneName={zoneName}
            records={zone.records}
            onRefresh={fetchZone}
            onEdit={handleEdit}
          />
        </CardContent>
      </Card>

      <DNSRecordForm
        zoneName={zoneName}
        open={formOpen}
        onOpenChange={handleFormClose}
        onSuccess={fetchZone}
        record={editingRecord}
      />
    </div>
  );
}
