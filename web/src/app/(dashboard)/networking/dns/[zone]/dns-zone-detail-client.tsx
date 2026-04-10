'use client';

import { useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, Plus, RefreshCw, Download, Upload } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { DNSRecordTable } from '@/components/features/networking/dns-record-table';
import { DNSRecordForm } from '@/components/features/networking/dns-record-form';
import { useDNS, useApi, useToast } from '@/hooks';
import type { DNSZoneDetail, DNSRecord } from '@/types/infrastructure';
import type { GetZoneResponse, Zone, RecordSet, DNSRecord as SDKDNSRecord } from 'trusted-platform-sdk';

// Transform SDK Zone to UI DNSZoneDetail format
function transformZoneToDetail(zone: Zone): DNSZoneDetail {
  const records: DNSRecord[] = [];
  const recordSet = zone.records;

  // Helper to create UI record format
  const createRecord = (name: string, type: DNSRecord['type'], value: string, ttl: number, extra?: Partial<DNSRecord>): DNSRecord => ({
    id: `${type}-${name}-${value}`,
    name,
    type,
    value,
    ttl,
    ...extra,
  });

  // Transform record set to flat array
  if (recordSet) {
    // A records
    recordSet.aRecords?.forEach((r) => {
      records.push(createRecord(r.name, 'A', r.value, r.ttl));
    });

    // AAAA records
    recordSet.aaaaRecords?.forEach((r) => {
      records.push(createRecord(r.name, 'AAAA', r.value, r.ttl));
    });

    // CNAME records
    recordSet.cnameRecords?.forEach((r) => {
      records.push(createRecord(r.name, 'CNAME', r.value, r.ttl));
    });

    // MX records
    recordSet.mxRecords?.forEach((r) => {
      records.push(createRecord(r.name, 'MX', r.value, r.ttl, { priority: r.priority }));
    });

    // TXT records
    recordSet.txtRecords?.forEach((r) => {
      records.push(createRecord(r.name, 'TXT', r.value, r.ttl));
    });

    // NS records
    recordSet.nsRecords?.forEach((r) => {
      records.push(createRecord(r.name, 'NS', r.value, r.ttl));
    });

    // SOA record
    if (recordSet.soa) {
      const soa = recordSet.soa;
      records.push(createRecord(soa.name, 'SOA', `${soa.mname} ${soa.rname} ${soa.serial}`, soa.ttl));
    }
  }

  // Extract SOA data for zone details
  const soa = recordSet?.soa;
  const nsRecords = recordSet?.nsRecords || [];

  return {
    id: String(zone.id),
    name: zone.name,
    type: 'primary' as const, // Default to primary
    recordCount: records.length,
    serial: soa?.serial || 0,
    refresh: soa?.refresh || 3600,
    retry: soa?.retry || 600,
    expire: soa?.expire || 604800,
    ttl: zone.ttl,
    createdAt: new Date().toISOString(), // SDK doesn't provide timestamps
    updatedAt: new Date().toISOString(),
    nameservers: nsRecords.map((ns) => ns.value),
    adminEmail: soa?.rname || 'admin@' + zone.name,
    records,
  };
}

export default function DNSZoneDetailPage() {
  const params = useParams();
  const router = useRouter();
  const [formOpen, setFormOpen] = useState(false);
  const [editingRecord, setEditingRecord] = useState<DNSRecord | undefined>();
  const { toast } = useToast();
  const dns = useDNS();

  const zoneName = decodeURIComponent(params.zone as string);

  // Fetch zone data and transform to UI format
  const {
    data: zoneResponse,
    isLoading,
    refetch: fetchZone,
  } = useApi<GetZoneResponse>(() => dns.getZone(zoneName), [zoneName]);

  // Transform SDK Zone to UI DNSZoneDetail format
  const zone: DNSZoneDetail | null = zoneResponse?.zone
    ? transformZoneToDetail(zoneResponse.zone)
    : null;

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
