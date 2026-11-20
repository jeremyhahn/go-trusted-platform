'use client';

import { useCallback, useEffect, useState } from 'react';
import type { DNSRecord, RecordType } from 'trusted-platform-sdk';
import { Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast, type UseDnsOpsResult } from '@/hooks';

/** Record types whose payload is { name, value, ttl }: the ones this panel adds and edits. */
const VALUE_TYPES = ['A', 'AAAA', 'CNAME', 'NS', 'TXT'] as const;
type ValueType = (typeof VALUE_TYPES)[number];

/** Types the ListRecords filter offers; '' lists every type. */
const FILTER_TYPES = ['', 'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV', 'CAA', 'TLSA'] as const;

interface RecordPayload {
  name: string;
  value?: string;
  ttl?: number;
  [k: string]: unknown;
}

/** Short type (A) of a record whose type may be the protobuf name (RECORD_TYPE_A). */
export function shortType(record: DNSRecord): string {
  return String(record.type).replace(/^RECORD_TYPE_/, '');
}

/** The type-specific payload of a record (record.a for an A record, and so on). */
export function payloadOf(record: DNSRecord): RecordPayload | undefined {
  const key = shortType(record).toLowerCase() as keyof DNSRecord;
  return record[key] as RecordPayload | undefined;
}

function valueRecord(type: ValueType, name: string, value: string, ttl: number): DNSRecord {
  return { type, [type.toLowerCase()]: { name, value, ttl } } as unknown as DNSRecord;
}

function displayValue(p: RecordPayload | undefined): string {
  if (!p) return '';
  if (typeof p.value === 'string') {
    return typeof p.priority === 'number' ? `${p.priority} ${p.value}` : p.value;
  }
  return JSON.stringify(Object.fromEntries(Object.entries(p).filter(([k]) => k !== 'name' && k !== 'ttl')));
}

export interface DNSRecordsPanelProps {
  zoneName: string;
  ops: UseDnsOpsResult;
  /** Called after a write so the zone summary can refresh. */
  onChanged?: () => void;
}

/**
 * Records of a zone, read with ListRecords (optionally filtered by type), with
 * AddRecord, UpdateRecord and DeleteRecord controls (row #2060).
 */
export function DNSRecordsPanel({ zoneName, ops, onChanged }: DNSRecordsPanelProps) {
  const { toast } = useToast();
  const [filter, setFilter] = useState<string>('');
  const [records, setRecords] = useState<DNSRecord[]>([]);
  const [loading, setLoading] = useState(false);

  const [addType, setAddType] = useState<ValueType>('A');
  const [addName, setAddName] = useState('');
  const [addValue, setAddValue] = useState('');
  const [addTTL, setAddTTL] = useState('300');

  const [editing, setEditing] = useState<DNSRecord | null>(null);
  const [editValue, setEditValue] = useState('');
  const [editTTL, setEditTTL] = useState('');
  const [deleting, setDeleting] = useState<DNSRecord | null>(null);

  const { listRecords } = ops;
  const load = useCallback(async () => {
    setLoading(true);
    const out = await listRecords(zoneName, filter ? (filter as RecordType) : undefined);
    setLoading(false);
    if (out) setRecords(out);
  }, [listRecords, zoneName, filter]);

  useEffect(() => {
    let cancelled = false;
    void listRecords(zoneName, filter ? (filter as RecordType) : undefined).then((out) => {
      if (!cancelled && out) setRecords(out);
    });
    return () => {
      cancelled = true;
    };
    // Re-list only on zone or filter change; listRecords is stable.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [zoneName, filter]);

  // The server's message lands in ops.error on the next render; the alert below shows it.
  const fail = (title: string) => toast({ title, variant: 'destructive' });

  const afterWrite = async (title: string) => {
    toast({ title, variant: 'success' });
    await load();
    onChanged?.();
  };

  const onAdd = async () => {
    const ok = await ops.addRecord(zoneName, valueRecord(addType, addName, addValue, Number.parseInt(addTTL, 10) || 300));
    if (!ok) return fail('Failed to add record');
    setAddName('');
    setAddValue('');
    await afterWrite('Record added');
  };

  const onSaveEdit = async () => {
    if (!editing) return;
    const p = payloadOf(editing);
    const type = shortType(editing) as ValueType;
    const next = valueRecord(type, p?.name ?? '', editValue, Number.parseInt(editTTL, 10) || p?.ttl || 300);
    const ok = await ops.updateRecord(zoneName, editing, next);
    if (!ok) return fail('Failed to update record');
    setEditing(null);
    await afterWrite('Record updated');
  };

  const onConfirmDelete = async () => {
    if (!deleting) return;
    const ok = await ops.deleteRecord(zoneName, shortType(deleting) as RecordType, payloadOf(deleting)?.name ?? '');
    if (!ok) return fail('Failed to delete record');
    setDeleting(null);
    await afterWrite('Record deleted');
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>DNS Records</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap items-end gap-2" aria-label="Add record">
          <div className="space-y-1">
            <Label htmlFor="dns-record-add-type">Type</Label>
            <select
              id="dns-record-add-type"
              data-testid="dns-record-add-type"
              className="h-9 rounded-md border border-input bg-background px-2 text-sm"
              value={addType}
              onChange={(e) => setAddType(e.target.value as ValueType)}
            >
              {VALUE_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="dns-record-add-name">Name</Label>
            <Input id="dns-record-add-name" data-testid="dns-record-add-name" value={addName} onChange={(e) => setAddName(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="dns-record-add-value">Value</Label>
            <Input id="dns-record-add-value" data-testid="dns-record-add-value" value={addValue} onChange={(e) => setAddValue(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="dns-record-add-ttl">TTL</Label>
            <Input
              id="dns-record-add-ttl"
              data-testid="dns-record-add-ttl"
              type="number"
              min={1}
              className="w-24"
              value={addTTL}
              onChange={(e) => setAddTTL(e.target.value)}
            />
          </div>
          <Button onClick={onAdd} disabled={!addName || !addValue || ops.busy}>
            Add record
          </Button>
        </div>

        <div className="flex items-center gap-2">
          <Label htmlFor="dns-records-type">Type filter</Label>
          <select
            id="dns-records-type"
            data-testid="dns-records-type"
            className="h-9 rounded-md border border-input bg-background px-2 text-sm"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          >
            {FILTER_TYPES.map((t) => (
              <option key={t || 'all'} value={t}>
                {t || 'All types'}
              </option>
            ))}
          </select>
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
        </div>

        {ops.error && (
          <p role="alert" className="text-sm text-destructive">
            {ops.error}
          </p>
        )}

        <table data-testid="dns-records-list" className="w-full text-sm">
          <thead>
            <tr className="text-left text-muted-foreground">
              <th className="py-1">Type</th>
              <th className="py-1">Name</th>
              <th className="py-1">Value</th>
              <th className="py-1">TTL</th>
              <th className="py-1 sr-only">Actions</th>
            </tr>
          </thead>
          <tbody>
            {records.length === 0 && (
              <tr>
                <td colSpan={5} className="py-2 text-muted-foreground">
                  No records
                </td>
              </tr>
            )}
            {records.map((r, i) => {
              const p = payloadOf(r);
              const type = shortType(r);
              const editable = (VALUE_TYPES as readonly string[]).includes(type);
              const isEditing = editing === r;
              const isDeleting = deleting === r;
              return (
                <tr key={`${type}-${p?.name}-${i}`} className="border-t border-border">
                  <td className="py-1 font-mono">{type}</td>
                  <td className="py-1 font-mono">{p?.name}</td>
                  <td className="py-1 font-mono">
                    {isEditing ? (
                      <Input
                        aria-label="Record value"
                        data-testid="dns-record-edit-value"
                        value={editValue}
                        onChange={(e) => setEditValue(e.target.value)}
                      />
                    ) : (
                      displayValue(p)
                    )}
                  </td>
                  <td className="py-1 font-mono">
                    {isEditing ? (
                      <Input
                        aria-label="Record TTL"
                        data-testid="dns-record-edit-ttl"
                        type="number"
                        className="w-24"
                        value={editTTL}
                        onChange={(e) => setEditTTL(e.target.value)}
                      />
                    ) : (
                      p?.ttl
                    )}
                  </td>
                  <td className="py-1 text-right space-x-1">
                    {isEditing ? (
                      <>
                        <Button size="sm" onClick={onSaveEdit} disabled={ops.busy}>
                          Save record
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => setEditing(null)}>
                          Cancel
                        </Button>
                      </>
                    ) : isDeleting ? (
                      <>
                        <Button size="sm" variant="destructive" onClick={onConfirmDelete} disabled={ops.busy}>
                          Confirm delete
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => setDeleting(null)}>
                          Cancel
                        </Button>
                      </>
                    ) : (
                      <>
                        {editable && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              setDeleting(null);
                              setEditing(r);
                              setEditValue(p?.value ?? '');
                              setEditTTL(String(p?.ttl ?? ''));
                            }}
                          >
                            Edit
                          </Button>
                        )}
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            setEditing(null);
                            setDeleting(r);
                          }}
                        >
                          Delete
                        </Button>
                      </>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}
