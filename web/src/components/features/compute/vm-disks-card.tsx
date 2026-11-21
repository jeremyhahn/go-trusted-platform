'use client';

import { useCallback, useEffect, useState, type FormEvent } from 'react';
import type { DiskBus, DiskConfig, DiskType } from 'trusted-platform-sdk';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
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
import { DISK_BUSES, DISK_TYPES, diskEnumLabel, parseSizeGb, useVMDisks } from '@/hooks/use-vm-disks';

type Refusal = { success: boolean; error?: { message?: string } };

const selectClass =
  'flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm';

/** The disks of one VM: attach, resize (grow only) and detach behind a confirm. */
export function VMDisksCard({ vmId }: { vmId: string }) {
  const disks = useVMDisks(vmId);
  const [list, setList] = useState<DiskConfig[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [path, setPath] = useState('');
  const [type, setType] = useState<DiskType>('DISK_TYPE_QCOW2');
  const [bus, setBus] = useState<DiskBus>('DISK_BUS_VIRTIO');
  const [size, setSize] = useState('');
  const [resizeTo, setResizeTo] = useState<Record<string, string>>({});
  const [detaching, setDetaching] = useState<DiskConfig | null>(null);

  const load = useCallback(async () => {
    const res = await disks.listDisks();
    if (res.success) {
      setList(res.data ?? []);
    } else {
      setError(res.error?.message ?? 'Could not read the disks.');
    }
  }, [disks]);

  useEffect(() => {
    void load();
  }, [load]);

  const run = async (call: () => Promise<Refusal>) => {
    setBusy(true);
    setError(null);
    try {
      const res = await call();
      if (!res.success) {
        setError(res.error?.message ?? 'The request was refused.');
        return false;
      }
      await load();
      return true;
    } finally {
      setBusy(false);
    }
  };

  const onAttach = async (e: FormEvent) => {
    e.preventDefault();
    const sizeGb = parseSizeGb(size);
    if (!path.trim()) {
      setFormError('A disk path is required.');
      return;
    }
    if (sizeGb === null) {
      setFormError('The size must be a whole number of GB, at least 1.');
      return;
    }
    setFormError(null);
    const done = await run(() => disks.attach({ path: path.trim(), type, bus, sizeGb }));
    if (done) {
      setPath('');
      setSize('');
    }
  };

  const onResize = async (disk: DiskConfig) => {
    const id = disk.id ?? '';
    const n = parseSizeGb(resizeTo[id] ?? '');
    if (n === null || n <= Number(disk.sizeGb ?? 0)) {
      setFormError('A disk can only grow.');
      return;
    }
    setFormError(null);
    const done = await run(() => disks.resize(id, n));
    if (done) setResizeTo((m) => ({ ...m, [id]: '' }));
  };

  const onDetach = async () => {
    const disk = detaching;
    if (!disk?.id) return;
    const id = disk.id;
    setDetaching(null);
    await run(() => disks.detach(id));
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Disks</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <Alert variant="destructive" data-testid="vm-disks-error">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {formError && (
          <p className="text-sm text-destructive" data-testid="vm-disk-form-error">
            {formError}
          </p>
        )}

        {list !== null && list.length === 0 && (
          <p className="text-sm text-muted-foreground" data-testid="vm-disks-empty">
            No disks attached.
          </p>
        )}
        {list !== null && list.length > 0 && (
          <table className="w-full text-sm" data-testid="vm-disks-table">
            <thead>
              <tr className="text-left text-muted-foreground">
                <th className="py-1">Path</th>
                <th className="py-1">Type</th>
                <th className="py-1">Bus</th>
                <th className="py-1">Size</th>
                <th className="py-1" />
              </tr>
            </thead>
            <tbody>
              {list.map((disk) => {
                const id = disk.id ?? disk.path;
                return (
                  <tr key={id} data-testid={`vm-disk-${id}`} className="border-t">
                    <td className="py-1 font-mono">{disk.path}</td>
                    <td className="py-1">{diskEnumLabel(disk.type)}</td>
                    <td className="py-1">{diskEnumLabel(disk.bus)}</td>
                    <td className="py-1">{`${disk.sizeGb ?? 0} GB`}</td>
                    <td className="py-1">
                      <div className="flex items-center justify-end gap-2">
                        <Input
                          className="w-24"
                          aria-label={`New size of ${disk.path} in GB`}
                          inputMode="numeric"
                          data-testid={`vm-disk-resize-${id}`}
                          value={resizeTo[id] ?? ''}
                          onChange={(e) => setResizeTo((m) => ({ ...m, [id]: e.target.value }))}
                        />
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={busy}
                          data-testid={`vm-disk-resize-apply-${id}`}
                          onClick={() => void onResize(disk)}
                        >
                          Resize
                        </Button>
                        <Button
                          size="sm"
                          variant="destructive"
                          disabled={busy}
                          data-testid={`vm-disk-detach-${id}`}
                          onClick={() => setDetaching(disk)}
                        >
                          Detach
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        <form className="grid gap-3 sm:grid-cols-5 sm:items-end" data-testid="vm-disk-attach-form" onSubmit={onAttach} noValidate>
          <div className="space-y-1 sm:col-span-2">
            <Label htmlFor="vm-disk-path">Path</Label>
            <Input
              id="vm-disk-path"
              data-testid="vm-disk-path"
              value={path}
              onChange={(e) => setPath(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="vm-disk-type">Type</Label>
            <select
              id="vm-disk-type"
              className={selectClass}
              data-testid="vm-disk-type"
              value={type}
              onChange={(e) => setType(e.target.value as DiskType)}
            >
              {DISK_TYPES.map((t) => (
                <option key={t} value={t}>
                  {diskEnumLabel(t)}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="vm-disk-bus">Bus</Label>
            <select
              id="vm-disk-bus"
              className={selectClass}
              data-testid="vm-disk-bus"
              value={bus}
              onChange={(e) => setBus(e.target.value as DiskBus)}
            >
              {DISK_BUSES.map((b) => (
                <option key={b} value={b}>
                  {diskEnumLabel(b)}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="vm-disk-size">Size (GB)</Label>
            <Input
              id="vm-disk-size"
              inputMode="numeric"
              data-testid="vm-disk-size"
              value={size}
              onChange={(e) => setSize(e.target.value)}
            />
          </div>
          <div className="sm:col-span-5">
            <Button type="submit" disabled={busy} data-testid="vm-disk-attach">
              Attach
            </Button>
          </div>
        </form>

        <Dialog open={detaching !== null} onOpenChange={(open) => !open && setDetaching(null)}>
          <DialogContent data-testid="vm-disk-detach-dialog">
            <DialogHeader>
              <DialogTitle>Detach this disk?</DialogTitle>
              <DialogDescription>
                {`${detaching?.path ?? ''} is detached from this VM. The VM loses access to it.`}
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDetaching(null)}>
                Cancel
              </Button>
              <Button variant="destructive" data-testid="vm-disk-detach-confirm" onClick={() => void onDetach()}>
                Detach
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}
