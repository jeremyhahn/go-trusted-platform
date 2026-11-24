'use client';

import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Gated } from '@/components/features/capabilities/gated';
import { useCompute } from '@/hooks';
import { useToast } from '@/hooks/use-toast';
import type { VMDisk } from '@/types/infrastructure';

const ATTACH_OP = 'POST /api/v1/compute/vms/{id}/disks';
const RESIZE_OP = 'PATCH /api/v1/compute/vms/{id}/disks/{diskId}';
const DETACH_OP = 'DELETE /api/v1/compute/vms/{id}/disks/{diskId}';

export interface VMDisksCardProps {
  vmId: string;
  disks: VMDisk[];
  onChanged?: () => void;
}

interface Outcome {
  success?: boolean;
  error?: unknown;
}

function errorText(err: unknown): string {
  if (typeof err === 'string') {
    return err;
  }
  if (err && typeof err === 'object' && 'message' in err && typeof err.message === 'string') {
    return err.message;
  }
  return 'the control plane refused the disk change';
}

/** positiveInt answers the integer in text when it is above zero, else undefined. */
function positiveInt(text: string): number | undefined {
  const trimmed = text.trim();
  if (!/^\d+$/.test(trimmed)) {
    return undefined;
  }
  const n = Number(trimmed);
  return n > 0 ? n : undefined;
}

/**
 * VMDisksCard lists a VM's disks and sends AttachDisk, ResizeDisk and
 * DetachDisk through the SDK ComputeService, each control behind the
 * server's capability gate (#2044).
 */
export function VMDisksCard({ vmId, disks, onChanged }: VMDisksCardProps) {
  const compute = useCompute();
  const { toast } = useToast();
  const [attachOpen, setAttachOpen] = useState(false);
  const [path, setPath] = useState('');
  const [size, setSize] = useState('');
  const [newSizes, setNewSizes] = useState<Record<string, string>>({});
  const [confirming, setConfirming] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const run = async (title: string, done: string, call: () => Promise<Outcome | undefined>): Promise<boolean> => {
    if (pending) {
      return false;
    }
    setPending(true);
    try {
      const res = await call();
      if (res && res.success === false) {
        toast({ title: `${title} failed`, description: errorText(res.error), variant: 'destructive' });
        return false;
      }
      toast({ title, description: done, variant: 'success' });
      onChanged?.();
      return true;
    } catch (err) {
      toast({ title: `${title} failed`, description: errorText(err), variant: 'destructive' });
      return false;
    } finally {
      setPending(false);
    }
  };

  const handleAttach = async () => {
    const diskPath = path.trim();
    const sizeGb = positiveInt(size);
    if (!diskPath || sizeGb === undefined) {
      return;
    }
    const attached = await run('Disk attached', `Attached ${diskPath}`, () =>
      compute.attachDisk({ vmId, disk: { path: diskPath, sizeGb } }),
    );
    if (attached) {
      setAttachOpen(false);
      setPath('');
      setSize('');
    }
  };

  const handleResize = async (diskId: string) => {
    const newSizeGb = positiveInt(newSizes[diskId] ?? '');
    if (newSizeGb === undefined) {
      return;
    }
    const resized = await run('Disk resized', `Resized ${diskId} to ${newSizeGb} GB`, () =>
      compute.resizeDisk({ vmId, diskId, newSizeGb }),
    );
    if (resized) {
      setNewSizes((prev) => ({ ...prev, [diskId]: '' }));
    }
  };

  const handleDetach = async (diskId: string) => {
    if (confirming !== diskId) {
      setConfirming(diskId);
      return;
    }
    setConfirming(null);
    await run('Disk detached', `Detached ${diskId}`, () => compute.detachDisk({ vmId, diskId }));
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Disks</CardTitle>
        <Gated op={ATTACH_OP}>
          <Button variant="outline" size="sm" onClick={() => setAttachOpen((open) => !open)}>
            Attach disk
          </Button>
        </Gated>
      </CardHeader>
      <CardContent className="space-y-4">
        {attachOpen && (
          <form
            className="flex flex-wrap items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void handleAttach();
            }}
          >
            <div className="space-y-1">
              <Label htmlFor={`attach-disk-path-${vmId}`}>Disk path</Label>
              <Input
                id={`attach-disk-path-${vmId}`}
                aria-label="Disk path"
                value={path}
                onChange={(e) => setPath(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor={`attach-disk-size-${vmId}`}>Size (GB)</Label>
              <Input
                id={`attach-disk-size-${vmId}`}
                type="number"
                min={1}
                aria-label="Size (GB)"
                value={size}
                onChange={(e) => setSize(e.target.value)}
              />
            </div>
            <Gated op={ATTACH_OP}>
              <Button type="submit" disabled={pending}>
                Attach
              </Button>
            </Gated>
          </form>
        )}
        {disks.length === 0 ? (
          <p className="text-sm text-muted-foreground">No disks attached</p>
        ) : (
          <ul className="space-y-3">
            {disks.map((disk) => (
              <li key={disk.id} className="flex flex-wrap items-center gap-3">
                <span className="font-mono text-sm">{disk.path}</span>
                <span className="text-sm text-muted-foreground">{disk.type}</span>
                <span className="text-sm">{`${disk.sizeMB / 1024} GB`}</span>
                {disk.readonly && <Badge variant="secondary">readonly</Badge>}
                {disk.boot && <Badge variant="secondary">boot</Badge>}
                <Input
                  className="w-28"
                  type="number"
                  min={1}
                  aria-label={`New size (GB) for ${disk.id}`}
                  value={newSizes[disk.id] ?? ''}
                  onChange={(e) => setNewSizes((prev) => ({ ...prev, [disk.id]: e.target.value }))}
                />
                <Gated op={RESIZE_OP}>
                  <Button variant="outline" size="sm" disabled={pending} onClick={() => void handleResize(disk.id)}>
                    Resize
                  </Button>
                </Gated>
                {!disk.boot && (
                  <Gated op={DETACH_OP}>
                    <Button
                      variant={confirming === disk.id ? 'destructive' : 'outline'}
                      size="sm"
                      disabled={pending}
                      onClick={() => void handleDetach(disk.id)}
                    >
                      {confirming === disk.id ? 'Confirm detach' : 'Detach'}
                    </Button>
                  </Gated>
                )}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
