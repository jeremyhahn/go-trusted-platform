'use client';

/**
 * KmsKeyAdminCard — change a KMS key's status (UpdateKeyStatus) and import
 * base64 key material as a new key (ImportKey), #2057.
 *
 * A disabled or compromised key refuses every operation, so every status but
 * ENABLED asks first. A refusal from the control plane is toasted verbatim,
 * and a refused import keeps every field.
 */

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
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
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks';
import {
  IMPORT_ALGORITHMS,
  KEY_STATUSES,
  useKmsKeyAdmin,
  type ImportKeyInput,
  type ImportKeyResult,
  type KeyStatus,
} from '@/hooks/use-kms-key-admin';

const SELECT_CLASS =
  'flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring';

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function KmsKeyAdminCard(): JSX.Element {
  const admin = useKmsKeyAdmin();
  const { toast } = useToast();

  const [key, setKey] = useState('');
  const [status, setStatus] = useState<KeyStatus>('ENABLED');
  const [versionText, setVersionText] = useState('');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  const [importName, setImportName] = useState('');
  const [algorithm, setAlgorithm] = useState<string>('AES-256-GCM');
  const [material, setMaterial] = useState('');
  const [usageText, setUsageText] = useState('');
  const [wrappingKey, setWrappingKey] = useState('');
  const [description, setDescription] = useState('');
  const [imported, setImported] = useState<ImportKeyResult | null>(null);

  const runStatus = async () => {
    const name = key.trim();
    const version = versionText.trim() !== '' ? Number(versionText) : undefined;
    setBusy(true);
    try {
      const res = await admin.setStatus(name, status, version);
      if (res.success && res.data) {
        const data = res.data;
        toast({
          title: 'Key status updated',
          description: `${data.key_id} v${data.version} is ${data.status}`,
          variant: 'success',
        });
      } else {
        toast({
          title: 'Status update failed',
          description: res.error?.message || 'The control plane did not update the status',
          variant: 'destructive',
        });
      }
    } catch (err) {
      toast({ title: 'Status update failed', description: errorMessage(err), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  const runImport = async () => {
    const usage = usageText
      .split(',')
      .map((u) => u.trim().toUpperCase())
      .filter((u) => u !== '');
    const input: ImportKeyInput = {
      name: importName.trim(),
      algorithm,
      key_material: material.trim(),
    };
    if (usage.length > 0) input.usage = usage;
    if (wrappingKey.trim() !== '') input.wrapping_key_id = wrappingKey.trim();
    if (description.trim() !== '') input.description = description.trim();

    setBusy(true);
    try {
      const res = await admin.importKey(input);
      if (res.success && res.data) {
        const data = res.data;
        setImported(data);
        setMaterial('');
        toast({
          title: 'Key imported',
          description: `${data.key_id} v${data.version}`,
          variant: 'success',
        });
      } else {
        toast({
          title: 'Import failed',
          description: res.error?.message || 'The control plane did not import the key',
          variant: 'destructive',
        });
      }
    } catch (err) {
      toast({ title: 'Import failed', description: errorMessage(err), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  const onUpdateStatus = () => {
    if (status === 'ENABLED') {
      void runStatus();
    } else {
      setConfirmOpen(true);
    }
  };

  const onConfirm = () => {
    setConfirmOpen(false);
    void runStatus();
  };

  return (
    <Card data-testid="kms-key-admin-card">
      <CardHeader>
        <CardTitle>Key administration</CardTitle>
        <CardDescription>Change a key&apos;s status, or import key material as a new key.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <section className="space-y-3" aria-labelledby="kms-status-heading">
          <h3 id="kms-status-heading" className="text-sm font-medium">
            Status
          </h3>
          <div className="space-y-1">
            <Label htmlFor="kms-status-key">Key name</Label>
            <Input id="kms-status-key" value={key} onChange={(e) => setKey(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="kms-status-value">New status</Label>
            <select
              id="kms-status-value"
              className={SELECT_CLASS}
              value={status}
              onChange={(e) => setStatus(e.target.value as KeyStatus)}
            >
              {KEY_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="kms-status-version">Version (optional)</Label>
            <Input
              id="kms-status-version"
              type="number"
              min={1}
              value={versionText}
              onChange={(e) => setVersionText(e.target.value)}
            />
          </div>
          <Button onClick={onUpdateStatus} disabled={busy || key.trim() === ''}>
            Update status
          </Button>
        </section>

        <section className="space-y-3" aria-labelledby="kms-import-heading">
          <h3 id="kms-import-heading" className="text-sm font-medium">
            Import
          </h3>
          <div className="space-y-1">
            <Label htmlFor="kms-import-name">New key name</Label>
            <Input id="kms-import-name" value={importName} onChange={(e) => setImportName(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="kms-import-alg">Algorithm</Label>
            <select
              id="kms-import-alg"
              className={SELECT_CLASS}
              value={algorithm}
              onChange={(e) => setAlgorithm(e.target.value)}
            >
              {IMPORT_ALGORITHMS.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="kms-import-material">Key material (base64)</Label>
            <Textarea
              id="kms-import-material"
              className="font-mono"
              value={material}
              onChange={(e) => setMaterial(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="kms-import-usage">Usage (comma separated)</Label>
            <Input id="kms-import-usage" value={usageText} onChange={(e) => setUsageText(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="kms-import-wrap">Wrapping key ID (optional)</Label>
            <Input id="kms-import-wrap" value={wrappingKey} onChange={(e) => setWrappingKey(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="kms-import-desc">Description (optional)</Label>
            <Input id="kms-import-desc" value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          <Button
            onClick={() => void runImport()}
            disabled={busy || importName.trim() === '' || material.trim() === ''}
          >
            Import key
          </Button>
          {imported && (
            <dl data-testid="kms-import-result" className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
              <dt className="text-muted-foreground">Key ID</dt>
              <dd className="font-mono">{imported.key_id}</dd>
              <dt className="text-muted-foreground">Version</dt>
              <dd>{imported.version}</dd>
              <dt className="text-muted-foreground">Algorithm</dt>
              <dd>{imported.algorithm}</dd>
            </dl>
          )}
        </section>
      </CardContent>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{`Set ${key.trim()} to ${status}?`}</DialogTitle>
            <DialogDescription>
              {`Operations with this key are refused while it is ${status}.`}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={onConfirm}>
              Set status
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
