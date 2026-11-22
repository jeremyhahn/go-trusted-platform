'use client';

/**
 * vTPM templates page (#1674): list, create, inspect, clone and delete
 * vTPM templates.
 */

import { useState } from 'react';
import Link from 'next/link';
import { Plus } from 'lucide-react';
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
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  useVTPMTemplates,
  type VTPMBundleWire,
  type VTPMTemplateWire,
} from '@/hooks/use-vtpm-templates';

const emptyForm = {
  id: '',
  description: '',
  ekAlgorithm: 'RSA' as 'RSA' | 'ECC',
  secureBootEnabled: false,
};

export default function VTPMTemplatesPage() {
  const vt = useVTPMTemplates();
  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState(emptyForm);
  const [details, setDetails] = useState<VTPMTemplateWire | null>(null);
  const [cloneFrom, setCloneFrom] = useState<string | null>(null);
  const [cloneHostname, setCloneHostname] = useState('');
  const [cloned, setCloned] = useState<VTPMBundleWire | null>(null);
  const [deleteId, setDeleteId] = useState<string | null>(null);

  const handleCreate = async (event: React.FormEvent) => {
    event.preventDefault();
    try {
      await vt.createTemplate.mutateAsync({
        id: form.id.trim(),
        description: form.description.trim() || undefined,
        ekAlgorithm: form.ekAlgorithm,
        secureBootEnabled: form.secureBootEnabled,
      });
      setCreateOpen(false);
      setForm(emptyForm);
    } catch {
      // onError already shows a toast
    }
  };

  const handleDetails = async (id: string) => {
    try {
      setDetails(await vt.getTemplate.mutateAsync(id));
    } catch {
      setDetails(null);
    }
  };

  const handleClone = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!cloneFrom) return;
    try {
      const result = await vt.cloneTemplate.mutateAsync({
        templateId: cloneFrom,
        hostname: cloneHostname.trim(),
      });
      setCloned(result);
      setCloneFrom(null);
      setCloneHostname('');
    } catch {
      // onError already shows a toast
    }
  };

  const handleDelete = async () => {
    if (!deleteId) return;
    const id = deleteId;
    try {
      await vt.deleteTemplate.mutateAsync(id);
      if (details?.id === id) setDetails(null);
    } catch {
      // onError already shows a toast
    } finally {
      setDeleteId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">vTPM Templates</h1>
          <p className="text-muted-foreground">
            Golden vTPM state that new bundles are cloned from.
          </p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" />
          New template
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Templates</CardTitle>
          <CardDescription>
            {vt.templatesLoading ? 'Loading templates' : `${vt.templates.length} template(s)`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table data-testid="vtpm-template-list">
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>EK algorithm</TableHead>
                <TableHead>Secure boot</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {vt.templates.map((t) => (
                <TableRow key={t.id}>
                  <TableCell className="font-mono">{t.id}</TableCell>
                  <TableCell>{t.ek_algorithm}</TableCell>
                  <TableCell>
                    <Badge variant={t.secure_boot_enabled ? 'default' : 'secondary'}>
                      {t.secure_boot_enabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </TableCell>
                  <TableCell className="space-x-2 text-right">
                    <Button variant="outline" size="sm" onClick={() => handleDetails(t.id)}>
                      Details
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => setCloneFrom(t.id)}>
                      Clone
                    </Button>
                    <Button variant="destructive" size="sm" onClick={() => setDeleteId(t.id)}>
                      Delete
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {!vt.templatesLoading && vt.templates.length === 0 && (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-muted-foreground">
                    No templates
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {details && (
        <Card data-testid="vtpm-template-details">
          <CardHeader>
            <CardTitle>Template {details.id}</CardTitle>
            {details.description && <CardDescription>{details.description}</CardDescription>}
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
              <dt className="text-muted-foreground">ID</dt>
              <dd className="font-mono">{details.id}</dd>
              <dt className="text-muted-foreground">Description</dt>
              <dd>{details.description || '-'}</dd>
              <dt className="text-muted-foreground">TPM state dir</dt>
              <dd className="font-mono">{details.tpm_state_dir}</dd>
              <dt className="text-muted-foreground">NVRAM path</dt>
              <dd className="font-mono">{details.nvram_path}</dd>
              <dt className="text-muted-foreground">Secure boot keys dir</dt>
              <dd className="font-mono">{details.secure_boot_keys_dir || '-'}</dd>
              <dt className="text-muted-foreground">EK algorithm</dt>
              <dd>{details.ek_algorithm}</dd>
              <dt className="text-muted-foreground">Secure boot</dt>
              <dd>{details.secure_boot_enabled ? 'Enabled' : 'Disabled'}</dd>
              <dt className="text-muted-foreground">Created</dt>
              <dd>{details.created_at || '-'}</dd>
            </dl>
          </CardContent>
        </Card>
      )}

      {cloned && (
        <Card data-testid="vtpm-clone-result">
          <CardHeader>
            <CardTitle>Bundle cloned</CardTitle>
          </CardHeader>
          <CardContent className="text-sm">
            New bundle{' '}
            <Link className="font-mono underline" href={`/devices/vtpm/bundles/${encodeURIComponent(cloned.id)}`}>
              {cloned.id}
            </Link>
          </CardContent>
        </Card>
      )}

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <form onSubmit={handleCreate} className="space-y-4">
            <DialogHeader>
              <DialogTitle>New vTPM template</DialogTitle>
              <DialogDescription>Create a template that bundles can be cloned from.</DialogDescription>
            </DialogHeader>
            <div className="space-y-2">
              <Label htmlFor="vt-id">ID</Label>
              <Input
                id="vt-id"
                required
                value={form.id}
                onChange={(e) => setForm({ ...form, id: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="vt-description">Description</Label>
              <Input
                id="vt-description"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="vt-ek-algorithm">EK algorithm</Label>
              <select
                id="vt-ek-algorithm"
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm"
                value={form.ekAlgorithm}
                onChange={(e) =>
                  setForm({ ...form, ekAlgorithm: e.target.value === 'ECC' ? 'ECC' : 'RSA' })
                }
              >
                <option value="RSA">RSA</option>
                <option value="ECC">ECC</option>
              </select>
            </div>
            <div className="flex items-center gap-2">
              <input
                id="vt-secure-boot"
                type="checkbox"
                checked={form.secureBootEnabled}
                onChange={(e) => setForm({ ...form, secureBootEnabled: e.target.checked })}
              />
              <Label htmlFor="vt-secure-boot">Secure boot enabled</Label>
            </div>
            <DialogFooter>
              <Button type="submit" disabled={vt.createTemplate.isLoading || !form.id.trim()}>
                Create template
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={cloneFrom !== null} onOpenChange={(open) => !open && setCloneFrom(null)}>
        <DialogContent>
          <form onSubmit={handleClone} className="space-y-4">
            <DialogHeader>
              <DialogTitle>Clone template {cloneFrom}</DialogTitle>
              <DialogDescription>Create a new bundle from this template.</DialogDescription>
            </DialogHeader>
            <div className="space-y-2">
              <Label htmlFor="vt-clone-hostname">Hostname</Label>
              <Input
                id="vt-clone-hostname"
                required
                value={cloneHostname}
                onChange={(e) => setCloneHostname(e.target.value)}
              />
            </div>
            <DialogFooter>
              <Button type="submit" disabled={vt.cloneTemplate.isLoading || !cloneHostname.trim()}>
                Clone to bundle
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={deleteId !== null} onOpenChange={(open) => !open && setDeleteId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete template {deleteId}?</DialogTitle>
            <DialogDescription>Bundles already cloned from it are kept.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteId(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={vt.deleteTemplate.isLoading}
              onClick={handleDelete}
            >
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
