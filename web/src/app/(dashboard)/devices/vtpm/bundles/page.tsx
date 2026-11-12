'use client';

/**
 * vTPM bundles page (#1674): list bundles and import a bundle archive.
 */

import { useState } from 'react';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
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
import { useVTPMTemplates, type VTPMBundleWire } from '@/hooks/use-vtpm-templates';

function bundleHref(id: string): string {
  return `/devices/vtpm/bundles/${encodeURIComponent(id)}`;
}

export default function VTPMBundlesPage() {
  const vt = useVTPMTemplates();
  const [file, setFile] = useState<File | null>(null);
  const [imported, setImported] = useState<VTPMBundleWire | null>(null);

  const handleImport = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!file) return;
    try {
      setImported(await vt.importBundle.mutateAsync(file));
    } catch {
      // onError already shows a toast
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">vTPM Bundles</h1>
        <p className="text-muted-foreground">Bundles on this platform and bundle archive import.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Import bundle</CardTitle>
          <CardDescription>
            A bundle archive (gzip tar) as written by bundle export, at most 100 MB.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleImport} className="flex flex-wrap items-end gap-4">
            <div className="space-y-2">
              <Label htmlFor="vb-import-file">Archive</Label>
              <Input
                id="vb-import-file"
                type="file"
                accept=".tar.gz,.tgz,application/gzip"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            </div>
            <Button type="submit" disabled={!file || vt.importBundle.isLoading}>
              Import bundle
            </Button>
          </form>
          {imported && (
            <p data-testid="vtpm-import-result" className="mt-4 text-sm">
              Imported bundle{' '}
              <Link className="font-mono underline" href={bundleHref(imported.id)}>
                {imported.id}
              </Link>
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Bundles</CardTitle>
          <CardDescription>
            {vt.bundlesLoading ? 'Loading bundles' : `${vt.bundles.length} bundle(s)`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table data-testid="vtpm-bundle-list">
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Mode</TableHead>
                <TableHead>Hostname</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {vt.bundles.map((b) => (
                <TableRow key={b.id}>
                  <TableCell>
                    <Link className="font-mono underline" href={bundleHref(b.id)}>
                      {b.id}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{b.mode}</Badge>
                  </TableCell>
                  <TableCell>{b.manifest?.hostname || '-'}</TableCell>
                </TableRow>
              ))}
              {!vt.bundlesLoading && vt.bundles.length === 0 && (
                <TableRow>
                  <TableCell colSpan={3} className="text-center text-muted-foreground">
                    No bundles
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
