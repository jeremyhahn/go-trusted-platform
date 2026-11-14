'use client';

/**
 * vTPM bundle detail (#1674): bundle manifest, validation and the bundle,
 * TPM socket and NVRAM paths.
 */

import { useEffect, useRef, useState } from 'react';
import { useParams, usePathname } from 'next/navigation';
import { resolveDynamicId } from '@/utils/dynamic-route';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  useVTPMTemplates,
  type VTPMBundleWire,
  type VTPMValidationWire,
} from '@/hooks/use-vtpm-templates';

export default function BundleDetailClient() {
  const params = useParams();
  const pathname = usePathname();
  const bundleId = resolveDynamicId(params, pathname, 'bundles');
  const vt = useVTPMTemplates();
  const { getBundle } = vt;

  const [validation, setValidation] = useState<VTPMValidationWire | null>(null);
  const [bundlePath, setBundlePath] = useState<string | null>(null);
  const [socketPath, setSocketPath] = useState<string | null>(null);
  const [nvramPath, setNvramPath] = useState<string | null>(null);

  // Results are keyed to the ID that produced them: a response for an ID the
  // URL has since left is dropped, so bundle A never shows under bundle B.
  const [loaded, setLoaded] = useState<{ id: string; bundle: VTPMBundleWire } | null>(null);
  const [failedId, setFailedId] = useState<string | null>(null);
  const currentId = useRef(bundleId);
  currentId.current = bundleId;

  useEffect(() => {
    setLoaded(null);
    setFailedId(null);
    setValidation(null);
    setBundlePath(null);
    setSocketPath(null);
    setNvramPath(null);
    if (!bundleId) return;
    const id = bundleId;
    getBundle.mutateAsync(id).then(
      (result) => {
        if (currentId.current === id) setLoaded({ id, bundle: result });
      },
      () => {
        if (currentId.current === id) setFailedId(id);
      }
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bundleId]);

  const bundle: VTPMBundleWire | null = loaded && loaded.id === bundleId ? loaded.bundle : null;

  const run = async <T,>(id: string, call: () => Promise<T>, set: (value: T) => void) => {
    try {
      const value = await call();
      if (currentId.current === id) set(value);
    } catch {
      // onError already shows a toast
    }
  };

  if (!bundleId || (!bundle && failedId !== bundleId)) {
    return <p className="text-muted-foreground">Loading bundle</p>;
  }

  if (!bundle) {
    return <p className="text-muted-foreground">Bundle {bundleId} could not be loaded.</p>;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">vTPM bundle {bundle.id}</h1>
      </div>

      <Card data-testid="vtpm-bundle-detail">
        <CardHeader>
          <CardTitle>Bundle</CardTitle>
          <CardDescription>Manifest of bundle {bundle.id}</CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted-foreground">ID</dt>
            <dd className="font-mono">{bundle.id}</dd>
            <dt className="text-muted-foreground">Mode</dt>
            <dd>
              <Badge variant="outline">{bundle.mode}</Badge>
            </dd>
            <dt className="text-muted-foreground">Hostname</dt>
            <dd>{bundle.manifest?.hostname || '-'}</dd>
            <dt className="text-muted-foreground">EK algorithm</dt>
            <dd>{bundle.manifest?.ek_algorithm || '-'}</dd>
            <dt className="text-muted-foreground">Created</dt>
            <dd>{bundle.created_at || bundle.manifest?.created_at || '-'}</dd>
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Operations</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              disabled={vt.validateBundle.isLoading}
              onClick={() => run(bundleId, () => vt.validateBundle.mutateAsync(bundleId), setValidation)}
            >
              Validate bundle
            </Button>
            <Button
              variant="outline"
              onClick={() =>
                run(bundleId, () => vt.getBundlePath.mutateAsync(bundleId), (r) => setBundlePath(r.path))
              }
            >
              Get bundle path
            </Button>
            <Button
              variant="outline"
              onClick={() =>
                run(bundleId, () => vt.getTPMSocketPath.mutateAsync(bundleId), (r) => setSocketPath(r.path))
              }
            >
              Get TPM socket path
            </Button>
            <Button
              variant="outline"
              onClick={() =>
                run(bundleId, () => vt.getNVRAMPath.mutateAsync(bundleId), (r) => setNvramPath(r.path))
              }
            >
              Get NVRAM path
            </Button>
          </div>

          {validation && (
            <div data-testid="vtpm-validate-result" className="text-sm">
              {validation.valid ? (
                <span className="font-medium text-green-600">Valid</span>
              ) : (
                <>
                  <span className="font-medium text-destructive">Invalid</span>
                  <ul className="mt-1 list-disc pl-5">
                    {(validation.errors ?? []).map((error) => (
                      <li key={error}>{error}</li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          )}

          <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
            {bundlePath !== null && (
              <>
                <dt className="text-muted-foreground">Bundle path</dt>
                <dd data-testid="vtpm-bundle-path" className="font-mono">
                  {bundlePath}
                </dd>
              </>
            )}
            {socketPath !== null && (
              <>
                <dt className="text-muted-foreground">TPM socket path</dt>
                <dd data-testid="vtpm-socket-path" className="font-mono">
                  {socketPath}
                </dd>
              </>
            )}
            {nvramPath !== null && (
              <>
                <dt className="text-muted-foreground">NVRAM path</dt>
                <dd data-testid="vtpm-nvram-path" className="font-mono">
                  {nvramPath}
                </dd>
              </>
            )}
          </dl>
        </CardContent>
      </Card>
    </div>
  );
}
