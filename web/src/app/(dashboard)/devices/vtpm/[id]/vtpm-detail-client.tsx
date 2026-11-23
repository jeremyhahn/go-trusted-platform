'use client';

/**
 * vTPM Detail Page
 * Display detailed information about a specific vTPM instance. Seal and
 * Unseal call the bundle runtime routes and Delete its route, each gated on
 * the server's capabilities (#2071). The server has no reset route and keeps
 * no sealed-data store: the caller holds sealed blobs.
 */

/** SEAL_OP, UNSEAL_OP and DELETE_OP are the server ops the controls are gated on. */
const SEAL_OP = 'POST /api/v1/vtpm/bundles/{id}/seal';
const UNSEAL_OP = 'POST /api/v1/vtpm/bundles/{id}/unseal';
const DELETE_OP = 'DELETE /api/v1/vtpm/bundles/{id}';

/** parsePCRs reads a comma list of PCR indices 0-23; null when any is invalid. */
function parsePCRs(text: string): number[] | null {
  const parts = text
    .split(',')
    .map((p) => p.trim())
    .filter((p) => p !== '');
  const pcrs: number[] = [];
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    const n = Number(p);
    if (n > 23) return null;
    pcrs.push(n);
  }
  return pcrs;
}

/** errorText reads the message of an Error or of the SDK's MutationError ({ code, message }). */
function errorText(error: unknown, fallback: string): string {
  if (error && typeof error === 'object' && 'message' in error) {
    const message = (error as { message?: unknown }).message;
    if (typeof message === 'string' && message !== '') return message;
  }
  return fallback;
}

import { useState, useEffect } from 'react';
import { useParams, usePathname, useRouter, useSearchParams } from 'next/navigation';
import { resolveDynamicId } from '@/utils/dynamic-route';
import {
  ArrowLeft,
  Lock,
  Unlock,
  RotateCcw,
  Trash2,
  FileText,
  Plus,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { VTPMPCRDisplay } from '@/components/features/devices/vtpm-pcr';
import { useToast } from '@/hooks/use-toast';
import { useVTPM, useMutation } from '@/hooks';
import { useVTPMRuntime, textToBase64, base64ToText } from '@/hooks/use-vtpm-runtime';
import { Gated } from '@/components/features/capabilities/gated';
import type { VTPMDetail } from '@/types/device';

export default function VTPMDetailPage() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const { toast } = useToast();
  const vtpmService = useVTPM();
  const vtpmId = resolveDynamicId(params, pathname, 'vtpm');
  const action = searchParams?.get('action');

  const [vtpm, setVTPM] = useState<VTPMDetail | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSealDialogOpen, setIsSealDialogOpen] = useState(false);
  const [isUnsealDialogOpen, setIsUnsealDialogOpen] = useState(false);
  const runtime = useVTPMRuntime(vtpmId);
  const [sealedBlob, setSealedBlob] = useState<string | null>(null);
  const [unsealInput, setUnsealInput] = useState('');
  const [unsealedData, setUnsealedData] = useState<string | null>(null);

  // Seal data form state
  const [sealForm, setSealForm] = useState({
    name: '',
    data: '',
    description: '',
    pcrIndices: '0,1,2,7',
  });

  // The effect settles the bundle read into state from its promise
  // callbacks (no synchronous setState in the effect).
  useEffect(() => {
    if (!vtpmId) {
      return;
    }
    let active = true;
    vtpmService
      .getBundle(vtpmId)
      .then((response) => {
        if (!response.data) {
          throw new Error('Failed to fetch vTPM');
        }
        if (active) {
          // The REST payload carries the VTPMDetail fields, which differ from
          // the SDK/proto declaration of the bundle (#445).
          setVTPM(response.data as unknown as VTPMDetail);
        }
      })
      .catch((error: unknown) => {
        if (active) {
          toast({
            title: 'Error',
            description: error instanceof Error ? error.message : 'Failed to fetch vTPM',
            variant: 'destructive',
          });
        }
      })
      .finally(() => {
        if (active) {
          setIsLoading(false);
        }
      });
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vtpmId]);

  // Open the seal dialog when the query asks for it (state adjusted during
  // render against the previous action, not in an effect).
  const [actionSeen, setActionSeen] = useState<string | null | undefined>(undefined);
  if (action !== actionSeen) {
    setActionSeen(action);
    if (action === 'seal') {
      setIsSealDialogOpen(true);
    }
  }

  const deleteMutation = useMutation(
    async () => {
      return await vtpmService.deleteBundle(vtpmId);
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'vTPM deleted successfully',
        });
        router.push('/devices/vtpm');
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: error.message || 'Failed to delete vTPM',
          variant: 'destructive',
        });
      },
    }
  );

  const handleDelete = async () => {
    if (!vtpm) return;

    if (!confirm(`Are you sure you want to delete vTPM ${vtpm.name}? This action cannot be undone.`)) {
      return;
    }

    deleteMutation.mutate(undefined);
  };

  const handleSealData = async (e: React.FormEvent) => {
    e.preventDefault();

    const pcrs = parsePCRs(sealForm.pcrIndices);
    if (pcrs === null) {
      toast({
        title: 'Error',
        description: 'PCR indices must be a comma list of integers 0-23',
        variant: 'destructive',
      });
      return;
    }
    setSealedBlob(null);
    try {
      const res = await runtime.seal.mutateAsync({ data: textToBase64(sealForm.data), pcrs });
      setSealedBlob(res.sealed_data);
      setIsSealDialogOpen(false);
      toast({ title: 'Success', description: 'Data sealed' });
    } catch (error) {
      toast({
        title: 'Error',
        description: errorText(error, 'Failed to seal data'),
        variant: 'destructive',
      });
    }
  };

  const handleUnsealData = async (e: React.FormEvent) => {
    e.preventDefault();

    setUnsealedData(null);
    try {
      const res = await runtime.unseal.mutateAsync({ sealed_data: unsealInput.trim() });
      setUnsealedData(base64ToText(res.data));
    } catch (error) {
      toast({
        title: 'Error',
        description: errorText(error, 'Failed to unseal data'),
        variant: 'destructive',
      });
    }
  };

  const formatDate = (date: string) => {
    return new Date(date).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getStateBadge = (state: VTPMDetail['state']) => {
    const variants: Record<VTPMDetail['state'], { variant: 'default' | 'secondary' | 'outline'; label: string }> = {
      active: { variant: 'default', label: 'Active' },
      sealed: { variant: 'secondary', label: 'Sealed' },
      migrating: { variant: 'outline', label: 'Migrating' },
      suspended: { variant: 'secondary', label: 'Suspended' },
    };

    // The REST bundle may carry no state; show it as unknown, not a crash.
    const { variant, label } = variants[state] ?? { variant: 'outline' as const, label: state || 'Unknown' };
    return <Badge variant={variant}>{label}</Badge>;
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center">
          <div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-current border-r-transparent motion-reduce:animate-[spin_1.5s_linear_infinite]" />
          <p className="mt-2 text-sm text-muted-foreground">Loading vTPM details...</p>
        </div>
      </div>
    );
  }

  if (!vtpm) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <p className="text-lg font-medium">vTPM not found</p>
        <Button className="mt-4" onClick={() => router.push('/devices/vtpm')}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to vTPM List
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => router.back()}>
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold tracking-tight">{vtpm.name}</h1>
            <p className="text-muted-foreground">vTPM instance details and operations</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Gated op={SEAL_OP}>
            <Button onClick={() => setIsSealDialogOpen(true)}>
              <Lock className="mr-2 h-4 w-4" />
              Seal Data
            </Button>
          </Gated>
          <Gated op={UNSEAL_OP}>
            <Button variant="outline" onClick={() => setIsUnsealDialogOpen(true)}>
              <Unlock className="mr-2 h-4 w-4" />
              Unseal
            </Button>
          </Gated>
          <Button variant="outline" disabled title="No server route">
            <RotateCcw className="mr-2 h-4 w-4" />
            Reset
          </Button>
          <Gated op={DELETE_OP}>
            <Button variant="destructive" onClick={handleDelete}>
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </Button>
          </Gated>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>vTPM Information</CardTitle>
          <CardDescription>Basic information about this vTPM instance</CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Name</dt>
              <dd className="mt-1 text-sm font-medium">{vtpm.name}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted-foreground">State</dt>
              <dd className="mt-1">{getStateBadge(vtpm.state)}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted-foreground">VM/Container</dt>
              <dd className="mt-1">
                <div className="flex flex-col">
                  <span className="text-sm font-medium">{vtpm.vmName}</span>
                  <span className="text-xs text-muted-foreground">{vtpm.vmId}</span>
                </div>
              </dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted-foreground">PCR Profile</dt>
              <dd className="mt-1">
                <Badge variant="outline">{vtpm.pcrProfile}</Badge>
              </dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-muted-foreground">Created</dt>
              <dd className="mt-1 text-sm">{formatDate(vtpm.createdAt)}</dd>
            </div>
            {vtpm.updatedAt && (
              <div>
                <dt className="text-sm font-medium text-muted-foreground">Last Updated</dt>
                <dd className="mt-1 text-sm">{formatDate(vtpm.updatedAt)}</dd>
              </div>
            )}
          </dl>
        </CardContent>
      </Card>

      <VTPMPCRDisplay pcrValues={vtpm.pcrValues ?? []} />

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <FileText className="h-5 w-5" />
                Sealed Data
              </CardTitle>
              <CardDescription>
                Data sealed to PCR values. The server keeps no sealed-data store:
                sealed blobs are held by the caller.
              </CardDescription>
            </div>
            <Gated op={SEAL_OP}>
              <Button onClick={() => setIsSealDialogOpen(true)} size="sm">
              <Plus className="mr-2 h-4 w-4" />
              Seal Data
              </Button>
            </Gated>
          </div>
        </CardHeader>
        <CardContent>
          {sealedBlob === null ? (
            <p className="text-sm text-muted-foreground">No data sealed in this session.</p>
          ) : (
            <div>
              <Label>Last sealed blob (base64)</Label>
              <pre
                data-testid="vtpm-sealed-blob"
                className="mt-1 whitespace-pre-wrap break-all rounded-md border border-border bg-muted/50 p-3 font-mono text-xs"
              >
                {sealedBlob}
              </pre>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Seal Data Dialog */}
      <Dialog open={isSealDialogOpen} onOpenChange={setIsSealDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Seal Data</DialogTitle>
            <DialogDescription>
              Seal data to current PCR values. Data can only be unsealed when PCRs match.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSealData} className="space-y-4">
            <div>
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                value={sealForm.name}
                onChange={(e) => setSealForm({ ...sealForm, name: e.target.value })}
                placeholder="my-sealed-data"
                required
              />
            </div>
            <div>
              <Label htmlFor="data">Data to Seal</Label>
              <Textarea
                id="data"
                value={sealForm.data}
                onChange={(e) => setSealForm({ ...sealForm, data: e.target.value })}
                placeholder="Enter sensitive data to seal..."
                className="font-mono text-sm"
                rows={6}
                required
              />
            </div>
            <div>
              <Label htmlFor="description">Description (Optional)</Label>
              <Input
                id="description"
                value={sealForm.description}
                onChange={(e) => setSealForm({ ...sealForm, description: e.target.value })}
                placeholder="Description of sealed data"
              />
            </div>
            <div>
              <Label htmlFor="pcrIndices">PCR Indices (comma-separated)</Label>
              <Input
                id="pcrIndices"
                value={sealForm.pcrIndices}
                onChange={(e) => setSealForm({ ...sealForm, pcrIndices: e.target.value })}
                placeholder="0,1,2,7"
                required
              />
              <p className="mt-1 text-xs text-muted-foreground">
                Data will be sealed to these PCR values
              </p>
            </div>
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => setIsSealDialogOpen(false)}>
                Cancel
              </Button>
              <Gated op={SEAL_OP}>
                <Button type="submit" disabled={runtime.seal.isLoading}>
                  <Lock className="mr-2 h-4 w-4" />
                  Seal Data
                </Button>
              </Gated>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Unseal Data Dialog */}
      <Dialog open={isUnsealDialogOpen} onOpenChange={setIsUnsealDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Unseal Data</DialogTitle>
            <DialogDescription>
              Paste a blob this bundle sealed. It unseals only when the PCRs match.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleUnsealData} className="space-y-4">
            <div>
              <Label htmlFor="unsealInput">Sealed blob to unseal</Label>
              <Textarea
                id="unsealInput"
                value={unsealInput}
                onChange={(e) => setUnsealInput(e.target.value)}
                placeholder="Base64 sealed blob"
                className="font-mono text-sm"
                rows={4}
                required
              />
            </div>
            {unsealedData !== null && (
              <div>
                <Label>Unsealed Data</Label>
                <pre
                  data-testid="vtpm-unsealed-data"
                  className="mt-1 whitespace-pre-wrap break-all rounded-md border border-border bg-muted/50 p-3 font-mono text-sm"
                >
                  {unsealedData}
                </pre>
              </div>
            )}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => setIsUnsealDialogOpen(false)}>
                Close
              </Button>
              <Gated op={UNSEAL_OP}>
                <Button type="submit" disabled={runtime.unseal.isLoading}>
                  <Unlock className="mr-2 h-4 w-4" />
                  Unseal blob
                </Button>
              </Gated>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
