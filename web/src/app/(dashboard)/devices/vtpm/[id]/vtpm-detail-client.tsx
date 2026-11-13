'use client';

/**
 * vTPM Detail Page
 * Display detailed information about a specific vTPM instance
 */

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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
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
  const [unsealedData] = useState<string | null>(null);

  // Seal data form state
  const [sealForm, setSealForm] = useState({
    name: '',
    data: '',
    description: '',
    pcrIndices: '0,1,2,7',
  });

  const fetchVTPM = async () => {
    setIsLoading(true);
    try {
      const response = await vtpmService.getBundle(vtpmId);

      if (response.data) {
        // The REST payload carries the VTPMDetail fields, which differ from
        // the SDK/proto declaration of the bundle (#445).
        setVTPM(response.data as unknown as VTPMDetail);
      } else {
        throw new Error('Failed to fetch vTPM');
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to fetch vTPM',
        variant: 'destructive',
      });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (vtpmId) {
      fetchVTPM();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vtpmId]);

  useEffect(() => {
    if (action === 'seal') {
      setIsSealDialogOpen(true);
    }
  }, [action]);

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

  const handleReset = async () => {
    if (!vtpm) return;

    if (!confirm(`Are you sure you want to reset vTPM ${vtpm.name}? This will clear all state.`)) {
      return;
    }

    toast({
      title: 'Info',
      description: 'Reset operation not yet implemented in SDK',
      variant: 'default',
    });
  };

  const handleDelete = async () => {
    if (!vtpm) return;

    if (!confirm(`Are you sure you want to delete vTPM ${vtpm.name}? This action cannot be undone.`)) {
      return;
    }

    deleteMutation.mutate(undefined);
  };

  const handleSealData = async (e: React.FormEvent) => {
    e.preventDefault();

    toast({
      title: 'Info',
      description: 'Seal operation not yet implemented in SDK',
      variant: 'default',
    });
  };

  const handleUnsealData = async () => {
    toast({
      title: 'Info',
      description: 'Unseal operation not yet implemented in SDK',
      variant: 'default',
    });
  };

  const handleDeleteSealed = async () => {
    if (!confirm('Are you sure you want to delete this sealed data?')) {
      return;
    }

    toast({
      title: 'Info',
      description: 'Delete sealed data operation not yet implemented in SDK',
      variant: 'default',
    });
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

  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const getStateBadge = (state: VTPMDetail['state']) => {
    const variants: Record<VTPMDetail['state'], { variant: 'default' | 'secondary' | 'outline'; label: string }> = {
      active: { variant: 'default', label: 'Active' },
      sealed: { variant: 'secondary', label: 'Sealed' },
      migrating: { variant: 'outline', label: 'Migrating' },
      suspended: { variant: 'secondary', label: 'Suspended' },
    };

    const { variant, label } = variants[state];
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
          {vtpm.state === 'active' && (
            <Button onClick={() => setIsSealDialogOpen(true)}>
              <Lock className="mr-2 h-4 w-4" />
              Seal Data
            </Button>
          )}
          <Button variant="outline" onClick={handleReset}>
            <RotateCcw className="mr-2 h-4 w-4" />
            Reset
          </Button>
          <Button variant="destructive" onClick={handleDelete}>
            <Trash2 className="mr-2 h-4 w-4" />
            Delete
          </Button>
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

      <VTPMPCRDisplay pcrValues={vtpm.pcrValues} />

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <FileText className="h-5 w-5" />
                Sealed Data
              </CardTitle>
              <CardDescription>
                Data sealed to PCR values
              </CardDescription>
            </div>
            <Button onClick={() => setIsSealDialogOpen(true)} size="sm">
              <Plus className="mr-2 h-4 w-4" />
              Seal Data
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border border-border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>PCR Indices</TableHead>
                  <TableHead>Size</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vtpm.sealedData.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground">
                      No sealed data found
                    </TableCell>
                  </TableRow>
                ) : (
                  vtpm.sealedData.map((sealed) => (
                    <TableRow key={sealed.id}>
                      <TableCell className="font-medium">{sealed.name}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {sealed.description || '-'}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          {sealed.pcrIndices.map((idx) => (
                            <Badge key={idx} variant="outline" className="font-mono text-xs">
                              {idx}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell className="text-sm">{formatBytes(sealed.dataSize)}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatDate(sealed.createdAt)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleUnsealData()}
                          >
                            <Unlock className="mr-2 h-4 w-4" />
                            Unseal
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDeleteSealed()}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
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
              <Button type="submit">
                <Lock className="mr-2 h-4 w-4" />
                Seal Data
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Unseal Data Dialog */}
      <Dialog open={isUnsealDialogOpen} onOpenChange={setIsUnsealDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Unsealed Data</DialogTitle>
            <DialogDescription>
              Data has been successfully unsealed
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Unsealed Data</Label>
              <Textarea
                value={unsealedData || ''}
                readOnly
                className="font-mono text-sm"
                rows={8}
              />
            </div>
            <div className="flex justify-end">
              <Button onClick={() => setIsUnsealDialogOpen(false)}>
                Close
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
