'use client';

import { useEffect, useState } from 'react';
import { FolderOpen, Loader2, Plus, Save, Trash2 } from 'lucide-react';
import { useIAM, useApi, useMutation, useToast } from '@/hooks';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

// The SDK rejects with an error object carrying the server's message; it is
// not always an Error instance.
function failureMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (err !== null && typeof err === 'object' && typeof (err as { message?: unknown }).message === 'string') {
    return (err as { message: string }).message;
  }
  return String(err);
}

// Tenant record as the REST API sends it: GetTenant writes the record flat,
// the SDK declares it wrapped in `tenant` (#445).
interface TenantWire {
  id?: string;
  name?: string;
}

// The tenant routes answer only for the system tenant (systemOnly in the IAM
// router). Tenant settings are not edited here: the server's TenantSettings
// JSON is snake_case and the SDK's type is camelCase.
export default function TenantsPage() {
  const iam = useIAM();
  const { toast } = useToast();

  const { data: list, isLoading, error, refetch } = useApi(() => iam.listTenants(), []);
  const tenants: TenantWire[] = (list as { tenants?: TenantWire[] } | null | undefined)?.tenants ?? [];

  const [newId, setNewId] = useState('');
  const [newName, setNewName] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editName, setEditName] = useState('');

  const {
    data: selected,
    refetch: refetchSelected,
  } = useApi(
    () => (selectedId ? iam.getTenant(selectedId) : Promise.resolve({ success: true, data: null })),
    [selectedId],
  );

  // Reads the REST wire shape, which differs from the SDK/proto declaration — #445.
  const raw = selected as unknown as (TenantWire & { tenant?: TenantWire }) | null | undefined;
  const tenant: TenantWire | null = raw?.tenant ?? raw ?? null;
  const loadedName = tenant?.name ?? '';

  // Seed the editor from the tenant the server holds, again after each re-read.
  useEffect(() => {
    setEditName(loadedName);
  }, [loadedName]);

  const createMutation = useMutation(
    async () => iam.createTenant({ id: newId.trim(), name: newName.trim() }),
    {
      onSuccess: () => {
        toast({ title: 'Tenant created', variant: 'success' });
        setNewId('');
        setNewName('');
        void refetch();
      },
      onError: (err) => {
        toast({
          title: 'Failed to create tenant',
          description: failureMessage(err),
          variant: 'destructive',
        });
      },
    },
  );

  const updateMutation = useMutation(
    async () => {
      if (!selectedId) throw new Error('No tenant selected');
      return iam.updateTenant({ tenantId: selectedId, name: editName.trim() });
    },
    {
      onSuccess: () => {
        toast({ title: 'Tenant updated', variant: 'success' });
        void refetchSelected();
        void refetch();
      },
      onError: (err) => {
        toast({
          title: 'Failed to update tenant',
          description: failureMessage(err),
          variant: 'destructive',
        });
      },
    },
  );

  const deleteMutation = useMutation(
    async () => {
      if (!selectedId) throw new Error('No tenant selected');
      return iam.deleteTenant(selectedId);
    },
    {
      onSuccess: () => {
        toast({ title: 'Tenant deleted', variant: 'success' });
        setSelectedId(null);
        void refetch();
      },
      onError: (err) => {
        toast({
          title: 'Failed to delete tenant',
          description: failureMessage(err),
          variant: 'destructive',
        });
      },
    },
  );

  const trimmedNewId = newId.trim();
  const tenantBusy = updateMutation.isLoading || deleteMutation.isLoading;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Tenants</h1>
        <p className="text-muted-foreground">
          Create, rename and delete IAM tenants. These operations answer only for the system tenant.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Tenants</CardTitle>
          <CardDescription>The tenants the control plane holds.</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <Loader2 className="h-6 w-6 animate-spin" />
          ) : error ? (
            <Alert variant="destructive">
              <AlertDescription>{failureMessage(error)}</AlertDescription>
            </Alert>
          ) : tenants.length === 0 ? (
            <p className="text-sm text-muted-foreground">No tenants.</p>
          ) : (
            <ul className="divide-y">
              {tenants.map((t) => (
                <li key={t.id} className="flex items-center justify-between py-2">
                  <div>
                    <p className="font-mono text-sm">{t.id}</p>
                    <p className="text-sm text-muted-foreground">{t.name}</p>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    aria-label={`Open tenant ${t.id}`}
                    onClick={() => t.id && setSelectedId(t.id)}
                  >
                    <FolderOpen className="h-4 w-4" />
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Create tenant</CardTitle>
          <CardDescription>The tenant ID is required.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="tenant-id">Tenant ID</Label>
            <Input id="tenant-id" value={newId} onChange={(e) => setNewId(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="tenant-name">Tenant name</Label>
            <Input id="tenant-name" value={newName} onChange={(e) => setNewName(e.target.value)} />
          </div>
          <Button
            disabled={trimmedNewId === '' || createMutation.isLoading}
            onClick={() => createMutation.mutate(undefined)}
          >
            {createMutation.isLoading ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Plus className="mr-2 h-4 w-4" />
            )}
            Create tenant
          </Button>
        </CardContent>
      </Card>

      {selectedId && (
        <Card>
          <CardHeader>
            <CardTitle>Tenant {selectedId}</CardTitle>
            <CardDescription>Rename or delete this tenant.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-tenant-name">Edit tenant name</Label>
              <Input id="edit-tenant-name" value={editName} onChange={(e) => setEditName(e.target.value)} />
            </div>
            <div className="flex gap-2">
              <Button disabled={tenantBusy} onClick={() => updateMutation.mutate(undefined)}>
                <Save className="mr-2 h-4 w-4" />
                Save tenant
              </Button>
              <Button variant="destructive" disabled={tenantBusy} onClick={() => deleteMutation.mutate(undefined)}>
                <Trash2 className="mr-2 h-4 w-4" />
                Delete tenant
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
