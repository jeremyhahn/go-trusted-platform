'use client';

/**
 * Device Templates Management Page
 * Display and manage device templates for standardized provisioning
 */

import { useState, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import {
  Plus,
  Filter,
  RefreshCw,
  MoreHorizontal,
  Eye,
  Pencil,
  Trash2,
  Copy,
  LayoutTemplate,
  Settings2,
  Shield,
  AlertCircle,
  Loader2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { useToast, useDeviceTemplates } from '@/hooks';
import type {
  DeviceProfile,
  DeviceRole,
  DeviceTemplate,
  UpdateDeviceTemplateRequest,
} from 'trusted-platform-sdk';
import {
  ConfirmDialog,
  CreateProfileDialog,
  EditTemplateDialog,
  ProfileAssignmentPanel,
  TemplateDetailsDialog,
} from './template-dialogs';
import {
  ASSIGNABLE_DEVICE_ROLES,
  DEVICE_ROLES,
  deviceRoleLabel,
  toDeviceRole,
} from '@/lib/device-role';

// ============================================================================
// Types
// ============================================================================

interface TemplateFilters {
  role?: DeviceRole;
  search?: string;
}

interface TemplateStats {
  total: number;
  byRole: Partial<Record<DeviceRole, number>>;
}

// ============================================================================
// Helper Functions
// ============================================================================

function computeStats(templates: DeviceTemplate[]): TemplateStats {
  const byRole: Partial<Record<DeviceRole, number>> = {};
  templates.forEach((template) => {
    const role = template.role || 'unknown';
    byRole[role] = (byRole[role] || 0) + 1;
  });

  return {
    total: templates.length,
    byRole,
  };
}

function getRoleBadge(role: DeviceRole) {
  return <Badge variant="outline">{deviceRoleLabel(role)}</Badge>;
}

function formatDate(dateString: string | null | undefined) {
  if (!dateString) return '—';
  const d = new Date(dateString);
  if (!Number.isFinite(d.getTime())) return '—';
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

// ============================================================================
// Main Component
// ============================================================================

export default function DeviceTemplatesPage() {
  const router = useRouter();
  const { toast } = useToast();
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [filters, setFilters] = useState<TemplateFilters>({});

  const [detailsId, setDetailsId] = useState<string | null>(null);
  const [editTarget, setEditTarget] = useState<DeviceTemplate | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<DeviceTemplate | null>(null);
  const [profileTarget, setProfileTarget] = useState<DeviceTemplate | null>(null);

  const {
    templates,
    isLoading,
    error,
    refetch,
    create,
    update,
    remove,
    createProfileFromTemplate,
  } = useDeviceTemplates();

  // Filtered templates
  const filteredTemplates = useMemo(() => {
    return templates.filter((template) => {
      if (filters.role && template.role !== filters.role) return false;
      if (filters.search) {
        const search = filters.search.toLowerCase();
        return (
          template.name.toLowerCase().includes(search) ||
          template.description?.toLowerCase().includes(search) ||
          template.id.toString().includes(search)
        );
      }
      return true;
    });
  }, [templates, filters]);

  // Statistics
  const stats = useMemo(() => computeStats(templates), [templates]);

  const handleFilterChange = (key: keyof TemplateFilters, value: string) => {
    setFilters((prev) => ({
      ...prev,
      [key]: value || undefined,
    }));
  };

  const handleViewTemplate = (template: DeviceTemplate) => {
    setDetailsId(template.id);
  };

  const handleEditTemplate = (template: DeviceTemplate) => {
    setEditTarget(template);
  };

  const handleUpdateTemplate = async (request: UpdateDeviceTemplateRequest) => {
    try {
      await update.mutateAsync(request);
      toast({
        title: 'Template updated',
        description: `"${request.name ?? ''}" has been saved`,
        variant: 'success',
      });
      setEditTarget(null);
      refetch();
    } catch (err) {
      toast({
        title: 'Error updating template',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  const handleCreateProfile = async (overrides: Partial<DeviceProfile> | undefined) => {
    if (!profileTarget) {
      return;
    }
    try {
      const profile = await createProfileFromTemplate.mutateAsync({
        templateId: profileTarget.id,
        overrides,
      });
      toast({
        title: 'Profile created',
        description: `Profile ${profile?.name ?? ''} was created from "${profileTarget.name}"`,
        variant: 'success',
      });
      setProfileTarget(null);
    } catch (err) {
      toast({
        title: 'Error creating profile',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  const handleDuplicateTemplate = async (template: DeviceTemplate) => {
    try {
      await create.mutateAsync({
        name: `${template.name} (Copy)`,
        description: template.description,
        role: template.role,
        config: template.config,
        match_rules: template.match_rules,
      });
      toast({
        title: 'Template duplicated',
        description: `"${template.name} (Copy)" has been created`,
        variant: 'success',
      });
      refetch();
    } catch (err) {
      toast({
        title: 'Error duplicating template',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  const handleDeleteTemplate = (template: DeviceTemplate) => {
    setDeleteTarget(template);
  };

  const confirmDeleteTemplate = async () => {
    const template = deleteTarget;
    if (!template) {
      return;
    }
    setDeleteTarget(null);
    try {
      await remove.mutateAsync(template.id);
      toast({
        title: 'Template deleted',
        description: 'The template has been deleted successfully',
        variant: 'success',
      });
      refetch();
    } catch (err) {
      toast({
        title: 'Error deleting template',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  const handleCreateTemplate = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);

    try {
      await create.mutateAsync({
        name: formData.get('name') as string,
        description: (formData.get('description') as string) || undefined,
        role: toDeviceRole(formData.get('role')),
      });
      toast({
        title: 'Template created',
        description: 'The template has been created successfully',
        variant: 'success',
      });
      refetch();
      setIsCreateDialogOpen(false);
    } catch (err) {
      toast({
        title: 'Error creating template',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  if (error) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Templates</AlertTitle>
          <AlertDescription>
            {error.message}
            <Button
              variant="outline"
              size="sm"
              className="ml-4"
              onClick={() => refetch()}
            >
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Device Templates</h1>
          <p className="text-muted-foreground">
            Manage reusable device configuration templates for standardized provisioning
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => refetch()} disabled={isLoading}>
            <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" />
                Create Template
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Create Device Template</DialogTitle>
                <DialogDescription>
                  Create a reusable template for standardized device provisioning
                </DialogDescription>
              </DialogHeader>
              <form onSubmit={handleCreateTemplate}>
                <div className="grid gap-4 py-4">
                  <div className="grid gap-2">
                    <Label htmlFor="name">Template Name</Label>
                    <Input
                      id="name"
                      name="name"
                      placeholder="e.g., Production Edge Gateway Template"
                      required
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="description">Description</Label>
                    <Textarea
                      id="description"
                      name="description"
                      placeholder="Describe this template's purpose and intended use"
                      rows={3}
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="role">Device Role</Label>
                    <Select name="role" defaultValue="server">
                      <SelectTrigger>
                        <SelectValue placeholder="Select device role" />
                      </SelectTrigger>
                      <SelectContent>
                        {ASSIGNABLE_DEVICE_ROLES.map((role) => (
                          <SelectItem key={role} value={role}>
                            {deviceRoleLabel(role)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <DialogFooter>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setIsCreateDialogOpen(false)}
                  >
                    Cancel
                  </Button>
                  <Button type="submit" disabled={create.isLoading}>
                    {create.isLoading && (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    )}
                    Create Template
                  </Button>
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Templates</CardTitle>
            <LayoutTemplate className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">All device templates</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Servers</CardTitle>
            <Settings2 className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {stats.byRole.server || 0}
            </div>
            <p className="text-xs text-muted-foreground">Server templates</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Edge / IoT</CardTitle>
            <Shield className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
              {(stats.byRole.edge || 0) + (stats.byRole.iot || 0)}
            </div>
            <p className="text-xs text-muted-foreground">Edge and IoT templates</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Gateways</CardTitle>
            <Settings2 className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
              {(stats.byRole.gateway || 0) + (stats.byRole['load-balancer'] || 0)}
            </div>
            <p className="text-xs text-muted-foreground">Gateway templates</p>
          </CardContent>
        </Card>
      </div>

      {/* Config lookup and profile assignment */}
      <ProfileAssignmentPanel />

      <TemplateDetailsDialog
        templateId={detailsId}
        onOpenChange={(open) => !open && setDetailsId(null)}
        onOpenPage={(id) => router.push(`/devices/templates/${id}`)}
      />
      <EditTemplateDialog
        template={editTarget}
        onOpenChange={(open) => !open && setEditTarget(null)}
        pending={update.isLoading}
        onSave={handleUpdateTemplate}
      />
      <CreateProfileDialog
        template={profileTarget}
        onOpenChange={(open) => !open && setProfileTarget(null)}
        pending={createProfileFromTemplate.isLoading}
        onCreate={handleCreateProfile}
      />
      <ConfirmDialog
        open={deleteTarget !== null}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
        title="Delete template?"
        description={
          deleteTarget ? `"${deleteTarget.name}" will be deleted. This cannot be undone.` : ''
        }
        confirmLabel="Delete"
        pending={remove.isLoading}
        onConfirm={confirmDeleteTemplate}
      />

      {/* Filters */}
      <div className="flex items-center gap-4 rounded-lg border border-border bg-card p-4">
        <Filter className="h-5 w-5 text-muted-foreground" />
        <div className="flex flex-1 items-center gap-4">
          <Input
            placeholder="Search templates..."
            value={filters.search || ''}
            onChange={(e) => handleFilterChange('search', e.target.value)}
            className="max-w-sm"
          />
          <Select
            value={filters.role || 'all'}
            onValueChange={(value) =>
              handleFilterChange('role', value === 'all' ? '' : value)
            }
          >
            <SelectTrigger className="w-44">
              <SelectValue placeholder="All roles" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All roles</SelectItem>
              {DEVICE_ROLES.map((role) => (
                <SelectItem key={role} value={role}>
                  {deviceRoleLabel(role)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {(filters.role || filters.search) && (
            <Button variant="ghost" onClick={() => setFilters({})}>
              Clear filters
            </Button>
          )}
        </div>
      </div>

      {/* Templates Table */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <div className="text-center">
            <Loader2 className="h-8 w-8 animate-spin mx-auto" />
            <p className="mt-2 text-sm text-muted-foreground">Loading templates...</p>
          </div>
        </div>
      ) : (
        <div className="rounded-md border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Updated</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredTemplates.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-muted-foreground">
                    {filters.search || filters.role
                      ? 'No templates match your filters'
                      : 'No device templates found'}
                  </TableCell>
                </TableRow>
              ) : (
                filteredTemplates.map((template) => (
                  <TableRow key={template.id}>
                    <TableCell>
                      <div className="font-medium">{template.name}</div>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground">
                        {template.description || '-'}
                      </span>
                    </TableCell>
                    <TableCell>{getRoleBadge(template.role)}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {formatDate(template.updated_at)}
                    </TableCell>
                    <TableCell className="text-right">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon"
                            disabled={remove.isLoading}
                          >
                            <MoreHorizontal className="h-4 w-4" />
                            <span className="sr-only">Open menu</span>
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuLabel>Actions</DropdownMenuLabel>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem onClick={() => handleViewTemplate(template)}>
                            <Eye className="mr-2 h-4 w-4" />
                            View Details
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleEditTemplate(template)}>
                            <Pencil className="mr-2 h-4 w-4" />
                            Edit Template
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleDuplicateTemplate(template)}>
                            <Copy className="mr-2 h-4 w-4" />
                            Duplicate
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => setProfileTarget(template)}>
                            <Plus className="mr-2 h-4 w-4" />
                            Create Profile
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            onClick={() => handleDeleteTemplate(template)}
                            className="text-destructive"
                          >
                            <Trash2 className="mr-2 h-4 w-4" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
