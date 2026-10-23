'use client';

/**
 * Device Template Detail Page
 * View, edit, and manage a specific device template
 */

import { useState } from 'react';
import { useRouter, useParams, usePathname } from 'next/navigation';
import { resolveDynamicId } from '@/utils/dynamic-route';
import {
  ArrowLeft,
  Pencil,
  Trash2,
  Plus,
  AlertCircle,
  Loader2,
  Calendar,
  Tag,
  FileText,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';
import { useToast, useApi, useDevice, useMutation } from '@/hooks';
import type { DeviceRole } from 'trusted-platform-sdk';
import { deviceRoleLabel } from '@/lib/device-role';

// ============================================================================
// Helper Functions
// ============================================================================

function getRoleBadge(role: DeviceRole) {
  return <Badge variant="outline">{deviceRoleLabel(role)}</Badge>;
}

function formatDate(dateString: string) {
  return new Date(dateString).toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

// ============================================================================
// Main Component
// ============================================================================

export default function TemplateDetailClient() {
  const params = useParams<{ id: string }>();
  const pathname = usePathname();
  // Keep the template ID as a string so 19-digit uint64 values
  // round-trip through the URL without losing precision; parseInt
  // would truncate them past JavaScript's safe-integer range.
  // Template ids stay strings while the SDK mutation params say number — #418.
  const templateId = resolveDynamicId(params, pathname, 'templates') as any;
  const router = useRouter();
  const { toast } = useToast();
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);
  const deviceService = useDevice();

  const {
    data: template,
    isLoading,
    error,
    refetch,
  } = useApi(
    () => deviceService.getTemplate(templateId),
    [templateId],
    {
      onError: (err) => {
        toast({
          title: 'Error loading template',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  const deleteTemplateMutation = useMutation(
    async (_: void) => {
      return deviceService.deleteTemplate(templateId);
    },
    {
      onSuccess: () => {
        toast({
          title: 'Template deleted',
          description: 'The template has been deleted successfully',
          variant: 'success',
        });
        router.push('/devices/templates');
      },
      onError: (err) => {
        toast({
          title: 'Error deleting template',
          description: err.message,
          variant: 'destructive',
        });
        setIsDeleteDialogOpen(false);
      },
    }
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin mx-auto" />
          <p className="mt-2 text-sm text-muted-foreground">Loading template...</p>
        </div>
      </div>
    );
  }

  if (error || !template) {
    return (
      <div className="flex flex-col gap-6">
        <Button variant="ghost" className="w-fit" onClick={() => router.push('/devices/templates')}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Templates
        </Button>
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Template</AlertTitle>
          <AlertDescription>
            {error?.message ?? 'Template not found'}
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

  const hasConfig = template.config && Object.keys(template.config).length > 0;
  const hasMatchRules = template.match_rules && Object.keys(template.match_rules).length > 0;

  return (
    <div className="flex flex-col gap-6">
      {/* Back navigation */}
      <Button variant="ghost" className="w-fit" onClick={() => router.push('/devices/templates')}>
        <ArrowLeft className="mr-2 h-4 w-4" />
        Back to Templates
      </Button>

      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-bold tracking-tight">{template.name}</h1>
            {getRoleBadge(template.role)}
          </div>
          {template.description && (
            <p className="text-muted-foreground max-w-2xl">{template.description}</p>
          )}
          <div className="flex items-center gap-4 text-sm text-muted-foreground">
            <span className="flex items-center gap-1">
              <Calendar className="h-3.5 w-3.5" />
              Created {formatDate(template.created_at)}
            </span>
            <span className="flex items-center gap-1">
              <Calendar className="h-3.5 w-3.5" />
              Updated {formatDate(template.updated_at)}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={() => router.push(`/devices/templates/${templateId}/edit`)}
          >
            <Pencil className="mr-2 h-4 w-4" />
            Edit Template
          </Button>
          <Button
            onClick={() => router.push(`/devices/templates/${templateId}/create-profile`)}
          >
            <Plus className="mr-2 h-4 w-4" />
            Create Profile from Template
          </Button>
          <Button
            variant="destructive"
            size="icon"
            onClick={() => setIsDeleteDialogOpen(true)}
          >
            <Trash2 className="h-4 w-4" />
            <span className="sr-only">Delete template</span>
          </Button>
        </div>
      </div>

      <Separator />

      {/* Content */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Template info */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Tag className="h-4 w-4" />
              Template Details
            </CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Template ID</span>
              <span className="text-sm font-mono">{template.id}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Tenant ID</span>
              <span className="text-sm font-mono">{template.tenant_id || '-'}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Device Role</span>
              {getRoleBadge(template.role)}
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Created</span>
              <span className="text-sm">{formatDate(template.created_at)}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Last Updated</span>
              <span className="text-sm">{formatDate(template.updated_at)}</span>
            </div>
          </CardContent>
        </Card>

        {/* Match Rules */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Tag className="h-4 w-4" />
              Match Rules
            </CardTitle>
            <CardDescription>
              Rules used to automatically match devices to this template
            </CardDescription>
          </CardHeader>
          <CardContent>
            {hasMatchRules ? (
              <div className="grid gap-2">
                {template.match_rules?.mac_prefix && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">MAC Prefix</span>
                    <span className="text-sm font-mono">{template.match_rules.mac_prefix}</span>
                  </div>
                )}
                {template.match_rules?.serial_prefix && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Serial Prefix</span>
                    <span className="text-sm font-mono">{template.match_rules.serial_prefix}</span>
                  </div>
                )}
                {template.match_rules?.model && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Model</span>
                    <span className="text-sm">{template.match_rules.model}</span>
                  </div>
                )}
                {template.match_rules?.model_pattern && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Model Pattern</span>
                    <span className="text-sm font-mono">{template.match_rules.model_pattern}</span>
                  </div>
                )}
                {template.match_rules?.manufacturer_match && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Manufacturer</span>
                    <span className="text-sm">{template.match_rules.manufacturer_match}</span>
                  </div>
                )}
                {template.match_rules?.tpm_vendor && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">TPM Vendor</span>
                    <span className="text-sm">{template.match_rules.tpm_vendor}</span>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No match rules configured</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Config Preview */}
      {hasConfig && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileText className="h-4 w-4" />
              Platform Configuration
            </CardTitle>
            <CardDescription>
              Full platform configuration embedded in this template
            </CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="rounded-md bg-muted p-4 text-sm font-mono overflow-auto max-h-96 whitespace-pre-wrap">
              {JSON.stringify(template.config, null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}

      {/* Delete Confirmation Dialog */}
      <Dialog open={isDeleteDialogOpen} onOpenChange={setIsDeleteDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Template</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete &quot;{template.name}&quot;? This action cannot be
              undone. Existing profiles created from this template will not be affected.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setIsDeleteDialogOpen(false)}
              disabled={deleteTemplateMutation.isLoading}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => deleteTemplateMutation.mutate(undefined)}
              disabled={deleteTemplateMutation.isLoading}
            >
              {deleteTemplateMutation.isLoading && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Delete Template
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
