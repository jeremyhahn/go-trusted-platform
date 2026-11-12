"use client";

/**
 * Dialogs and the profile-assignment panel of the device templates page
 * (#1737): template details (GetTemplate), edit (UpdateTemplate), a confirm
 * dialog for destructive actions (DeleteTemplate, UnassignProfileFromDevice),
 * create profile from template (CreateProfileFromTemplate), and the config
 * lookup / assign / unassign panel (FindConfigForDevice,
 * AssignProfileToDevice, UnassignProfileFromDevice).
 */
import { useEffect, useRef, useState } from 'react';
import { Loader2, Search, Link2, Unlink } from 'lucide-react';
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
import { useToast, useDeviceTemplateActions } from '@/hooks';
import type {
  DeviceProfile,
  DeviceTemplate,
  UpdateDeviceTemplateRequest,
} from 'trusted-platform-sdk';
import { ASSIGNABLE_DEVICE_ROLES, deviceRoleLabel, toDeviceRole } from '@/lib/device-role';
import { profileOverrides } from '@/lib/device-profile-networks';

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : 'Unknown error';
}

// ============================================================================
// Confirm dialog
// ============================================================================

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel: string;
  pending?: boolean;
  onConfirm: () => void | Promise<void>;
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  pending,
  onConfirm,
}: ConfirmDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            type="button"
            variant="destructive"
            disabled={pending}
            onClick={() => void onConfirm()}
          >
            {pending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ============================================================================
// Template details (GetTemplate)
// ============================================================================

export interface TemplateDetailsDialogProps {
  templateId: string | null;
  onOpenChange: (open: boolean) => void;
  onOpenPage: (id: string) => void;
}

export function TemplateDetailsDialog({
  templateId,
  onOpenChange,
  onOpenPage,
}: TemplateDetailsDialogProps) {
  const { getTemplate } = useDeviceTemplateActions();
  const fetchTemplate = getTemplate.mutateAsync;
  // The answer the dialog owns, tagged with the id it was requested for.
  const [shown, setShown] = useState<{ id: string; template?: DeviceTemplate; error?: string } | null>(
    null,
  );

  useEffect(() => {
    if (templateId === null) {
      return undefined;
    }
    // A superseded request (the dialog closed or moved to another id) is
    // ignored when it completes, whatever order the responses arrive in.
    let active = true;
    fetchTemplate(templateId).then(
      (t) => {
        if (active) setShown({ id: templateId, template: t });
      },
      (err) => {
        if (active) setShown({ id: templateId, error: errorMessage(err) });
      },
    );
    return () => {
      active = false;
    };
    // fetchTemplate is stable per mount; refetch only when the id changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [templateId]);

  // Show only the answer for the id on display, never a previous one.
  const current = shown !== null && shown.id === templateId ? shown : null;
  const template =
    current?.template && String(current.template.id) === templateId ? current.template : null;
  const loadError = current?.error ?? null;

  return (
    <Dialog open={templateId !== null} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Template Details</DialogTitle>
          <DialogDescription>The template as the server stores it</DialogDescription>
        </DialogHeader>
        {loadError ? (
          <p className="text-sm text-destructive">{loadError}</p>
        ) : !template ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading template...
          </div>
        ) : (
          <dl className="grid grid-cols-3 gap-2 text-sm" data-testid="template-details">
            <dt className="text-muted-foreground">Name</dt>
            <dd className="col-span-2 font-medium">{template.name}</dd>
            <dt className="text-muted-foreground">Description</dt>
            <dd className="col-span-2">{template.description || '-'}</dd>
            <dt className="text-muted-foreground">Role</dt>
            <dd className="col-span-2">{deviceRoleLabel(template.role)}</dd>
            <dt className="text-muted-foreground">Config</dt>
            <dd className="col-span-2">
              <pre className="max-h-48 overflow-auto rounded bg-muted p-2 text-xs">
                {JSON.stringify(template.config ?? {}, null, 2)}
              </pre>
            </dd>
          </dl>
        )}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
          {templateId !== null && (
            <Button type="button" onClick={() => onOpenPage(templateId)}>
              Open Page
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ============================================================================
// Edit template (UpdateTemplate)
// ============================================================================

export interface EditTemplateDialogProps {
  template: DeviceTemplate | null;
  onOpenChange: (open: boolean) => void;
  pending?: boolean;
  onSave: (request: UpdateDeviceTemplateRequest) => void | Promise<void>;
}

export function EditTemplateDialog({
  template,
  onOpenChange,
  pending,
  onSave,
}: EditTemplateDialogProps) {
  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!template) {
      return;
    }
    const formData = new FormData(event.currentTarget);
    void onSave({
      id: template.id,
      name: formData.get('name') as string,
      description: (formData.get('description') as string) ?? '',
      role: toDeviceRole(formData.get('role')),
      // PUT replaces the stored template: send the unedited fields back
      // unchanged, or the server erases them.
      tenant_id: template.tenant_id,
      config: template.config,
      match_rules: template.match_rules,
    });
  };

  return (
    <Dialog open={template !== null} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Edit Device Template</DialogTitle>
          <DialogDescription>Change the template&apos;s name, description or role</DialogDescription>
        </DialogHeader>
        {template && (
          <form onSubmit={handleSubmit}>
            <div className="grid gap-4 py-4">
              <div className="grid gap-2">
                <Label htmlFor="edit-name">Template Name</Label>
                <Input id="edit-name" name="name" defaultValue={template.name} required />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="edit-description">Description</Label>
                <Textarea
                  id="edit-description"
                  name="description"
                  defaultValue={template.description}
                  rows={3}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="edit-role">Device Role</Label>
                <Select name="role" defaultValue={template.role}>
                  <SelectTrigger id="edit-role">
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
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={pending}>
                {pending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Save Changes
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

// ============================================================================
// Create profile from template (CreateProfileFromTemplate)
// ============================================================================

export interface CreateProfileDialogProps {
  template: DeviceTemplate | null;
  onOpenChange: (open: boolean) => void;
  pending?: boolean;
  onCreate: (overrides: Partial<DeviceProfile> | undefined) => void | Promise<void>;
}

export function CreateProfileDialog({
  template,
  onOpenChange,
  pending,
  onCreate,
}: CreateProfileDialogProps) {
  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    void onCreate(
      profileOverrides({
        staticIp: '',
        ekSerial: (formData.get('ekSerial') as string) ?? '',
        macAddress: (formData.get('macAddress') as string) ?? '',
      }),
    );
  };

  return (
    <Dialog open={template !== null} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Create Profile from Template</DialogTitle>
          <DialogDescription>
            {template ? `A new device profile from "${template.name}"` : ''}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="cp-ek-serial">EK Serial Number</Label>
              <Input id="cp-ek-serial" name="ekSerial" />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="cp-mac">MAC Address</Label>
              <Input id="cp-mac" name="macAddress" />
            </div>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {pending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Create Profile
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ============================================================================
// Profile assignment panel (FindConfigForDevice, Assign, Unassign)
// ============================================================================

export function ProfileAssignmentPanel() {
  const { toast } = useToast();
  const { findConfig, assign, unassign } = useDeviceTemplateActions();
  const [ekSerial, setEkSerial] = useState('');
  const [macAddress, setMacAddress] = useState('');
  const [profileId, setProfileId] = useState('');
  const [found, setFound] = useState<DeviceProfile | null | undefined>(undefined);
  const [confirmUnassign, setConfirmUnassign] = useState(false);
  // Each lookup takes a sequence number; an identity edit bumps it, so a
  // response for an earlier lookup or an earlier identity is discarded.
  const lookupSeq = useRef(0);
  // True while profileId holds the lookup's answer, not the operator's entry.
  const autoProfile = useRef(false);

  const identityChanged = () => {
    lookupSeq.current++;
    setFound(undefined);
    if (autoProfile.current) {
      autoProfile.current = false;
      setProfileId('');
    }
  };

  const handleFind = async () => {
    const seq = ++lookupSeq.current;
    try {
      const result = await findConfig.mutateAsync({ ekSerial, macAddress });
      if (seq !== lookupSeq.current) return;
      setFound(result ?? null);
      if (result?.id) {
        setProfileId(String(result.id));
        autoProfile.current = true;
      }
    } catch (err) {
      if (seq !== lookupSeq.current) return;
      setProfileId('');
      autoProfile.current = false;
      // No matching profile is a 404 (ErrNoMatchingConfig), not an error.
      if ((err as { status?: number }).status === 404) {
        setFound(null);
        return;
      }
      setFound(undefined);
      toast({ title: 'Config lookup failed', description: errorMessage(err), variant: 'destructive' });
    }
  };

  const handleAssign = async () => {
    try {
      await assign.mutateAsync({
        // A decimal string: generated ids exceed 2^53 and Number() rounds them.
        profileId: profileId.trim(),
        ekSerial: ekSerial || undefined,
        macAddress: macAddress || undefined,
      });
      toast({
        title: 'Profile assigned',
        description: `Profile ${profileId} is bound to the device`,
        variant: 'success',
      });
    } catch (err) {
      toast({ title: 'Error assigning profile', description: errorMessage(err), variant: 'destructive' });
    }
  };

  const handleUnassign = async () => {
    try {
      await unassign.mutateAsync(profileId.trim());
      toast({
        title: 'Profile unassigned',
        description: `Profile ${profileId} is back in the unassigned pool`,
        variant: 'success',
      });
    } catch (err) {
      toast({ title: 'Error unassigning profile', description: errorMessage(err), variant: 'destructive' });
    } finally {
      setConfirmUnassign(false);
    }
  };

  const hasIdentity = ekSerial.trim() !== '' || macAddress.trim() !== '';
  const hasProfile = /^[0-9]+$/.test(profileId.trim());

  return (
    <Card data-testid="profile-assignment">
      <CardHeader>
        <CardTitle>Profile Assignment</CardTitle>
        <CardDescription>
          Look up the config a device receives, and bind a profile to a device or release it
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="grid gap-4 md:grid-cols-3">
          <div className="grid gap-2">
            <Label htmlFor="pa-ek-serial">EK Serial Number</Label>
            <Input id="pa-ek-serial" value={ekSerial} onChange={(e) => {
                setEkSerial(e.target.value);
                identityChanged();
              }}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="pa-mac">MAC Address</Label>
            <Input id="pa-mac" value={macAddress} onChange={(e) => {
                setMacAddress(e.target.value);
                identityChanged();
              }}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="pa-profile-id">Profile ID</Label>
            <Input id="pa-profile-id" value={profileId} onChange={(e) => {
                autoProfile.current = false;
                setProfileId(e.target.value);
              }}
            />
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={() => void handleFind()} disabled={!hasIdentity || findConfig.isLoading}>
            <Search className="mr-2 h-4 w-4" />
            Find Config
          </Button>
          <Button onClick={() => void handleAssign()} disabled={!hasProfile || !hasIdentity || assign.isLoading}>
            <Link2 className="mr-2 h-4 w-4" />
            Assign Profile
          </Button>
          <Button
            variant="destructive"
            onClick={() => setConfirmUnassign(true)}
            disabled={!hasProfile || unassign.isLoading}
          >
            <Unlink className="mr-2 h-4 w-4" />
            Unassign Profile
          </Button>
        </div>
        {found !== undefined && (
          <p className="text-sm" data-testid="find-config-result">
            {found === null
              ? 'No profile matches this device'
              : `Matching profile: ${found.name} (ID ${found.id})`}
          </p>
        )}
        <ConfirmDialog
          open={confirmUnassign}
          onOpenChange={setConfirmUnassign}
          title="Unassign profile?"
          description={`Profile ${profileId} loses its device binding and returns to the unassigned pool.`}
          confirmLabel="Unassign"
          pending={unassign.isLoading}
          onConfirm={handleUnassign}
        />
      </CardContent>
    </Card>
  );
}
