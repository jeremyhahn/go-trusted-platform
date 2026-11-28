'use client';

/**
 * TemplateEditDialog edits a device template's name, description and role
 * through DeviceService.updateTemplate (PUT /api/v1/device/templates/{id}).
 * The server keeps the stored tenant, config and match rules the PUT leaves
 * out, so the dialog sends only what it edits (#2049).
 */

import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import type { DeviceRole, DeviceTemplate } from 'trusted-platform-sdk';

import { Gated } from '@/components/features/capabilities/gated';
import { Button } from '@/components/ui/button';
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { useDevice, useToast } from '@/hooks';
import { ASSIGNABLE_DEVICE_ROLES, deviceRoleLabel } from '@/lib/device-role';

export const UPDATE_TEMPLATE_OP = 'PUT /api/v1/device/templates/{id:[0-9]+}';

export interface TemplateEditDialogProps {
  template: DeviceTemplate;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSaved: () => void;
}

export function TemplateEditDialog({ template, open, onOpenChange, onSaved }: TemplateEditDialogProps) {
  const deviceService = useDevice();
  const { toast } = useToast();
  const [name, setName] = useState(template.name);
  const [description, setDescription] = useState(template.description ?? '');
  const [role, setRole] = useState<DeviceRole>(template.role);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (open) {
      setName(template.name);
      setDescription(template.description ?? '');
      setRole(template.role);
    }
  }, [open, template]);

  const fail = (message: string) =>
    toast({ title: 'Error saving template', description: message, variant: 'destructive' });

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!name.trim()) return;
    setSaving(true);
    try {
      const res = await deviceService.updateTemplate({
        id: String(template.id),
        name: name.trim(),
        description,
        role,
      });
      if (res.success === false) {
        fail(res.error?.message ?? 'Unknown error');
        return;
      }
      toast({
        title: 'Template saved',
        description: `"${name.trim()}" has been updated`,
        variant: 'success',
      });
      onSaved();
    } catch (err) {
      fail(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Edit template</DialogTitle>
          <DialogDescription>
            Change the template&apos;s name, description and device role. Its config and match
            rules are kept.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="template-edit-name">Name</Label>
              <Input
                id="template-edit-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="template-edit-description">Description</Label>
              <Textarea
                id="template-edit-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="template-edit-role">Device Role</Label>
              <Select value={role} onValueChange={(value) => setRole(value as DeviceRole)}>
                <SelectTrigger id="template-edit-role">
                  <SelectValue placeholder="Select device role" />
                </SelectTrigger>
                <SelectContent>
                  {ASSIGNABLE_DEVICE_ROLES.map((r) => (
                    <SelectItem key={r} value={r}>
                      {deviceRoleLabel(r)}
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
            <Gated op={UPDATE_TEMPLATE_OP}>
              <Button type="submit" disabled={saving || !name.trim()}>
                {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Save template
              </Button>
            </Gated>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
