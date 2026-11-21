'use client';

import { useEffect, useState } from 'react';
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
import { useDNS, useMutation, useToast } from '@/hooks';

interface DNSZoneEditDialogProps {
  zoneName: string;
  ttl: number;
  description: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSaved: () => void;
}

// The record form's TTL bound (dns-record-form.tsx).
const MIN_TTL = 60;
const MAX_TTL = 86400;

/**
 * Edits a zone's default TTL and description through
 * client.dns.updateZone (PUT /dns/zones/{zone}).
 */
export function DNSZoneEditDialog({
  zoneName,
  ttl,
  description,
  open,
  onOpenChange,
  onSaved,
}: DNSZoneEditDialogProps) {
  const { toast } = useToast();
  const dns = useDNS();
  const [ttlText, setTtlText] = useState(String(ttl));
  const [descriptionText, setDescriptionText] = useState(description);
  const [ttlError, setTtlError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setTtlText(String(ttl));
      setDescriptionText(description);
      setTtlError(null);
    }
  }, [open, ttl, description]);

  const updateMutation = useMutation(
    (values: { ttl: number; description: string }) =>
      dns.updateZone({ name: zoneName, ttl: values.ttl, description: values.description }),
    {
      onSuccess: () => {
        toast({ title: 'Success', description: 'Zone updated' });
        onSaved();
        onOpenChange(false);
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: `Failed to update zone: ${error.message}`,
          variant: 'destructive',
        });
      },
    }
  );

  const handleSave = () => {
    const value = Number(ttlText);
    if (ttlText.trim() === '' || !Number.isInteger(value) || value < MIN_TTL || value > MAX_TTL) {
      setTtlError(`TTL must be a whole number from ${MIN_TTL} to ${MAX_TTL}.`);
      return;
    }
    setTtlError(null);
    updateMutation.mutate({ ttl: value, description: descriptionText });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit Zone</DialogTitle>
          <DialogDescription>
            Changes the default TTL and the description of {zoneName}.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="zone-ttl">TTL (seconds)</Label>
            <Input
              id="zone-ttl"
              type="number"
              min={MIN_TTL}
              max={MAX_TTL}
              value={ttlText}
              onChange={(e) => setTtlText(e.target.value)}
            />
            {ttlError && <p className="text-sm text-destructive">{ttlError}</p>}
          </div>
          <div className="space-y-2">
            <Label htmlFor="zone-description">Description</Label>
            <Input
              id="zone-description"
              value={descriptionText}
              onChange={(e) => setDescriptionText(e.target.value)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={updateMutation.isLoading}>
            {updateMutation.isLoading ? 'Saving...' : 'Save'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
