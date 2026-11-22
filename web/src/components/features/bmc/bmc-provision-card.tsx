'use client';

/**
 * BMCProvisionCard shows and starts bare-metal provisioning of a BMC host (#2039).
 *
 * It reads BMCService.ProvisionStatus (`GET /bmc/{profileID}/provision`)
 * through useBMCStatus on mount and on Refresh, and runs Provision
 * (`POST /bmc/{profileID}/provision`, an optional ISO URL). Provision reboots
 * the host into the installer, so the card asks in a dialog first. Refusals
 * from the control plane are shown verbatim.
 */

import { useCallback, useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Gated } from '@/components/features/capabilities/gated';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
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
import { useToast } from '@/hooks';
import { isProvisionDone, useBMCStatus, type BMCProvisionResult } from '@/hooks/use-bmc-status';

// The server's op for Provision (pkg/webservice/v1/bmc/routes.go).
const BMC_PROVISION_OP = 'POST /api/v1/bmc/{profileID:[0-9]+}/provision';

export interface BMCProvisionCardProps {
  profileID: string;
}

export function BMCProvisionCard({ profileID }: BMCProvisionCardProps) {
  const { getProvisionStatus, provision } = useBMCStatus(profileID);
  const { toast } = useToast();
  const [result, setResult] = useState<BMCProvisionResult | null>(null);
  const [statusNote, setStatusNote] = useState<string | null>(null);
  const [isoURL, setISOURL] = useState('');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    const res = await getProvisionStatus();
    if (res.success && res.data) {
      setResult(res.data);
      setStatusNote(null);
    } else {
      setResult(null);
      setStatusNote(res.error?.message ?? 'request failed');
    }
  }, [getProvisionStatus]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const running = result !== null && !isProvisionDone(result.status);
  const iso = isoURL.trim();

  const confirm = async () => {
    setBusy(true);
    setConfirmOpen(false);
    const res = await provision(isoURL);
    if (res.success && res.data) {
      setResult(res.data);
      setStatusNote(null);
      toast({ title: 'Provision started', description: res.data.provision_id, variant: 'success' });
    } else {
      toast({
        title: 'Provision refused',
        description: res.error?.message ?? 'request failed',
        variant: 'destructive',
      });
    }
    setBusy(false);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>BMC provisioning</CardTitle>
        <CardDescription>BMC profile {profileID}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div data-testid="bmc-provision-status" className="space-y-1 text-sm">
          {result ? (
            <>
              <div className="flex items-center gap-2">
                <Badge variant={result.status === 'failed' ? 'destructive' : 'secondary'}>{result.status}</Badge>
                <span>{isProvisionDone(result.status) ? 'Finished' : 'In progress'}</span>
              </div>
              {result.message && <p>{result.message}</p>}
              <p>Provision {result.provision_id}</p>
            </>
          ) : statusNote !== null ? (
            <p>No provision: {statusNote}</p>
          ) : null}
        </div>
        <div className="space-y-2">
          <Label htmlFor="bmc-provision-iso">ISO URL (optional)</Label>
          <Input
            id="bmc-provision-iso"
            placeholder="https://images.example/installer.iso"
            value={isoURL}
            onChange={(e) => setISOURL(e.target.value)}
          />
        </div>
        <div className="flex gap-2">
          <Gated op={BMC_PROVISION_OP}>
            <Button variant="destructive" disabled={busy || running} onClick={() => setConfirmOpen(true)}>
              Provision
            </Button>
          </Gated>
          <Button variant="outline" size="sm" onClick={() => void reload()}>
            Refresh
          </Button>
        </div>
      </CardContent>
      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Provision this host?</DialogTitle>
            <DialogDescription>
              This reboots the host of BMC profile {profileID} into the installer.
              {iso && ` ISO: ${iso}`}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={() => void confirm()}>
              Confirm provision
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
