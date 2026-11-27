'use client';

/**
 * BMCCertCard runs the certificate operations of one BMC profile under
 * /api/v1/bmc/{profileID} through useBMCCertOps. It offers RestoreFactoryCert
 * only, asking first in a dialog; server refusals are shown verbatim.
 * Enrolment and web certificate replacement are held back: the profile
 * enrolment path cannot capture a trust pin yet, and a replace leaves the
 * stored pin stale, so neither is offered until the server updates the pin.
 */
import { useState } from 'react';
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
import { useToast } from '@/hooks/use-toast';
import { Gated } from '@/components/features/capabilities/gated';
import { failedCeremonySteps, useBMCCertOps, type BMCCeremonyStep } from '@/hooks/use-bmc-cert-ops';

// The webservice's route op the restore control is gated on.
const RESTORE_OP = 'POST /api/v1/bmc/{profileID:[0-9]+}/cert/restore';

export interface BMCCertCardProps {
  profileID: string;
}

interface CeremonyView {
  subject?: string;
  steps: BMCCeremonyStep[];
}

function stepLine(step: BMCCeremonyStep): string {
  const line = `${step.name}: ${step.ok ? 'ok' : 'failed'}`;
  return step.detail ? `${line} (${step.detail})` : line;
}

export function BMCCertCard({ profileID }: BMCCertCardProps) {
  const { restoreFactoryCert } = useBMCCertOps(profileID);
  const { toast } = useToast();
  const [busy, setBusy] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [view, setView] = useState<CeremonyView | null>(null);

  const reportSteps = (steps: BMCCeremonyStep[] | undefined, title: string, incomplete: string) => {
    const failed = failedCeremonySteps(steps);
    if (failed.length === 0) {
      toast({ title, description: `BMC profile ${profileID}` });
    } else {
      toast({ title: incomplete, description: `failed steps: ${failed.join(', ')}`, variant: 'destructive' });
    }
  };

  const onRestore = async () => {
    setBusy(true);
    try {
      const res = await restoreFactoryCert();
      if (res.success && res.data) {
        setView({ subject: res.data.new_cert_meta?.subject, steps: res.data.steps ?? [] });
        reportSteps(res.data.steps, 'Factory certificate restored', 'Restore incomplete');
      } else {
        toast({ title: 'Restore failed', description: res.error?.message ?? 'Unknown error', variant: 'destructive' });
      }
    } finally {
      setConfirmOpen(false);
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>BMC certificate</CardTitle>
        <CardDescription>Restore the BMC&apos;s factory certificate.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <p className="text-sm text-muted-foreground" data-testid="bmc-cert-held-back">
          Enrolment and web certificate replacement are unavailable until the server updates the BMC trust pin.
        </p>

        <section>
          <Gated op={RESTORE_OP}>
            <Button variant="destructive" onClick={() => setConfirmOpen(true)} disabled={busy}>
              Restore factory certificate
            </Button>
          </Gated>
        </section>

        {view && (
          <section className="space-y-2 text-sm">
            {view.subject && <p>Subject: {view.subject}</p>}
            <ul data-testid="bmc-cert-steps">
              {view.steps.map((step, i) => (
                <li key={`${step.name}-${i}`}>{stepLine(step)}</li>
              ))}
            </ul>
          </section>
        )}
      </CardContent>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Restore the factory certificate?</DialogTitle>
            <DialogDescription>
              This replaces the web certificate of BMC profile {profileID} with a new one from the factory ceremony.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)} disabled={busy}>
              Cancel
            </Button>
            <Gated op={RESTORE_OP}>
              <Button variant="destructive" onClick={onRestore} disabled={busy}>
                Confirm
              </Button>
            </Gated>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
