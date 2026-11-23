'use client';

/**
 * BMCCertCard runs the certificate operations of one BMC profile under
 * /api/v1/bmc/{profileID} through useBMCCertOps: EnrollBMC (the enrol
 * ceremony with its four options), RestoreFactoryCert and
 * ReplaceWebCertificate. The restore asks first in a dialog. The private key
 * PEM is never shown back and is cleared after the call. Server refusals are
 * shown verbatim.
 */
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import {
  failedCeremonySteps,
  replaceCertProblem,
  useBMCCertOps,
  type BMCCeremonyStep,
  type BMCEnrollOptions,
} from '@/hooks/use-bmc-cert-ops';

export const BMC_ENROLL_OPTIONS: { key: keyof BMCEnrollOptions; label: string }[] = [
  { key: 'replace_certificate', label: 'Replace certificate' },
  { key: 'rotate_password', label: 'Rotate password' },
  { key: 'dns_register', label: 'Register DNS' },
  { key: 'dane_publish', label: 'Publish DANE' },
];

export interface BMCCertCardProps {
  profileID: string;
}

interface CeremonyView {
  pin?: string;
  subject?: string;
  steps: BMCCeremonyStep[];
}

function stepLine(step: BMCCeremonyStep): string {
  const line = `${step.name}: ${step.ok ? 'ok' : 'failed'}`;
  return step.detail ? `${line} (${step.detail})` : line;
}

export function BMCCertCard({ profileID }: BMCCertCardProps) {
  const { enroll, restoreFactoryCert, replaceWebCertificate } = useBMCCertOps(profileID);
  const { toast } = useToast();
  const [opts, setOpts] = useState<BMCEnrollOptions>({});
  const [busy, setBusy] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [certPEM, setCertPEM] = useState('');
  const [keyPEM, setKeyPEM] = useState('');
  const [view, setView] = useState<CeremonyView | null>(null);

  const set = (key: keyof BMCEnrollOptions, value: boolean) =>
    setOpts((prev) => ({ ...prev, [key]: value }));

  const reportSteps = (steps: BMCCeremonyStep[] | undefined, title: string, incomplete: string) => {
    const failed = failedCeremonySteps(steps);
    if (failed.length === 0) {
      toast({ title, description: `BMC profile ${profileID}` });
    } else {
      toast({ title: incomplete, description: `failed steps: ${failed.join(', ')}`, variant: 'destructive' });
    }
  };

  const onEnroll = async () => {
    const body: BMCEnrollOptions = {};
    for (const { key } of BMC_ENROLL_OPTIONS) {
      if (opts[key] !== undefined) body[key] = opts[key];
    }
    setBusy(true);
    try {
      const res = await enroll(body);
      if (res.success && res.data) {
        setView({
          pin: res.data.pin_spki_sha256,
          subject: res.data.factory_cert_meta?.subject,
          steps: res.data.steps ?? [],
        });
        reportSteps(res.data.steps, 'Enrolled', 'Enrolment incomplete');
      } else {
        toast({ title: 'Enroll failed', description: res.error?.message ?? 'Unknown error', variant: 'destructive' });
      }
    } finally {
      setBusy(false);
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

  const onReplace = async () => {
    const req = { cert_pem: certPEM, key_pem: keyPEM };
    const problem = replaceCertProblem(req);
    if (problem) {
      toast({ title: 'Replace web certificate failed', description: problem, variant: 'destructive' });
      return;
    }
    setBusy(true);
    try {
      const res = await replaceWebCertificate(req);
      if (res.success) {
        toast({ title: 'Web certificate replaced', description: `BMC profile ${profileID}` });
        setCertPEM('');
      } else {
        toast({
          title: 'Replace web certificate failed',
          description: res.error?.message ?? 'Unknown error',
          variant: 'destructive',
        });
      }
    } finally {
      setKeyPEM('');
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>BMC certificate</CardTitle>
        <CardDescription>Enrol the BMC, restore its factory certificate or replace its web certificate.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <section className="space-y-3">
          <div className="grid grid-cols-2 gap-2">
            {BMC_ENROLL_OPTIONS.map(({ key, label }) => (
              <div key={key} className="flex items-center gap-2">
                <Checkbox
                  id={`bmc-enroll-${key}`}
                  aria-label={label}
                  checked={opts[key] === true}
                  onCheckedChange={(v) => set(key, v === true)}
                  disabled={busy}
                />
                <Label htmlFor={`bmc-enroll-${key}`}>{label}</Label>
              </div>
            ))}
          </div>
          <Button onClick={onEnroll} disabled={busy}>
            Enroll
          </Button>
        </section>

        <section>
          <Button variant="destructive" onClick={() => setConfirmOpen(true)} disabled={busy}>
            Restore factory certificate
          </Button>
        </section>

        {view && (
          <section className="space-y-2 text-sm">
            {view.pin !== undefined && (
              <p>
                SPKI pin: <code data-testid="bmc-cert-pin">{view.pin}</code>
              </p>
            )}
            {view.subject && <p>Subject: {view.subject}</p>}
            <ul data-testid="bmc-cert-steps">
              {view.steps.map((step, i) => (
                <li key={`${step.name}-${i}`}>{stepLine(step)}</li>
              ))}
            </ul>
          </section>
        )}

        <section className="space-y-3">
          <Textarea
            aria-label="Certificate PEM"
            value={certPEM}
            onChange={(e) => setCertPEM(e.target.value)}
            disabled={busy}
          />
          <Textarea
            aria-label="Private key PEM"
            value={keyPEM}
            onChange={(e) => setKeyPEM(e.target.value)}
            disabled={busy}
          />
          <Button onClick={onReplace} disabled={busy}>
            Replace web certificate
          </Button>
        </section>
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
            <Button variant="destructive" onClick={onRestore} disabled={busy}>
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
