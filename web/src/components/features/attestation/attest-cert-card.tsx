'use client';

/**
 * AttestCertCard — the device's recorded attestation (IAK/AK) certificate and
 * the "Record certificate" action (docs/device/api.md §4.5, #491).
 *
 * A device enrolled before the control plane recorded certificates (#447) has
 * none, and the verifier denies its quotes until one is recorded. The action
 * calls POST /api/v1/devices/{id}/attest-cert/record through the SDK. The
 * server fails closed with no override, so neither does this card: the dialog
 * offers only the opt-in CA re-issuance, and a refusal is shown verbatim
 * because its text names every candidate and why it was refused.
 */

import { useState } from 'react';
import { FileBadge, Shield } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
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
import { useDevice, useToast } from '@/hooks';
import type { RecordAttestCertResponse } from 'trusted-platform-sdk';

interface AttestCertCardProps {
  deviceId: string;
  /** The PEM certificate on the device record; absent when none is recorded */
  attestCert?: string;
  /** Called after a certificate is recorded so the page re-reads the device */
  onRecorded: () => void;
}

const SOURCE_LABELS: Record<RecordAttestCertResponse['source'], string> = {
  device: 'the certificate already on the record',
  ca: 'the platform CA certificate store',
  reissued: 'a certificate the platform CA re-issued',
};

export function AttestCertCard({ deviceId, attestCert, onRecorded }: AttestCertCardProps) {
  const deviceService = useDevice();
  const { toast } = useToast();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [reissue, setReissue] = useState(false);
  const [isRecording, setIsRecording] = useState(false);
  const [refusal, setRefusal] = useState<string | null>(null);

  const openDialog = () => {
    setReissue(false);
    setRefusal(null);
    setDialogOpen(true);
  };

  const handleRecord = async () => {
    setIsRecording(true);
    setRefusal(null);
    try {
      const response = await deviceService.recordAttestCert(deviceId, { reissue });
      if (response.success && response.data) {
        const result = response.data;
        toast({
          title: result.changed ? 'Certificate recorded' : 'Certificate already recorded',
          description: result.changed
            ? `Recorded from ${SOURCE_LABELS[result.source]}; the next collection verifies quotes against it.`
            : 'The record already held this certificate; nothing was written.',
        });
        setDialogOpen(false);
        onRecorded();
      } else {
        setRefusal(response.error?.message || 'The control plane did not record a certificate');
      }
    } catch (err) {
      setRefusal(err instanceof Error ? err.message : String(err));
    } finally {
      setIsRecording(false);
    }
  };

  return (
    <Card data-testid="attest-cert-card">
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Attestation Certificate
          </CardTitle>
          <CardDescription>
            The IAK certificate on the device record. Quotes are trusted only when it chains to the
            platform CA and carries tcg-cap-verifiedTPMRestricted.
          </CardDescription>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={openDialog}
          title="Record a certificate that chains to the platform CA, carries tcg-cap-verifiedTPMRestricted and certifies the enrolled attestation key"
        >
          <FileBadge className="mr-2 h-4 w-4" />
          Record certificate
        </Button>
      </CardHeader>
      <CardContent>
        {attestCert ? (
          <code className="block rounded bg-muted p-2 text-xs font-mono break-all whitespace-pre-wrap">
            {attestCert}
          </code>
        ) : (
          <p className="text-sm text-muted-foreground" data-testid="attest-cert-absent">
            No attestation certificate is recorded. The verifier denies this device&apos;s quotes until
            one is.
          </p>
        )}
      </CardContent>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="sm:max-w-[560px]">
          <DialogHeader>
            <DialogTitle>Record attestation certificate</DialogTitle>
            <DialogDescription>
              The control plane tries the certificate already on the record, then the platform CA
              store under the device&apos;s names, and records the first that verifies. Nothing is
              written if none does.
            </DialogDescription>
          </DialogHeader>

          <div className="flex items-start gap-3">
            <Checkbox
              id="attest-cert-reissue"
              checked={reissue}
              onCheckedChange={(checked) => setReissue(checked === true)}
              disabled={isRecording}
              className="mt-1"
            />
            <div className="space-y-1">
              <Label htmlFor="attest-cert-reissue">Re-issue from the platform CA</Label>
              <p className="text-sm text-muted-foreground">
                If no existing certificate verifies, ask the CA to issue one over the enrolled
                attestation key.
              </p>
            </div>
          </div>

          {reissue && (
            <Alert variant="warning" data-testid="attest-cert-reissue-warning">
              <AlertTitle>The CA will issue a new certificate</AlertTitle>
              <AlertDescription>
                It is recorded only if it carries tcg-cap-verifiedTPMRestricted. If the CA&apos;s
                profile omits it, the control plane refuses and revokes the new certificate.
              </AlertDescription>
            </Alert>
          )}

          {refusal !== null && (
            <Alert variant="destructive">
              <AlertTitle>Certificate not recorded</AlertTitle>
              <AlertDescription data-testid="attest-cert-refusal" className="whitespace-pre-wrap break-words">
                {refusal}
              </AlertDescription>
            </Alert>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)} disabled={isRecording}>
              Cancel
            </Button>
            <Button onClick={handleRecord} disabled={isRecording}>
              {reissue ? 'Record and re-issue' : 'Record'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
