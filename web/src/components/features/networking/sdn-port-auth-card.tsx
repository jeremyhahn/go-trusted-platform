'use client';

/**
 * SDNPortAuthCard authenticates a switch port with a certificate
 * (AuthenticatePort) and revokes it (RevokePortAuth) on
 * `POST|DELETE /api/v1/sdn/bridges/{name}/ports/{port}/auth` through
 * useSDNPortAuth, which calls the SDK SDNService. Revoking asks first.
 *
 * The switch may refuse with 409 while port authentication is not enforced;
 * the card shows that refusal verbatim and never claims the port is
 * authenticated unless the answer says so.
 *
 * Authenticate and Revoke are gated on the server's POST and DELETE .../auth
 * capabilities (#2033).
 */

import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Gated } from '@/components/features/capabilities/gated';
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
import { useSDNPortAuth } from '@/hooks/use-sdn-port-auth';
import type { PortAuth } from 'trusted-platform-sdk';

export type CertificateInputFormat = 'PEM' | 'DER';

/** The format the text looks like: 'PEM' when it contains "-----BEGIN ", else 'DER'. */
export function guessCertificateFormat(text: string): CertificateInputFormat {
  return text.includes('-----BEGIN ') ? 'PEM' : 'DER';
}

export interface SDNPortAuthCardProps {
  bridgeId: string;
  portId: string;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function SDNPortAuthCard({ bridgeId, portId }: SDNPortAuthCardProps) {
  const { toast } = useToast();
  const { authenticatePEM, authenticateDER, revoke } = useSDNPortAuth(bridgeId, portId);
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [format, setFormat] = useState<CertificateInputFormat>('PEM');
  const [certificate, setCertificate] = useState('');
  const [auth, setAuth] = useState<PortAuth | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refuse = (title: string, message: string) => {
    setRefusal(message);
    toast({ title, description: message, variant: 'destructive' });
  };

  const onCertificateChange = (text: string) => {
    if (certificate === '' && text !== '') {
      setFormat(guessCertificateFormat(text));
    }
    setCertificate(text);
  };

  const onAuthenticate = async () => {
    if (certificate.trim() === '') return;
    setBusy(true);
    try {
      const response = format === 'PEM' ? await authenticatePEM(certificate) : await authenticateDER(certificate);
      if (!response.success || !response.data) {
        refuse('Authenticate failed', response.error?.message || 'the switch did not answer');
        return;
      }
      const payload = response.data;
      const next = payload.auth ?? null;
      setAuth(next);
      setRefusal(null);
      if (next?.authenticated) {
        toast({
          title: 'Port authenticated',
          description: `Port ${portId} accepted ${next.certificateCn ?? 'the certificate'}`,
          variant: 'success',
        });
      } else {
        toast({
          title: 'Port not authenticated',
          description: payload.status?.message ?? 'the switch did not authenticate the port',
          variant: 'destructive',
        });
      }
    } catch (err) {
      refuse('Authenticate failed', errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const onRevoke = async () => {
    setConfirmRevoke(false);
    setBusy(true);
    try {
      const response = await revoke();
      if (!response.success) {
        refuse('Revoke failed', response.error?.message || 'the switch did not answer');
        return;
      }
      setAuth({ authenticated: false });
      setRefusal(null);
      toast({ title: 'Port authentication revoked', description: `Port ${portId}`, variant: 'success' });
    } catch (err) {
      refuse('Revoke failed', errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Port authentication</CardTitle>
        <CardDescription>
          Port {portId} on bridge {bridgeId}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {auth && (
          <div className="flex items-center gap-2">
            <Badge data-testid="sdn-port-auth-state" variant={auth.authenticated ? 'default' : 'secondary'}>
              {auth.authenticated ? 'Authenticated' : 'Not authenticated'}
            </Badge>
            {auth.certificateCn && (
              <span data-testid="sdn-port-auth-cn" className="text-sm text-muted-foreground">
                {auth.certificateCn}
              </span>
            )}
          </div>
        )}
        <div className="space-y-2">
          <Label htmlFor={`sdn-port-auth-format-${portId}`}>Format</Label>
          <select
            id={`sdn-port-auth-format-${portId}`}
            aria-label="Certificate format"
            className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            value={format}
            onChange={(e) => setFormat(e.target.value as CertificateInputFormat)}
          >
            <option value="PEM">PEM text</option>
            <option value="DER">DER, base64</option>
          </select>
        </div>
        <div className="space-y-2">
          <Label htmlFor={`sdn-port-auth-cert-${portId}`}>Certificate</Label>
          <Textarea
            id={`sdn-port-auth-cert-${portId}`}
            aria-label="Certificate"
            value={certificate}
            onChange={(e) => onCertificateChange(e.target.value)}
          />
        </div>
        {refusal && (
          <p role="alert" className="text-sm text-destructive">
            {refusal}
          </p>
        )}
        <div className="flex gap-2">
          <Gated op="POST /api/v1/sdn/bridges/{name}/ports/{port}/auth">
            <Button onClick={onAuthenticate} disabled={busy || certificate.trim() === ''}>
              Authenticate
            </Button>
          </Gated>
          <Gated op="DELETE /api/v1/sdn/bridges/{name}/ports/{port}/auth">
            <Button variant="destructive" onClick={() => setConfirmRevoke(true)} disabled={busy}>
              Revoke
            </Button>
          </Gated>
        </div>
        <Dialog open={confirmRevoke} onOpenChange={setConfirmRevoke}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Revoke port authentication?</DialogTitle>
              <DialogDescription>
                Port {portId} on bridge {bridgeId} loses its authentication and the VLANs it authorized.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setConfirmRevoke(false)}>
                Cancel
              </Button>
              <Gated op="DELETE /api/v1/sdn/bridges/{name}/ports/{port}/auth">
                <Button variant="destructive" onClick={onRevoke}>
                  Revoke
                </Button>
              </Gated>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}
