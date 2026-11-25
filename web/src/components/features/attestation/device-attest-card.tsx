'use client';

/**
 * DeviceAttestCard — verify a device's quote evidence against a server-issued
 * challenge (#2048).
 *
 * "Issue challenge" calls POST /api/v1/devices/{id}/attest/challenge through
 * the SDK; the operator makes the quote evidence over the returned nonce and
 * "Verify evidence" sends it with the challenge_id to
 * POST /api/v1/devices/{id}/attest. The challenge is single-use: the server
 * consumes it on every verify, so the card forgets it either way. Both
 * controls sit behind the capability gate, and a refusal is shown verbatim.
 */

import { useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Gated } from '@/components/features/capabilities/gated';
import { useDevice } from '@/hooks';
import type { DeviceAttestChallengeResponse, DeviceAttestResponse } from 'trusted-platform-sdk';

interface DeviceAttestCardProps {
  deviceId: string;
}

const CHECKS: { id: string; label: string; passed: (r: DeviceAttestResponse) => boolean }[] = [
  { id: 'signature', label: 'Quote signature', passed: (r) => r.signature_valid },
  { id: 'nonce', label: 'Nonce is the challenge', passed: (r) => r.nonce_valid },
  { id: 'pcrs', label: 'PCRs match the baseline', passed: (r) => r.pcrs_valid },
  { id: 'ak', label: 'AK certificate chains to the platform CA', passed: (r) => r.ak_certificate_verified },
];

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function DeviceAttestCard({ deviceId }: DeviceAttestCardProps) {
  const deviceService = useDevice();
  const [challenge, setChallenge] = useState<DeviceAttestChallengeResponse | null>(null);
  const [evidence, setEvidence] = useState('');
  const [result, setResult] = useState<DeviceAttestResponse | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const handleChallenge = async () => {
    setBusy(true);
    setResult(null);
    setRefusal(null);
    try {
      const response = await deviceService.issueAttestationChallenge(deviceId);
      if (response.success && response.data) {
        setChallenge(response.data);
      } else {
        setChallenge(null);
        setRefusal(response.error?.message || 'The control plane issued no challenge');
      }
    } catch (err) {
      setChallenge(null);
      setRefusal(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const handleVerify = async () => {
    if (!challenge) return;
    setBusy(true);
    setResult(null);
    setRefusal(null);
    try {
      const response = await deviceService.attestDevice(deviceId, {
        evidence: evidence.trim(),
        challenge_id: challenge.challenge_id,
      });
      if (response.success && response.data) {
        setResult(response.data);
      } else {
        setRefusal(response.error?.message || 'The control plane did not verify the evidence');
      }
    } catch (err) {
      setRefusal(errorText(err));
    } finally {
      // The server consumes the challenge on every verify.
      setChallenge(null);
      setBusy(false);
    }
  };

  const canVerify = challenge !== null && evidence.trim() !== '' && !busy;

  return (
    <Card data-testid="device-attest-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5" />
          Verify attestation
        </CardTitle>
        <CardDescription>
          Issue a single-use challenge, make the quote evidence over its nonce, then send the evidence
          for the control plane to verify.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <Gated op="POST /api/v1/devices/{id}/attest/challenge">
            <Button variant="outline" size="sm" onClick={handleChallenge} disabled={busy}>
              Issue challenge
            </Button>
          </Gated>
        </div>

        {challenge && (
          <div className="space-y-1">
            <p className="text-sm font-medium">Nonce</p>
            <code
              data-testid="device-attest-nonce"
              className="block rounded bg-muted p-2 text-xs font-mono break-all whitespace-pre-wrap"
            >
              {challenge.nonce}
            </code>
            <p className="text-xs text-muted-foreground">
              Expires <span data-testid="device-attest-expires">{challenge.expires_at}</span>
            </p>
          </div>
        )}

        <div className="space-y-2">
          <Label htmlFor="device-attest-evidence">Evidence (base64)</Label>
          <Textarea
            id="device-attest-evidence"
            value={evidence}
            onChange={(e) => setEvidence(e.target.value)}
            disabled={busy}
            rows={4}
            className="font-mono text-xs"
          />
        </div>

        <Gated op="POST /api/v1/devices/{id}/attest">
          <Button size="sm" onClick={handleVerify} disabled={!canVerify}>
            Verify evidence
          </Button>
        </Gated>

        {refusal !== null && (
          <Alert variant="destructive">
            <AlertTitle>Attestation refused</AlertTitle>
            <AlertDescription data-testid="device-attest-refusal" className="whitespace-pre-wrap break-words">
              {refusal}
            </AlertDescription>
          </Alert>
        )}

        {result && (
          <div className="space-y-2">
            <p className="text-sm font-medium" data-testid="device-attest-verdict">
              {result.verified ? 'Verified' : 'Not verified'}
            </p>
            <ul className="space-y-1 text-sm">
              {CHECKS.map((check) => {
                const passed = check.passed(result);
                return (
                  <li
                    key={check.id}
                    data-testid={`device-attest-check-${check.id}`}
                    data-passed={passed ? 'true' : 'false'}
                  >
                    {passed ? '✓' : '✗'} {check.label}
                  </li>
                );
              })}
            </ul>
            <p className="text-xs text-muted-foreground">Status: {result.attestation_status}</p>
            {result.message && <p className="text-sm">{result.message}</p>}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
