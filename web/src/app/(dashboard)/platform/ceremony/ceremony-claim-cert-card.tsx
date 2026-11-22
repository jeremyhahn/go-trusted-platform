"use client";

/**
 * CeremonyClaimCertCard lets an officer claim their certificate through
 * CeremonyService.ClaimCertBegin and ClaimCertComplete on `useCeremony()`
 * (`POST /api/v1/ceremony/claim-cert/begin` and
 * `POST /api/v1/ceremony/claim-cert/complete`). The officer signs the nonce
 * on their own authenticator outside the browser and pastes the signature
 * back.
 */
import * as React from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  useCeremony,
  type CeremonyAuthenticatorType,
  type CeremonyClaimCertBeginResponse,
  type CeremonyClaimCertCompleteResponse,
} from "@/hooks/use-ceremony";

/** The authenticator types an officer can claim with. */
export const CEREMONY_AUTHENTICATOR_TYPES = [
  "CEREMONY_AUTHENTICATOR_TYPE_PIV",
  "CEREMONY_AUTHENTICATOR_TYPE_FIDO2",
  "CEREMONY_AUTHENTICATOR_TYPE_SOFTWARE",
] as const;

/** authenticatorTypeLabel names a CeremonyAuthenticatorType for the operator. */
export function authenticatorTypeLabel(t: string): string {
  switch (t) {
    case "CEREMONY_AUTHENTICATOR_TYPE_PIV":
      return "PIV";
    case "CEREMONY_AUTHENTICATOR_TYPE_FIDO2":
      return "FIDO2";
    case "CEREMONY_AUTHENTICATOR_TYPE_SOFTWARE":
      return "Software";
    default:
      return "Unspecified";
  }
}

export function CeremonyClaimCertCard() {
  const ceremony = useCeremony();
  const [username, setUsername] = React.useState("");
  const [authenticatorType, setAuthenticatorType] =
    React.useState<CeremonyAuthenticatorType>("CEREMONY_AUTHENTICATOR_TYPE_PIV");
  const [slot, setSlot] = React.useState("");
  const [credentialId, setCredentialId] = React.useState("");
  const [challenge, setChallenge] = React.useState<CeremonyClaimCertBeginResponse>();
  const [signature, setSignature] = React.useState("");
  const [claimed, setClaimed] = React.useState<CeremonyClaimCertCompleteResponse>();
  const [error, setError] = React.useState<string>();
  const [busy, setBusy] = React.useState(false);

  const begin = async () => {
    setBusy(true);
    setError(undefined);
    const res = await ceremony.claimCertBegin({
      username: username.trim(),
      authenticatorType,
      slot: slot || undefined,
      credentialId: credentialId || undefined,
    });
    setBusy(false);
    if (res.error || !res.data) {
      setError(res.error?.message ?? "");
      return;
    }
    setChallenge(res.data);
  };

  const complete = async () => {
    if (!challenge) return;
    setBusy(true);
    setError(undefined);
    const res = await ceremony.claimCertComplete({
      username: username.trim(),
      nonce: challenge.nonce,
      signature: signature.trim(),
    });
    setBusy(false);
    if (res.error || !res.data) {
      setError(res.error?.message ?? "");
      return;
    }
    setClaimed(res.data);
  };

  const startOver = () => {
    setUsername("");
    setAuthenticatorType("CEREMONY_AUTHENTICATOR_TYPE_PIV");
    setSlot("");
    setCredentialId("");
    setChallenge(undefined);
    setSignature("");
    setClaimed(undefined);
    setError(undefined);
    setBusy(false);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Claim officer certificate</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-2">
          <Label htmlFor="claim-cert-username">Username</Label>
          <Input
            id="claim-cert-username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="claim-cert-authenticator">Authenticator</Label>
          <select
            id="claim-cert-authenticator"
            className="h-9 rounded-md border bg-transparent px-3 text-sm"
            value={authenticatorType}
            onChange={(e) => setAuthenticatorType(e.target.value as CeremonyAuthenticatorType)}
          >
            {CEREMONY_AUTHENTICATOR_TYPES.map((t) => (
              <option key={t} value={t}>
                {authenticatorTypeLabel(t)}
              </option>
            ))}
          </select>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="claim-cert-slot">Slot</Label>
          <Input id="claim-cert-slot" value={slot} onChange={(e) => setSlot(e.target.value)} />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="claim-cert-credential-id">Credential ID</Label>
          <Input
            id="claim-cert-credential-id"
            value={credentialId}
            onChange={(e) => setCredentialId(e.target.value)}
          />
        </div>
        <Button onClick={begin} disabled={busy || username.trim() === ""}>
          Request challenge
        </Button>

        {challenge && !claimed && (
          <div className="space-y-4">
            <div className="grid gap-2">
              <Label htmlFor="claim-cert-nonce">Nonce</Label>
              <Input id="claim-cert-nonce" value={challenge.nonce} readOnly />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="claim-cert-challenge-id">Challenge ID</Label>
              <Input id="claim-cert-challenge-id" value={challenge.challengeId} readOnly />
            </div>
            {challenge.expiresAt && (
              <div className="grid gap-2">
                <Label htmlFor="claim-cert-expires-at">Expires at</Label>
                <Input id="claim-cert-expires-at" value={challenge.expiresAt} readOnly />
              </div>
            )}
            <div className="grid gap-2">
              <Label htmlFor="claim-cert-signature">Signature</Label>
              <Textarea
                id="claim-cert-signature"
                value={signature}
                onChange={(e) => setSignature(e.target.value)}
              />
            </div>
            <Button onClick={complete} disabled={busy || signature.trim() === ""}>
              Complete claim
            </Button>
          </div>
        )}

        {claimed && (
          <div className="space-y-4">
            <div className="grid gap-2">
              <Label htmlFor="claim-cert-certificate">Certificate</Label>
              <Textarea id="claim-cert-certificate" value={claimed.certificatePem} readOnly />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="claim-cert-chain">Chain</Label>
              <Textarea id="claim-cert-chain" value={claimed.chainPem} readOnly />
            </div>
          </div>
        )}

        {error !== undefined && <p role="alert">Claim refused: {error}</p>}

        <Button variant="outline" onClick={startOver}>
          Start over
        </Button>
      </CardContent>
    </Card>
  );
}
