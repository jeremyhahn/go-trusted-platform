"use client";

/**
 * CeremonyClaimShareCard lets an officer claim their Shamir key share through
 * CeremonyService.ClaimShareBegin and ClaimShareComplete on `useCeremony()`
 * (`POST /api/v1/ceremony/claim-share/begin` and
 * `POST /api/v1/ceremony/claim-share/complete`). The officer signs the nonce
 * outside the browser and pastes the base64 signature back. The share is
 * shown once, read-only, and kept only in component state: it is never
 * stored, logged or put in a toast.
 */
import * as React from "react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Gated } from "@/components/features/capabilities/gated";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  useCeremony,
  type CeremonyClaimShareBeginResponse,
  type CeremonyClaimShareCompleteResponse,
} from "@/hooks/use-ceremony";

export function CeremonyClaimShareCard() {
  const ceremony = useCeremony();
  const [username, setUsername] = React.useState("");
  const [challenge, setChallenge] = React.useState<CeremonyClaimShareBeginResponse>();
  const [signature, setSignature] = React.useState("");
  const [claimed, setClaimed] = React.useState<CeremonyClaimShareCompleteResponse>();
  const [error, setError] = React.useState<string>();
  const [busy, setBusy] = React.useState(false);

  const begin = async () => {
    setBusy(true);
    setError(undefined);
    const res = await ceremony.claimShareBegin({ username: username.trim() });
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
    const res = await ceremony.claimShareComplete({
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
    setSignature("");
  };

  const startOver = () => {
    setUsername("");
    setChallenge(undefined);
    setSignature("");
    setClaimed(undefined);
    setError(undefined);
    setBusy(false);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Claim key share</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-2">
          <Label htmlFor="claim-share-username">Username</Label>
          <Input
            id="claim-share-username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <Gated op="POST /api/v1/ceremony/claim-share/begin">
          <Button onClick={begin} disabled={busy || username.trim() === ""}>
            Request challenge
          </Button>
        </Gated>

        {challenge && !claimed && (
          <div className="space-y-4">
            <div className="grid gap-2">
              <Label htmlFor="claim-share-nonce">Nonce</Label>
              <Input id="claim-share-nonce" value={challenge.nonce} readOnly />
            </div>
            {challenge.expiresAt && (
              <div className="grid gap-2">
                <Label htmlFor="claim-share-expires-at">Expires at</Label>
                <Input id="claim-share-expires-at" value={challenge.expiresAt} readOnly />
              </div>
            )}
            <div className="grid gap-2">
              <Label htmlFor="claim-share-signature">Signature (base64)</Label>
              <Textarea
                id="claim-share-signature"
                value={signature}
                onChange={(e) => setSignature(e.target.value)}
              />
            </div>
            <Gated op="POST /api/v1/ceremony/claim-share/complete">
              <Button onClick={complete} disabled={busy || signature.trim() === ""}>
                Complete claim
              </Button>
            </Gated>
          </div>
        )}

        {claimed && (
          <div className="space-y-4">
            <Alert>
              <AlertDescription>
                Store this share offline now: the platform keeps no copy.
              </AlertDescription>
            </Alert>
            <div className="grid gap-2">
              <Label htmlFor="claim-share-share">Share</Label>
              <Textarea id="claim-share-share" value={claimed.share} readOnly />
            </div>
            <p>Share index {claimed.index}</p>
          </div>
        )}

        {error !== undefined && <p role="alert">Claim share refused: {error}</p>}

        <Button variant="outline" onClick={startOver}>
          Start over
        </Button>
      </CardContent>
    </Card>
  );
}
