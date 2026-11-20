"use client";

import * as React from "react";
import { Loader2, ShieldCheck } from "lucide-react";
import type { HostManifest } from "trusted-platform-sdk";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAttestationVerify } from "@/hooks/use-attestation-verify";

/** Parse the pasted manifest; returns the reason when it is not a manifest. */
export function parseManifest(text: string): { manifest?: HostManifest; error?: string } {
  if (!text.trim()) return { error: "Paste a manifest first." };
  try {
    const value = JSON.parse(text) as HostManifest;
    if (!value || typeof value !== "object" || typeof value.id !== "string") {
      return { error: "Not a manifest: the JSON has no id." };
    }
    return { manifest: value };
  } catch (err) {
    return { error: `Not valid JSON: ${err instanceof Error ? err.message : String(err)}` };
  }
}

const checks: Array<[string, string]> = [
  ["signatureValid", "Signature"],
  ["merkleRootValid", "Merkle root"],
  ["nonceValid", "Nonce"],
  ["timestampValid", "Timestamp"],
  ["hostAttestationValid", "Host attestation"],
];

/** VerifyManifest (#2038): paste a manifest, the server verifies it. */
export function VerifyManifestCard() {
  const ops = useAttestationVerify();
  const [text, setText] = React.useState("");
  const [parseError, setParseError] = React.useState<string>();

  const submit = async () => {
    const parsed = parseManifest(text);
    setParseError(parsed.error);
    if (parsed.manifest) await ops.verifyManifest(parsed.manifest);
  };

  const { pending, result, error, unavailable } = ops.manifest;
  const verdict = result?.result as unknown as Record<string, unknown> | undefined;
  const shown = parseError ?? error;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Verify a manifest</CardTitle>
        <CardDescription>
          Paste a host manifest as JSON; the server checks its signature, Merkle root, nonce and
          attestations.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <Label htmlFor="manifest-json">Manifest JSON</Label>
        <Textarea
          id="manifest-json"
          rows={6}
          value={text}
          onChange={(e) => setText(e.target.value)}
          className="font-mono text-xs"
        />
        <div>
          <Button onClick={submit} disabled={pending || unavailable || !text.trim()}>
            {pending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
            Verify manifest
          </Button>
        </div>
        {(shown || verdict) && (
          <div data-testid="verify-manifest-result">
            {shown ? (
              <Alert variant="destructive">
                <AlertTitle>{unavailable ? "Manifest verification unavailable" : "Verification failed"}</AlertTitle>
                <AlertDescription>{shown}</AlertDescription>
              </Alert>
            ) : (
              <div className="flex flex-col gap-1 text-sm">
                <p className="font-medium">Status: {String(verdict?.status ?? "unknown")}</p>
                {checks.map(([key, label]) => (
                  <p key={key}>
                    {label}: {verdict?.[key] ? "valid" : "not valid"}
                  </p>
                ))}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
