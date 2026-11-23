"use client";

/**
 * ManifestVerifyButton sends VerifyManifest
 * (POST /api/v1/attestation/manifests/verify) through the SDK
 * AttestationService with the manifest it was given, or the one it fetches
 * by id, and shows the verifier's checks and errors. It is offered only when
 * the server offers the route (#2038).
 */

import * as React from "react";
import { ShieldCheck } from "lucide-react";
import type { HostManifest, ManifestVerificationResult } from "trusted-platform-sdk";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Gated } from "@/components/features/capabilities/gated";
import { pemToBase64 } from "@/components/features/attestation/attestation-quote-card";
import { useAttestation, useToast } from "@/hooks";

export const VERIFY_MANIFEST_OP = "POST /api/v1/attestation/manifests/verify";

export interface ManifestVerifyButtonProps {
  manifestId: string;
  manifest?: HostManifest;
}

type CheckName =
  | "signatureValid"
  | "merkleRootValid"
  | "nonceValid"
  | "timestampValid"
  | "hostAttestationValid"
  | "vmAttestationsValid"
  | "containerAttestationsValid";

const CHECKS: { name: CheckName; label: string }[] = [
  { name: "signatureValid", label: "Signature" },
  { name: "merkleRootValid", label: "Merkle root" },
  { name: "nonceValid", label: "Nonce" },
  { name: "timestampValid", label: "Timestamp" },
  { name: "hostAttestationValid", label: "Host attestation" },
  { name: "vmAttestationsValid", label: "VM attestations" },
  { name: "containerAttestationsValid", label: "Container attestations" },
];

function errorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  if (err && typeof err === "object" && "message" in err) {
    return String((err as { message: unknown }).message);
  }
  if (err === undefined || err === null || err === "") {
    return "the server refused the verification";
  }
  return String(err);
}

function NamedErrors({ title, errors, testId }: { title: string; errors?: Record<string, string>; testId: string }) {
  const entries = Object.entries(errors ?? {});
  if (entries.length === 0) {
    return null;
  }
  return (
    <div data-testid={testId}>
      <p className="font-medium">{title}</p>
      <ul className="list-disc pl-5">
        {entries.map(([name, message]) => (
          <li key={name}>
            {name}: {message}
          </li>
        ))}
      </ul>
    </div>
  );
}

function VerifyResult({ result }: { result: ManifestVerificationResult }) {
  const errors = result.errors ?? [];
  return (
    <div data-testid="manifest-verify-result" className="space-y-3 text-sm">
      <div className="flex items-center gap-2">
        <span className="font-medium">Status</span>
        <Badge variant={result.status === "VERIFIED" ? "default" : "destructive"}>{result.status}</Badge>
        {result.verifiedAt && <span className="text-muted-foreground">{result.verifiedAt}</span>}
      </div>
      <ul className="space-y-1">
        {CHECKS.map((check) => (
          <li
            key={check.name}
            data-testid={`manifest-verify-check-${check.name}`}
            className="flex justify-between"
          >
            <span>{check.label}</span>
            <span className={result[check.name] ? "text-green-600" : "text-destructive"}>
              {result[check.name] ? "valid" : "invalid"}
            </span>
          </li>
        ))}
      </ul>
      {errors.length > 0 && (
        <div data-testid="manifest-verify-errors">
          <p className="font-medium">Errors</p>
          <ul className="list-disc pl-5">
            {errors.map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        </div>
      )}
      <NamedErrors title="VM errors" errors={result.vmErrors} testId="manifest-verify-vm-errors" />
      <NamedErrors title="Container errors" errors={result.containerErrors} testId="manifest-verify-container-errors" />
    </div>
  );
}

export function ManifestVerifyButton({ manifestId, manifest }: ManifestVerifyButtonProps) {
  const attestation = useAttestation();
  const { toast } = useToast();
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [expectedNonce, setExpectedNonce] = React.useState("");
  const [publicKeyPem, setPublicKeyPem] = React.useState("");
  const [result, setResult] = React.useState<ManifestVerificationResult | null>(null);

  const fail = (message: string) =>
    toast({ title: "Verification failed", description: message, variant: "destructive" });

  const openDialog = () => {
    setResult(null);
    setOpen(true);
  };

  const verify = async () => {
    setBusy(true);
    setResult(null);
    try {
      let target = manifest;
      if (!target) {
        const got = await attestation.getManifest(manifestId);
        if (got.success === false || !got.data?.manifest) {
          fail(errorMessage(got.error ?? "the manifest could not be read"));
          return;
        }
        target = got.data.manifest;
      }
      const nonce = expectedNonce.trim();
      const pem = publicKeyPem.trim();
      const res = await attestation.verifyManifest({
        manifest: target,
        ...(nonce !== "" && { expectedNonce: nonce }),
        ...(pem !== "" && { publicKeyPem: pemToBase64(pem) }),
      });
      if (res.success === false) {
        fail(errorMessage(res.error));
        return;
      }
      if (!res.data?.result) {
        fail(res.data?.status?.message || "the server sent no verification result");
        return;
      }
      setResult(res.data.result);
    } catch (err) {
      fail(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const nonceId = `manifest-verify-nonce-${manifestId}`;
  const pemId = `manifest-verify-pem-${manifestId}`;

  return (
    <>
      <Gated op={VERIFY_MANIFEST_OP}>
        <Button
          variant="outline"
          size="sm"
          aria-label="Verify manifest"
          data-testid="manifest-verify"
          onClick={openDialog}
        >
          <ShieldCheck className="h-4 w-4 mr-1" />
          Verify manifest
        </Button>
      </Gated>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Verify manifest</DialogTitle>
            <DialogDescription>
              The control plane checks the signature, Merkle root, nonce, timestamp and attestations of manifest{" "}
              {manifestId}.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor={nonceId}>Expected nonce</Label>
              <Input
                id={nonceId}
                value={expectedNonce}
                placeholder="base64, optional"
                onChange={(e) => setExpectedNonce(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor={pemId}>Public key (PEM)</Label>
              <Textarea
                id={pemId}
                value={publicKeyPem}
                placeholder="optional"
                rows={3}
                onChange={(e) => setPublicKeyPem(e.target.value)}
              />
            </div>
          </div>
          {result && <VerifyResult result={result} />}
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
              Close
            </Button>
            <Button onClick={() => void verify()} disabled={busy}>
              Verify
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
