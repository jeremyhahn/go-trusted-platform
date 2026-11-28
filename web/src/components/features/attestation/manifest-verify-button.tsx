"use client";

/**
 * ManifestVerifyButton sends VerifyManifest
 * (POST /api/v1/attestation/manifests/verify) through the SDK
 * AttestationService with the manifest it was given, or the one it fetches
 * by id, and shows the verifier's checks and errors. It is offered only when
 * the server offers the route (#2038). The signature is shown as not checked
 * and no public key is offered, because the production VerifyManifest checks
 * no signature and refuses a public key with
 * ErrAttestationManifestSignatureUnchecked
 * (pkg/attestation/service/service.go:103-105, 143-148). The Merkle root and
 * the host, VM and container attestations are shown as not checked too: the
 * server answers them with placeholders (a nonempty root, a host valid without
 * expected PCRs, VM and container always valid; service.go:122-151). Only the
 * nonce and timestamp are real checks. The status badge reads the protojson
 * wire value MANIFEST_VERIFICATION_STATUS_VERIFIED as success. A verify here
 * is an inspection, not a verdict: service.go's VerifyManifest reaches no
 * attestation observer, so neither a pass nor a failure quarantines or
 * restores a device (#2038). The nonce row reads not checked when no
 * expected nonce was sent, and an answer for an older input is dropped.
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
import { Gated } from "@/components/features/capabilities/gated";
import { useAttestation, useToast } from "@/hooks";

export const VERIFY_MANIFEST_OP = "POST /api/v1/attestation/manifests/verify";

export interface ManifestVerifyButtonProps {
  manifestId: string;
  manifest?: HostManifest;
}

type CheckName = "nonceValid" | "timestampValid";

// The checks VerifyManifest really makes.
const CHECKS: { name: CheckName; label: string }[] = [
  { name: "nonceValid", label: "Nonce" },
  { name: "timestampValid", label: "Timestamp" },
];

// Properties VerifyManifest answers with a placeholder, not a check: the host
// is valid when no expected PCRs are given (this dialog gives none), the
// Merkle root is valid when it is not empty, and VM and container attestations
// are always valid (pkg/attestation/service/service.go:122-151).
const UNCHECKED: { name: string; label: string; why: string }[] = [
  { name: "merkleRootValid", label: "Merkle root", why: "The control plane only checks that the Merkle root is not empty" },
  {
    name: "hostAttestationValid",
    label: "Host attestation",
    why: "The control plane checks host PCRs only against expected PCRs, and this dialog sends none",
  },
  { name: "vmAttestationsValid", label: "VM attestations", why: "The control plane does not verify VM attestations yet" },
  {
    name: "containerAttestationsValid",
    label: "Container attestations",
    why: "The control plane does not verify container attestations yet",
  },
];

/** isVerified reads the status as the SDK type names it or as protojson sends it. */
function isVerified(status: string | undefined): boolean {
  return status === "VERIFIED" || status === "MANIFEST_VERIFICATION_STATUS_VERIFIED";
}

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

function VerifyResult({ result, nonceSent }: { result: ManifestVerificationResult; nonceSent: boolean }) {
  const errors = result.errors ?? [];
  return (
    <div data-testid="manifest-verify-result" className="space-y-3 text-sm">
      <div className="flex items-center gap-2">
        <span className="font-medium">Status</span>
        <Badge
          data-testid="manifest-verify-status"
          data-verified={isVerified(result.status) ? "true" : "false"}
          variant={isVerified(result.status) ? "default" : "destructive"}
        >
          {result.status}
        </Badge>
        {result.verifiedAt && <span className="text-muted-foreground">{result.verifiedAt}</span>}
      </div>
      <ul className="space-y-1">
        <li data-testid="manifest-verify-check-signatureValid" className="flex justify-between">
          <span>Signature</span>
          <span className="text-muted-foreground" title="The control plane does not verify manifest signatures yet">
            not checked
          </span>
        </li>
        {CHECKS.map((check) => (
          <li
            key={check.name}
            data-testid={`manifest-verify-check-${check.name}`}
            className="flex justify-between"
          >
            <span>{check.label}</span>
            {check.name === "nonceValid" && !nonceSent ? (
              <span
                className="text-muted-foreground"
                title="No expected nonce was sent, so the control plane compared none"
              >
                not checked
              </span>
            ) : (
              <span className={result[check.name] ? "text-green-600" : "text-destructive"}>
                {result[check.name] ? "valid" : "invalid"}
              </span>
            )}
          </li>
        ))}
        {UNCHECKED.map((check) => (
          <li
            key={check.name}
            data-testid={`manifest-verify-check-${check.name}`}
            className="flex justify-between"
          >
            <span>{check.label}</span>
            <span className="text-muted-foreground" title={check.why}>
              not checked
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
  const [result, setResult] = React.useState<{ result: ManifestVerificationResult; nonceSent: boolean } | null>(
    null,
  );
  // verifySeq numbers each input revision: an answer for an older one is
  // dropped, as AttestationQuoteCard does.
  const verifySeq = React.useRef(0);

  const fail = (message: string) =>
    toast({ title: "Verification failed", description: message, variant: "destructive" });

  const openDialog = () => {
    verifySeq.current += 1;
    setBusy(false);
    setResult(null);
    setOpen(true);
  };

  const changeNonce = (value: string) => {
    verifySeq.current += 1;
    setBusy(false);
    setResult(null);
    setExpectedNonce(value);
  };

  const verify = async () => {
    const seq = ++verifySeq.current;
    setBusy(true);
    setResult(null);
    try {
      let target = manifest;
      if (!target) {
        const got = await attestation.getManifest(manifestId);
        if (seq !== verifySeq.current) {
          return;
        }
        if (got.success === false || !got.data?.manifest) {
          fail(errorMessage(got.error ?? "the manifest could not be read"));
          return;
        }
        target = got.data.manifest;
      }
      const nonce = expectedNonce.trim();
      const res = await attestation.verifyManifest({
        manifest: target,
        ...(nonce !== "" && { expectedNonce: nonce }),
      });
      if (seq !== verifySeq.current) {
        return;
      }
      if (res.success === false) {
        fail(errorMessage(res.error));
        return;
      }
      if (!res.data?.result) {
        fail(res.data?.status?.message || "the server sent no verification result");
        return;
      }
      setResult({ result: res.data.result, nonceSent: nonce !== "" });
    } catch (err) {
      if (seq === verifySeq.current) {
        fail(errorMessage(err));
      }
    } finally {
      if (seq === verifySeq.current) {
        setBusy(false);
      }
    }
  };

  const nonceId = `manifest-verify-nonce-${manifestId}`;

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
              The control plane checks the nonce and timestamp of manifest {manifestId} only. It does not check the
              manifest signature, the Merkle root or the host, VM and container attestations. Verifying here is an
              inspection: it does not restore a quarantined device or change its network placement; only a verified
              quote does.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor={nonceId}>Expected nonce</Label>
              <Input
                id={nonceId}
                value={expectedNonce}
                placeholder="base64, optional"
                onChange={(e) => changeNonce(e.target.value)}
              />
            </div>
          </div>
          {result && <VerifyResult result={result.result} nonceSent={result.nonceSent} />}
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
