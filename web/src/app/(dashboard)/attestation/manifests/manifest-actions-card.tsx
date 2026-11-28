"use client";

/**
 * ManifestActionsCard verifies a host manifest (VerifyManifest) through
 * useAttestationVerify and deletes one (DeleteManifest) after a confirm,
 * both through the SDK client (#2038).
 */

import * as React from "react";
import type { HostManifest, ManifestVerificationResult } from "trusted-platform-sdk";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Gated } from "@/components/features/capabilities/gated";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useAttestation, useToast } from "@/hooks";
import { useAttestationVerify } from "@/hooks/use-attestation-verify";

function yesNo(v: boolean | undefined): string {
  return v ? "Yes" : "No";
}

export function ManifestActionsCard({
  manifests,
  onDeleted,
}: {
  manifests: HostManifest[];
  onDeleted: () => void;
}): React.JSX.Element {
  const { toast } = useToast();
  const attestation = useAttestation();
  const verify = useAttestationVerify();

  const [selectedId, setSelectedId] = React.useState("");
  const [nonce, setNonce] = React.useState("");
  const [verdict, setVerdict] = React.useState<ManifestVerificationResult | undefined>();
  const [confirmOpen, setConfirmOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  const selected = manifests.find((m) => m.id === selectedId) ?? manifests[0];
  const empty = manifests.length === 0;

  const onVerify = async () => {
    if (!selected) return;
    const n = nonce.trim();
    setBusy(true);
    try {
      const res = await verify.verifyManifest({
        manifest: selected,
        ...(n ? { expectedNonce: n } : {}),
        // No public key: the control plane checks no manifest signature and
        // refuses one (ErrAttestationManifestSignatureUnchecked).
      });
      if (!res.success || !res.data?.result) {
        toast({
          title: "Manifest verification failed",
          description: res.error?.message,
          variant: "destructive",
        });
        return;
      }
      setVerdict(res.data.result);
    } finally {
      setBusy(false);
    }
  };

  const onDelete = async () => {
    if (!selected) return;
    const id = selected.id;
    setBusy(true);
    try {
      const res = await attestation.deleteManifest(id);
      if (!res.success) {
        toast({
          title: "Manifest delete failed",
          description: res.error?.message,
          variant: "destructive",
        });
        return;
      }
      toast({ title: "Manifest deleted", description: id });
      setConfirmOpen(false);
      setVerdict(undefined);
      onDeleted();
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="manifest-actions">
      <CardHeader>
        <CardTitle>Verify or delete a manifest</CardTitle>
        <CardDescription>
          Verify a host manifest against an expected nonce, or delete it.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid gap-4 md:grid-cols-2">
          <select
            aria-label="Manifest"
            className="h-9 rounded-md border border-input bg-transparent px-3 text-sm"
            value={selected?.id ?? ""}
            onChange={(e) => {
              setSelectedId(e.target.value);
              setVerdict(undefined);
            }}
            disabled={empty}
          >
            {empty ? (
              <option value="">No manifests</option>
            ) : (
              manifests.map((m) => (
                <option key={m.id} value={m.id}>
                  {`${m.id} (${m.hostId})`}
                </option>
              ))
            )}
          </select>
          <Input
            aria-label="Expected nonce"
            placeholder="base64 nonce"
            value={nonce}
            onChange={(e) => setNonce(e.target.value)}
            disabled={empty}
          />
        </div>
        <div className="flex gap-2">
          <Gated op="POST /api/v1/attestation/manifests/verify">
            <Button onClick={onVerify} disabled={empty || busy}>
              Verify manifest
            </Button>
          </Gated>
          <Gated op="DELETE /api/v1/attestation/manifests/{id}">
            <Button variant="destructive" onClick={() => setConfirmOpen(true)} disabled={empty || busy}>
              Delete manifest
            </Button>
          </Gated>
        </div>
        {verdict && (
          <div data-testid="manifest-verdict" className="flex flex-col gap-1 text-sm">
            <p className="font-medium">Status: {verdict.status}</p>
            {/* The control plane sets signatureValid without verifying a
                signature and accepts the host with no expected PCRs: both are
                placeholders, so neither is shown as a pass. */}
            <p title="The control plane does not verify manifest signatures yet">Signature valid: not checked</p>
            <p>Merkle root valid: {yesNo(verdict.merkleRootValid)}</p>
            <p>Nonce valid: {yesNo(verdict.nonceValid)}</p>
            <p>Timestamp valid: {yesNo(verdict.timestampValid)}</p>
            <p title="The control plane accepts the host with no expected PCRs">Host attestation valid: not checked</p>
            {verdict.errors && verdict.errors.length > 0 ? (
              <ul className="list-disc pl-5">
                {verdict.errors.map((e, i) => (
                  <li key={i}>{e}</li>
                ))}
              </ul>
            ) : (
              <p className="text-muted-foreground">No errors</p>
            )}
          </div>
        )}
      </CardContent>
      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete manifest</DialogTitle>
            <DialogDescription>
              {`Delete manifest ${selected?.id ?? ""}? Verifiers that use it will stop matching this host.`}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={onDelete} disabled={busy}>
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
