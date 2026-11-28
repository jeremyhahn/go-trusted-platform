"use client";

/**
 * ManifestDeleteButton sends DeleteManifest
 * (DELETE /api/v1/attestation/manifests/{id}) through the SDK
 * AttestationService after a confirm, and only when the server offers the
 * route (#2038).
 */

import * as React from "react";
import { Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Gated } from "@/components/features/capabilities/gated";
import { useAttestation, useToast } from "@/hooks";

export const DELETE_MANIFEST_OP = "DELETE /api/v1/attestation/manifests/{id}";

export interface ManifestDeleteButtonProps {
  id: string;
  label?: string;
  onDeleted: () => void;
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  if (err && typeof err === "object" && "message" in err) {
    return String((err as { message: unknown }).message);
  }
  if (err === undefined || err === null || err === "") {
    return "the server refused the delete";
  }
  return String(err);
}

export function ManifestDeleteButton({ id, label, onDeleted }: ManifestDeleteButtonProps) {
  const attestation = useAttestation();
  const { toast } = useToast();
  const [open, setOpen] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  const fail = (message: string) =>
    toast({ title: "Delete failed", description: message, variant: "destructive" });

  const confirm = async () => {
    setBusy(true);
    try {
      const res = await attestation.deleteManifest(id);
      if (res.success === false) {
        fail(errorMessage(res.error));
        return;
      }
      toast({ title: "Manifest deleted", description: label ?? id, variant: "success" });
      setOpen(false);
      onDeleted();
    } catch (err) {
      fail(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Gated op={DELETE_MANIFEST_OP}>
        <Button
          variant="outline"
          size="sm"
          aria-label="Delete manifest"
          data-testid="manifest-delete"
          onClick={() => setOpen(true)}
        >
          <Trash2 className="h-4 w-4 mr-1" />
          Delete manifest
        </Button>
      </Gated>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete manifest?</DialogTitle>
            <DialogDescription>
              The manifest for {label ?? id} is removed from the control plane. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={() => void confirm()} disabled={busy}>
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
