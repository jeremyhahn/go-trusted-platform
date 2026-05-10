"use client";

/**
 * FactorList — renders the registered auth factors for a user, grouped by type.
 * Each factor row shows label, type icon, last used, registered at, vendor badge,
 * Rotate, and Remove actions.
 */

import React, { useState } from "react";
import {
  Key,
  Fingerprint,
  CreditCard,
  Pencil,
  RotateCcw,
  Trash2,
  Check,
  X,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { VendorBadge } from "./vendor-badge";
import type { AuthFactor, AuthFactorType } from "@/types/auth-factors";

const TYPE_LABELS: Record<AuthFactorType, string> = {
  mtls: "mTLS Certificate",
  fido2: "FIDO2 / Passkey",
  piv: "PIV Smartcard",
};

function TypeIcon({ type }: { type: AuthFactorType }) {
  switch (type) {
    case "mtls":
      return <Key className="h-4 w-4 text-blue-500" aria-label="mTLS cert" />;
    case "fido2":
      return (
        <Fingerprint
          className="h-4 w-4 text-purple-500"
          aria-label="FIDO2 key"
        />
      );
    case "piv":
      return (
        <CreditCard
          className="h-4 w-4 text-green-500"
          aria-label="PIV smartcard"
        />
      );
  }
}

function relativeTime(ts: string | null | undefined): string {
  if (!ts) return "Never";
  try {
    return formatDistanceToNow(new Date(ts), { addSuffix: true });
  } catch {
    return ts;
  }
}

interface FactorRowProps {
  factor: AuthFactor;
  onRotate: (factor: AuthFactor) => void;
  onRemove: (factor: AuthFactor) => void;
  onRelabel: (factor: AuthFactor, label: string) => void;
  isLastFactor: boolean;
}

function FactorRow({
  factor,
  onRotate,
  onRemove,
  onRelabel,
  isLastFactor,
}: FactorRowProps) {
  const [editing, setEditing] = useState(false);
  const [labelDraft, setLabelDraft] = useState(factor.label);

  function commitLabel() {
    if (labelDraft.trim() && labelDraft !== factor.label) {
      onRelabel(factor, labelDraft.trim());
    }
    setEditing(false);
  }

  function cancelLabel() {
    setLabelDraft(factor.label);
    setEditing(false);
  }

  return (
    <div className="flex items-center gap-3 py-3">
      <TypeIcon type={factor.type} />

      {/* Label — inline edit */}
      <div className="flex-1 min-w-0">
        {editing ? (
          <div className="flex items-center gap-1">
            <Input
              value={labelDraft}
              onChange={(e) => setLabelDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") commitLabel();
                if (e.key === "Escape") cancelLabel();
              }}
              className="h-7 text-sm"
              autoFocus
              aria-label="Factor label"
            />
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={commitLabel}
              aria-label="Save label"
            >
              <Check className="h-3 w-3" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={cancelLabel}
              aria-label="Cancel"
            >
              <X className="h-3 w-3" />
            </Button>
          </div>
        ) : (
          <div className="flex items-center gap-1">
            <span className="text-sm font-medium truncate">{factor.label}</span>
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6 opacity-50 hover:opacity-100"
              onClick={() => setEditing(true)}
              aria-label="Edit label"
            >
              <Pencil className="h-3 w-3" />
            </Button>
          </div>
        )}
        <div className="flex items-center gap-2 mt-0.5 text-xs text-muted-foreground">
          <span>Registered {relativeTime(factor.registered_at)}</span>
          <span>·</span>
          <span>Last used {relativeTime(factor.last_used_at)}</span>
        </div>
      </div>

      <VendorBadge factor={factor} className="hidden sm:inline-flex" />

      <div className="flex items-center gap-1 shrink-0">
        <Button
          variant="outline"
          size="sm"
          onClick={() => onRotate(factor)}
          aria-label={`Rotate ${factor.label}`}
        >
          <RotateCcw className="h-3 w-3 mr-1" />
          Rotate
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => onRemove(factor)}
          disabled={isLastFactor}
          title={isLastFactor ? "Cannot remove the last factor" : undefined}
          aria-label={`Remove ${factor.label}`}
          className="text-destructive hover:text-destructive"
        >
          <Trash2 className="h-3 w-3 mr-1" />
          Remove
        </Button>
      </div>
    </div>
  );
}

interface FactorGroupProps {
  type: AuthFactorType;
  factors: AuthFactor[];
  onRotate: (factor: AuthFactor) => void;
  onRemove: (factor: AuthFactor) => void;
  onRelabel: (factor: AuthFactor, label: string) => void;
  totalFactors: number;
}

function FactorGroup({
  type,
  factors,
  onRotate,
  onRemove,
  onRelabel,
  totalFactors,
}: FactorGroupProps) {
  if (factors.length === 0) return null;

  return (
    <div className="mb-6">
      <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-2">
        <TypeIcon type={type} />
        {TYPE_LABELS[type]}
        <Badge variant="secondary" className="ml-1">
          {factors.length}
        </Badge>
      </h4>
      <div className="rounded-md border divide-y">
        {factors.map((f) => (
          <FactorRow
            key={f.id}
            factor={f}
            onRotate={onRotate}
            onRemove={onRemove}
            onRelabel={onRelabel}
            isLastFactor={totalFactors === 1}
          />
        ))}
      </div>
    </div>
  );
}

export interface FactorListProps {
  factors: AuthFactor[];
  loading?: boolean;
  onRotate: (factor: AuthFactor) => void;
  onRemove: (factor: AuthFactor) => void;
  onRelabel: (factor: AuthFactor, label: string) => void;
}

export function FactorList({
  factors,
  loading,
  onRotate,
  onRemove,
  onRelabel,
}: FactorListProps) {
  const [removeTarget, setRemoveTarget] = useState<AuthFactor | null>(null);

  const activeFactors = (factors || []).filter((f) => !f.revoked_at);
  const grouped: Record<AuthFactorType, AuthFactor[]> = {
    mtls: activeFactors.filter((f) => f.type === "mtls"),
    fido2: activeFactors.filter((f) => f.type === "fido2"),
    piv: activeFactors.filter((f) => f.type === "piv"),
  };

  if (loading) {
    return (
      <div className="space-y-3" aria-busy="true" aria-label="Loading factors">
        {[1, 2, 3].map((i) => (
          <div key={i} className="h-16 rounded-md bg-muted animate-pulse" />
        ))}
      </div>
    );
  }

  if (activeFactors.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground text-sm">
        No authentication factors registered. Add one to secure your account.
      </div>
    );
  }

  function handleRemoveConfirm() {
    if (removeTarget) {
      onRemove(removeTarget);
      setRemoveTarget(null);
    }
  }

  return (
    <>
      <FactorGroup
        type="mtls"
        factors={grouped.mtls}
        onRotate={onRotate}
        onRemove={(f) => setRemoveTarget(f)}
        onRelabel={onRelabel}
        totalFactors={activeFactors.length}
      />
      <FactorGroup
        type="fido2"
        factors={grouped.fido2}
        onRotate={onRotate}
        onRemove={(f) => setRemoveTarget(f)}
        onRelabel={onRelabel}
        totalFactors={activeFactors.length}
      />
      <FactorGroup
        type="piv"
        factors={grouped.piv}
        onRotate={onRotate}
        onRemove={(f) => setRemoveTarget(f)}
        onRelabel={onRelabel}
        totalFactors={activeFactors.length}
      />

      {/* Remove confirmation dialog */}
      <Dialog
        open={removeTarget !== null}
        onOpenChange={(open) => {
          if (!open) setRemoveTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remove authentication factor</DialogTitle>
            <DialogDescription>
              Are you sure you want to remove{" "}
              <strong>{removeTarget?.label}</strong>? You will no longer be able
              to sign in with this factor. This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRemoveTarget(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleRemoveConfirm}>
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
