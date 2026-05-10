"use client";

/**
 * VendorBadge — displays the inferred vendor name for an auth factor.
 * Resolves FIDO2 AAGUID → vendor name, PIV cert subject → card vendor,
 * or "Self-issued (mTLS)" for mTLS factors.
 */

import React from "react";
import { Badge } from "@/components/ui/badge";
import { resolveVendorBadge } from "@/types/auth-factors";
import type { AuthFactor } from "@/types/auth-factors";

interface VendorBadgeProps {
  factor: AuthFactor;
  className?: string;
}

export function VendorBadge({ factor, className }: VendorBadgeProps) {
  const badge = resolveVendorBadge(factor);
  return (
    <Badge variant="outline" className={className}>
      {badge.name}
    </Badge>
  );
}
