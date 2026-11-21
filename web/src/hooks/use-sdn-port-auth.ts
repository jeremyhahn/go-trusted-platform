"use client";

/**
 * SDN port authentication: AuthenticatePort and RevokePortAuth on
 * `POST|DELETE /api/v1/sdn/bridges/{name}/ports/{port}/auth`
 * (pkg/webservice/v1/rest/sdn/handlers.go lines 219-240).
 *
 * The hook calls the SDK SDNService from `useSDN()`, never a hand-written
 * fetch. The certificate travels base64 on the wire (proto `bytes`), so a PEM
 * text is base64-encoded here; a DER is given already base64-encoded.
 *
 * Revoking drops the port's authentication: a control that calls `revoke`
 * must ask the operator to confirm first.
 */

import { useMemo } from "react";
import { useSDN } from "trusted-platform-sdk";

/** UTF-8 text to base64 (TextEncoder + btoa over the bytes). */
export function certificateToBase64(pem: string): string {
  const bytes = new TextEncoder().encode(pem);
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary);
}

export function useSDNPortAuth(bridgeId: string, portId: string) {
  const sdn = useSDN();
  return useMemo(
    () => ({
      authenticatePEM: (pem: string) =>
        sdn.authenticatePort({ bridgeId, portId, certificate: certificateToBase64(pem.trim()), format: "PEM" }),
      authenticateDER: (derBase64: string) =>
        sdn.authenticatePort({ bridgeId, portId, certificate: derBase64.trim(), format: "DER" }),
      revoke: () => sdn.revokePortAuth(bridgeId, portId),
    }),
    [sdn, bridgeId, portId]
  );
}
