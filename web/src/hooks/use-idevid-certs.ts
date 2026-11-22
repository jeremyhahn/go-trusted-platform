"use client";

/**
 * useIDevIDCerts wraps the IDevID certificate operations of the control
 * plane: InstallIDevIDCertificate (`POST /api/v1/idevid/certificate`),
 * InstallIAKCertificate (`POST /api/v1/idevid/iak/certificate`),
 * DeleteIAKCertificate (`DELETE /api/v1/idevid/iak/certificate`) and
 * ActivateCredential (`POST /api/v1/idevid/activate-credential`), served by
 * pkg/webservice/v1/rest/idevid/router.go.
 *
 * It calls the SDK IDevIDService from `useIDevID()`. PEM fields are proto
 * bytes, so they travel as base64 on the wire: the hook takes PEM text and
 * encodes it; `base64ToPem` decodes base64 PEM bytes back to text. The hook
 * offers no IAK CSR call until the daemon's CreateIAKCSR returns a usable PEM
 * CSR.
 *
 * Deleting the IAK certificate cannot be undone, so a control that calls
 * `deleteIAKCertificate` must ask the operator to confirm first.
 */
import { useMemo } from "react";
import { useIDevID } from "trusted-platform-sdk";

/** UTF-8 text to base64 (TextEncoder + btoa over the bytes). */
export function pemToBase64(pem: string): string {
  const bytes = new TextEncoder().encode(pem);
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary);
}

/** base64 to UTF-8 text (atob + TextDecoder); "" for "" or undefined. */
export function base64ToPem(b64: string | undefined): string {
  if (!b64) {
    return "";
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

/** true when the text holds a `-----BEGIN <label>-----` ... `-----END <label>-----` block. */
export function looksLikePem(text: string, label: string): boolean {
  const begin = text.indexOf(`-----BEGIN ${label}-----`);
  if (begin < 0) {
    return false;
  }
  return text.indexOf(`-----END ${label}-----`, begin) > begin;
}

export function useIDevIDCerts() {
  const idevid = useIDevID();
  return useMemo(
    () => ({
      installIDevIDCertificate: (pem: string) =>
        idevid.installIDevIDCertificate({ certificatePem: pemToBase64(pem.trim()) }),
      installIAKCertificate: (pem: string) =>
        idevid.installIAKCertificate({ certificatePem: pemToBase64(pem.trim()) }),
      deleteIAKCertificate: () => idevid.deleteIAKCertificate(),
      activateCredential: (credentialBlobB64: string, secretB64: string) =>
        idevid.activateCredential({ credentialBlob: credentialBlobB64.trim(), secret: secretB64.trim() }),
    }),
    [idevid]
  );
}
