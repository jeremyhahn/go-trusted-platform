/**
 * PEM text on proto `bytes` fields. protojson carries bytes as standard
 * base64, so a PEM sent in a bytes field (VerifyCertificateRequest
 * .certificate_pem) must be encoded, and one received in a bytes field
 * (Certificate.pem) must be decoded before it is shown.
 */

/** Encodes PEM text as the standard base64 of its UTF-8 bytes. */
export function pemToBase64(pem: string): string {
  const bytes = new TextEncoder().encode(pem);
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary);
}

/**
 * Decodes the standard base64 of a PEM back to text. A value that is
 * already PEM, or is not valid base64, is returned unchanged.
 */
export function base64ToPem(value: string): string {
  if (value.startsWith("-----BEGIN")) {
    return value;
  }
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    return value;
  }
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
