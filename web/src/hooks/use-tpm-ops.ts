"use client";

import { useMutation, useTPM } from "trusted-platform-sdk";
import type {
  ExtendPCRRequest,
  GetRandomRequest,
  TPMActivateCredentialRequest,
  TPMMakeCredentialRequest,
} from "trusted-platform-sdk";

/**
 * Mutations for the TPM operations that change or draw on TPM state:
 * PCR extend, MakeCredential, ActivateCredential and GetRandom (#1725).
 */
export function useTPMOps() {
  const tpm = useTPM();
  const extendPCR = useMutation((req: ExtendPCRRequest) => tpm.extendPCR(req));
  const makeCredential = useMutation((req: TPMMakeCredentialRequest) =>
    tpm.makeCredential(req)
  );
  const activateCredential = useMutation((req: TPMActivateCredentialRequest) =>
    tpm.activateCredential(req)
  );
  const getRandom = useMutation((req: GetRandomRequest) => tpm.getRandom(req));
  return { extendPCR, makeCredential, activateCredential, getRandom };
}

/** Base64 of a UTF-8 string. */
export function textToBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  bytes.forEach((b) => {
    bin += String.fromCharCode(b);
  });
  return btoa(bin);
}

/** Lower-case hex of base64 bytes; empty for an invalid input. */
export function base64ToHex(b64: string): string {
  try {
    return Array.from(atob(b64), (c) =>
      c.charCodeAt(0).toString(16).padStart(2, "0")
    ).join("");
  } catch {
    return "";
  }
}
