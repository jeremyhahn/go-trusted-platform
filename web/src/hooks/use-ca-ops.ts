"use client";

// CAService operations for the CA pages (#2041, epic #1665): GetCAInfo,
// VerifyCertificate and SignCSR through the SDK client.
import { useApi, useCA, useMutation } from "@/hooks";

export interface CACertView {
  serial?: string;
  commonName?: string;
  common_name?: string;
  subject?: string;
  issuer?: string;
}

export interface CAInfoView {
  commonName: string;
  isIntermediate: boolean;
  defaultAlgorithm: string;
  defaultValidityDays: number | undefined;
  root: CACertView | undefined;
  intermediates: CACertView[];
}

type Wire = Record<string, unknown>;

/** Read GetCAInfo in either envelope (caInfo / ca_info) or as a bare body. */
export function normalizeCAInfo(data: unknown): CAInfoView {
  const outer = (data ?? {}) as Wire;
  const info = ((outer.caInfo ?? outer.ca_info ?? outer) as Wire) ?? {};
  const validity = info.defaultValidityDays ?? info.default_validity_days;
  return {
    commonName: String(info.commonName ?? info.common_name ?? ""),
    isIntermediate: Boolean(info.isIntermediate ?? info.is_intermediate),
    defaultAlgorithm: String(info.defaultAlgorithm ?? info.default_algorithm ?? ""),
    defaultValidityDays: typeof validity === "number" ? validity : undefined,
    root: (info.rootCert ?? info.root_cert) as CACertView | undefined,
    intermediates: Array.isArray(info.intermediates) ? (info.intermediates as CACertView[]) : [],
  };
}

/**
 * The VerifyCertificate body: the PEM's base64 DER in certificateDer, revocation
 * requested. certificate_pem is bytes the server PEM-decodes, so DER goes in
 * certificate_der.
 */
export function pemToVerifyRequest(pem: string): { certificateDer: string; verifyRevocation: true } {
  const b64 = pem
    .split(/\r?\n/)
    .filter((line) => !line.startsWith("-----"))
    .join("")
    .replace(/\s+/g, "");
  return { certificateDer: b64, verifyRevocation: true };
}

export function useCAInfo() {
  const ca = useCA();
  const { data, isLoading, error, refetch } = useApi(() => ca.getInfo(), []);
  return { info: normalizeCAInfo(data), isLoading, error, refetch };
}

export interface VerifyResultView {
  valid?: boolean;
  chain?: string[];
  errors?: string[];
  warnings?: string[];
}

export function useVerifyCertificate(options?: { onSuccess?: (data: unknown, pem: string) => void }) {
  const ca = useCA();
  const verifyAsync = (pem: string) => ca.verifyCertificate(pemToVerifyRequest(pem));
  const mutation = useMutation(verifyAsync, { onSuccess: options?.onSuccess });
  return {
    verify: (pem: string) => mutation.mutate(pem),
    verifyAsync,
    reset: () => mutation.reset(),
    data: mutation.data as VerifyResultView | undefined,
    error: mutation.error,
    isLoading: mutation.isLoading,
  };
}

export interface SignCSRInput {
  csrPem: string;
  token: string;
  validDays?: number;
}

/**
 * Why the console cannot sign a CSR: POST /v1/ca/sign-csr needs a platform
 * token with the ca:sign-csr scope, and the server's platform-token
 * middleware accepts only DPoP-bound tokens. The console has no DPoP key or
 * proof, so a bearer-only request is always refused.
 */
export const SIGN_CSR_UNAVAILABLE_REASON =
  "Signing a CSR needs a DPoP-bound platform token, and the console cannot send a DPoP proof yet";

/**
 * SignCSR is unavailable from the console (SIGN_CSR_UNAVAILABLE_REASON):
 * the hook reports available: false with the reason, and sign/signAsync
 * fail without sending a request.
 */
export function useSignCSR<K = unknown>(options?: { onSuccess?: (data: unknown, input: SignCSRInput & { key?: K }) => void }) {
  const signAsync: (input: SignCSRInput & { key?: K }) => Promise<unknown> = () =>
    Promise.reject(new Error(SIGN_CSR_UNAVAILABLE_REASON));
  const mutation = useMutation(signAsync, { onSuccess: options?.onSuccess });
  return {
    available: false as boolean,
    reason: SIGN_CSR_UNAVAILABLE_REASON as string | undefined,
    sign: (input: SignCSRInput & { key?: K }) => mutation.mutate(input),
    signAsync,
    reset: () => mutation.reset(),
    data: mutation.data as unknown,
    error: mutation.error,
    isLoading: mutation.isLoading,
  };
}
