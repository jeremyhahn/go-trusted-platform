"use client";

// CAService operations for the CA pages (#2041, epic #1665): GetCAInfo,
// VerifyCertificate and SignCSR through the SDK client, and the three
// lifecycle operations the daemon serves no route for (InitCA,
// InstallCACertificates, UninstallCACertificates), which the pages show as
// disabled controls with the reason below.
import { createPlatformClient } from "trusted-platform-sdk";
import { useApi, useCA, useMutation, usePlatformClient } from "@/hooks";

export type CAGatedOperation = "InitCA" | "InstallCACertificates" | "UninstallCACertificates";

export interface CAGatedControl {
  operation: CAGatedOperation;
  testId: string;
  label: string;
}

export const CA_GATED_CONTROLS: readonly CAGatedControl[] = [
  { operation: "InitCA", testId: "ca-init-control", label: "Initialize CA" },
  { operation: "InstallCACertificates", testId: "ca-install-control", label: "Install CA certificates" },
  { operation: "UninstallCACertificates", testId: "ca-uninstall-control", label: "Uninstall CA certificates" },
];

/**
 * Why a lifecycle control is off: the daemon runs these at start
 * (LoadOrInitCA, with the SO and user PINs from its own configuration), and
 * neither its gRPC CAService nor the REST API serves them.
 */
export function caOperationReason(operation: CAGatedOperation): string {
  return `Not available: the daemon runs ${operation} at start-up with its own PINs and serves no API route for it`;
}

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

/** The VerifyCertificate body: the PEM's base64 DER, revocation requested. */
export function pemToVerifyRequest(pem: string): { certificatePem: string; verifyRevocation: true } {
  const b64 = pem
    .split(/\r?\n/)
    .filter((line) => !line.startsWith("-----"))
    .join("")
    .replace(/\s+/g, "");
  return { certificatePem: b64, verifyRevocation: true };
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
 * SignCSR needs a token with the ca:sign-csr scope, which the browser
 * session does not carry: the request goes through a client that sends the
 * pasted token as its bearer.
 */
export function useSignCSR<K = unknown>(options?: { onSuccess?: (data: unknown, input: SignCSRInput & { key?: K }) => void }) {
  const { baseUrl } = usePlatformClient();
  const signAsync = (input: SignCSRInput & { key?: K }) => {
    const days = input.validDays;
    return createPlatformClient({
      baseUrl,
      credentials: "include",
      headers: { Authorization: `Bearer ${input.token.trim()}` },
    }).ca.signCSR({
      csrPem: input.csrPem.trim(),
      ...(typeof days === "number" && Number.isFinite(days) && days > 0 ? { validDays: days } : {}),
    });
  };
  const mutation = useMutation(signAsync, { onSuccess: options?.onSuccess });
  return {
    sign: (input: SignCSRInput & { key?: K }) => mutation.mutate(input),
    signAsync,
    reset: () => mutation.reset(),
    data: mutation.data as unknown,
    error: mutation.error,
    isLoading: mutation.isLoading,
  };
}
