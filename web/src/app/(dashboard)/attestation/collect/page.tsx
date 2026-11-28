"use client";

/**
 * CollectAttestationPage: CollectHostAttestation, CollectVMAttestation and
 * CollectContainerAttestation through the SDK AttestationService (#2038).
 * Each button sits in <Gated> on the server's route, so a node without
 * attestation withholds it.
 */

import * as React from "react";
import type {
  CollectContainerAttestationResponse,
  CollectVMAttestationResponse,
  HostAttestation,
} from "trusted-platform-sdk";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Gated } from "@/components/features/capabilities/gated";
import { parsePcrIndices } from "@/components/features/attestation/attestation-quote-card";
import { useAttestation } from "@/hooks";

type AttestationClient = ReturnType<typeof useAttestation>;
type QuoteConfig = Parameters<AttestationClient["collectHostAttestation"]>[0]["config"];

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function quoteConfig(pcrs: string, akHandle = ""): QuoteConfig {
  const config: QuoteConfig = {};
  const indices = parsePcrIndices(pcrs);
  if (indices.length > 0) config.pcrIndices = indices;
  if (akHandle.trim() !== "") {
    const handle = Number(akHandle.trim());
    if (!Number.isInteger(handle) || handle < 0) {
      throw new Error(`invalid AK handle: ${akHandle}`);
    }
    config.akHandle = handle;
  }
  return config;
}

function Field({
  id,
  label,
  value,
  onChange,
  placeholder,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <div className="grid gap-1">
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} data-testid={id} placeholder={placeholder} value={value} onChange={(e) => onChange(e.target.value)} />
    </div>
  );
}

function ErrorLine({ message }: { message: string | null }) {
  return message ? (
    <p role="alert" className="text-sm text-destructive">
      {message}
    </p>
  ) : null;
}

function HostCard() {
  const attestation = useAttestation();
  const [nonce, setNonce] = React.useState("");
  const [pcrs, setPcrs] = React.useState("");
  const [akHandle, setAkHandle] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [result, setResult] = React.useState<HostAttestation | null>(null);

  const collect = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setResult(null);
    let config: QuoteConfig;
    try {
      config = quoteConfig(pcrs, akHandle);
    } catch (err) {
      setError(errorText(err));
      return;
    }
    setBusy(true);
    try {
      const res = await attestation.collectHostAttestation({ nonce: nonce.trim(), config });
      if (!res.success || !res.data) {
        setError(res.error?.message ?? "no attestation in the answer");
        return;
      }
      if (res.data.status && res.data.status.success === false) {
        setError(res.data.status.error?.message || res.data.status.message || "host attestation failed");
        return;
      }
      if (!res.data.attestation) {
        setError("no attestation in the answer");
        return;
      }
      setResult(res.data.attestation);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="attestation-collect-host">
      <CardHeader>
        <CardTitle>Host attestation</CardTitle>
        <CardDescription>Collect this node&apos;s TPM attestation over a nonce</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="flex flex-col gap-3" onSubmit={collect}>
          <Field id="attestation-collect-host-nonce" label="Nonce (base64)" value={nonce} onChange={setNonce} />
          <Field id="attestation-collect-host-pcrs" label="PCR indices" placeholder="0,1,7" value={pcrs} onChange={setPcrs} />
          <Field id="attestation-collect-host-ak-handle" label="AK handle" placeholder="optional" value={akHandle} onChange={setAkHandle} />
          <ErrorLine message={error} />
          <div>
            <Gated op="POST /api/v1/attestation/host">
              <Button type="submit" variant="outline" disabled={busy}>
                Collect host attestation
              </Button>
            </Gated>
          </div>
          {result && (
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm" data-testid="attestation-collect-host-result">
              <dt className="text-muted-foreground">PCR digest</dt>
              <dd className="font-mono break-all">{result.pcrDigest || "none"}</dd>
              <dt className="text-muted-foreground">Signature algorithm</dt>
              <dd className="font-mono">{result.signatureAlgorithm || "none"}</dd>
              <dt className="text-muted-foreground">Hash algorithm</dt>
              <dd className="font-mono">{result.hashAlgorithm || "none"}</dd>
              <dt className="text-muted-foreground">Nonce</dt>
              <dd className="font-mono break-all">{result.nonce || "none"}</dd>
              <dt className="text-muted-foreground">Timestamp</dt>
              <dd>{result.timestamp || "none"}</dd>
              <dt className="text-muted-foreground">PCRs</dt>
              <dd>
                {(result.pcrs ?? []).length === 0 ? (
                  <span className="text-muted-foreground">none</span>
                ) : (
                  <ul className="space-y-1">
                    {(result.pcrs ?? []).map((pcr) => (
                      <li key={`${pcr.algorithm}-${pcr.index}`} className="font-mono break-all" data-testid="attestation-collect-host-pcr">
                        {pcr.index} ({pcr.algorithm}): {pcr.value}
                      </li>
                    ))}
                  </ul>
                )}
              </dd>
            </dl>
          )}
        </form>
      </CardContent>
    </Card>
  );
}

function VMCard() {
  const attestation = useAttestation();
  const [vmId, setVmId] = React.useState("");
  const [nonce, setNonce] = React.useState("");
  const [pcrs, setPcrs] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [result, setResult] = React.useState<CollectVMAttestationResponse | null>(null);
  const ready = vmId.trim() !== "" && nonce.trim() !== "";

  const collect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    setError(null);
    setResult(null);
    let config: QuoteConfig;
    try {
      config = quoteConfig(pcrs);
    } catch (err) {
      setError(errorText(err));
      return;
    }
    setBusy(true);
    try {
      const res = await attestation.collectVMAttestation({ vmId: vmId.trim(), nonce: nonce.trim(), config });
      if (!res.success || !res.data?.attestation) {
        setError(res.error?.message ?? "no attestation in the answer");
        return;
      }
      setResult(res.data);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="attestation-collect-vm">
      <CardHeader>
        <CardTitle>VM attestation</CardTitle>
        <CardDescription>Collect a VM&apos;s vTPM attestation over a nonce</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="flex flex-col gap-3" onSubmit={collect}>
          <Field id="attestation-collect-vm-id" label="VM ID" value={vmId} onChange={setVmId} />
          <Field id="attestation-collect-vm-nonce" label="Nonce (base64)" value={nonce} onChange={setNonce} />
          <Field id="attestation-collect-vm-pcrs" label="PCR indices" placeholder="0,1,7" value={pcrs} onChange={setPcrs} />
          <ErrorLine message={error} />
          <div>
            <Gated op="POST /api/v1/attestation/vm/{id}">
              <Button type="submit" variant="outline" disabled={busy || !ready}>
                Collect VM attestation
              </Button>
            </Gated>
          </div>
          {result && (
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm" data-testid="attestation-collect-vm-result">
              <dt className="text-muted-foreground">VM</dt>
              <dd className="font-mono break-all">{result.attestation?.vmId || "none"}</dd>
              <dt className="text-muted-foreground">Host</dt>
              <dd className="font-mono break-all">{result.attestation?.hostId || "none"}</dd>
              <dt className="text-muted-foreground">PCR digest</dt>
              <dd className="font-mono break-all">{result.attestation?.pcrDigest || "none"}</dd>
              <dt className="text-muted-foreground">Signature algorithm</dt>
              <dd className="font-mono">{result.attestation?.signatureAlgorithm || "none"}</dd>
              <dt className="text-muted-foreground">Hash algorithm</dt>
              <dd className="font-mono">{result.attestation?.hashAlgorithm || "none"}</dd>
              <dt className="text-muted-foreground">PCRs</dt>
              <dd>{result.attestation?.pcrs?.length ?? 0}</dd>
              <dt className="text-muted-foreground">Timestamp</dt>
              <dd>{result.attestation?.timestamp || "none"}</dd>
            </dl>
          )}
        </form>
      </CardContent>
    </Card>
  );
}

function ContainerCard() {
  const attestation = useAttestation();
  const [containerId, setContainerId] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [result, setResult] = React.useState<CollectContainerAttestationResponse | null>(null);
  const ready = containerId.trim() !== "";

  const collect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    setError(null);
    setResult(null);
    setBusy(true);
    try {
      const res = await attestation.collectContainerAttestation({ containerId: containerId.trim() });
      if (!res.success || !res.data?.attestation) {
        setError(res.error?.message ?? "no attestation in the answer");
        return;
      }
      setResult(res.data);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="attestation-collect-container">
      <CardHeader>
        <CardTitle>Container attestation</CardTitle>
        <CardDescription>Collect a container&apos;s measurement</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="flex flex-col gap-3" onSubmit={collect}>
          <Field id="attestation-collect-container-id" label="Container ID" value={containerId} onChange={setContainerId} />
          <ErrorLine message={error} />
          <div>
            <Gated op="POST /api/v1/attestation/container/{id}">
              <Button type="submit" variant="outline" disabled={busy || !ready}>
                Collect container attestation
              </Button>
            </Gated>
          </div>
          {result && (
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm" data-testid="attestation-collect-container-result">
              <dt className="text-muted-foreground">Container</dt>
              <dd className="font-mono break-all">{result.attestation?.containerId || "none"}</dd>
              <dt className="text-muted-foreground">Image digest</dt>
              <dd className="font-mono break-all">{result.attestation?.imageDigest || "none"}</dd>
              <dt className="text-muted-foreground">Digest</dt>
              <dd className="font-mono break-all">{result.attestation?.digest || "none"}</dd>
              <dt className="text-muted-foreground">PCR value</dt>
              <dd className="font-mono break-all">{result.attestation?.pcrValue || "none"}</dd>
              <dt className="text-muted-foreground">Timestamp</dt>
              <dd>{result.attestation?.timestamp || "none"}</dd>
            </dl>
          )}
        </form>
      </CardContent>
    </Card>
  );
}

// CollectAttestationPage collects host, VM and container attestation
// (AttestationService.CollectHostAttestation, CollectVMAttestation and
// CollectContainerAttestation), each only when the server offers its route.
export default function CollectAttestationPage() {
  return (
    <div className="container mx-auto py-6 space-y-6">
      <PageHeader title="Collect attestation" description="Collect host, VM and container attestation evidence" />
      <div className="grid gap-6 lg:grid-cols-3">
        <HostCard />
        <VMCard />
        <ContainerCard />
      </div>
    </div>
  );
}
