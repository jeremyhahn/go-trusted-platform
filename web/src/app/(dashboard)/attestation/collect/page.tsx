"use client";

import * as React from "react";
import { PageHeader } from "@/components/layout/page-header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useAttestationCollect } from "@/hooks/use-attestation-collect";
import type { CollectContainerAttestationResponse, CollectVMAttestationResponse } from "trusted-platform-sdk";

// #2038: the host, VM and container attestation collect operations, driven
// through useAttestationCollect. The operator types the nonce (base64) and
// the PCR indices; the page generates neither.

type PcrParse = { indices: number[]; error?: undefined } | { indices?: undefined; error: string };

function parsePcrIndices(text: string): PcrParse {
  const parts = text
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
  const indices: number[] = [];
  for (const part of parts) {
    if (!/^\d+$/.test(part)) {
      return { error: `"${part}" is not a PCR index (use comma-separated integers)` };
    }
    indices.push(Number(part));
  }
  return { indices };
}

type Outcome<T> = { data: T } | { error: string };

interface Refusal {
  success: boolean;
  data?: unknown;
  error?: { message?: string } | string;
}

function refusalMessage(res: Refusal): string {
  if (typeof res.error === "string") return res.error;
  return res.error?.message || "The collect request was refused";
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function Field(props: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  error?: string;
}) {
  return (
    <div className="space-y-1">
      <Label htmlFor={props.id}>{props.label}</Label>
      <Input
        id={props.id}
        data-testid={props.id}
        value={props.value}
        placeholder={props.placeholder}
        onChange={(e) => props.onChange(e.target.value)}
      />
      {props.error && (
        <p className="text-sm text-destructive" data-testid={`${props.id}-error`}>
          {props.error}
        </p>
      )}
    </div>
  );
}

function RefusalAlert({ message }: { message: string }) {
  return (
    <Alert variant="destructive">
      <AlertTitle>Collect refused</AlertTitle>
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  );
}

function VerifiedBadge({ verified }: { verified: boolean }) {
  return <Badge variant={verified ? "default" : "destructive"}>{verified ? "Verified" : "Not verified"}</Badge>;
}

export default function AttestationCollectPage() {
  const { collectHost, collectVM, collectContainer } = useAttestationCollect();

  const [hostPcrs, setHostPcrs] = React.useState("");
  const [hostNonce, setHostNonce] = React.useState("");
  const [hostPcrError, setHostPcrError] = React.useState<string>();
  const [hostBusy, setHostBusy] = React.useState(false);
  const [hostOutcome, setHostOutcome] = React.useState<Outcome<{ status: { success: boolean; message: string } }>>();

  const [vmId, setVmId] = React.useState("");
  const [vmPcrs, setVmPcrs] = React.useState("");
  const [vmNonce, setVmNonce] = React.useState("");
  const [vmPcrError, setVmPcrError] = React.useState<string>();
  const [vmBusy, setVmBusy] = React.useState(false);
  const [vmOutcome, setVmOutcome] = React.useState<Outcome<CollectVMAttestationResponse>>();

  const [containerId, setContainerId] = React.useState("");
  const [containerBusy, setContainerBusy] = React.useState(false);
  const [containerOutcome, setContainerOutcome] =
    React.useState<Outcome<CollectContainerAttestationResponse>>();

  const onHost = async () => {
    const pcrs = parsePcrIndices(hostPcrs);
    setHostPcrError(pcrs.error);
    if (pcrs.error !== undefined) return;
    setHostBusy(true);
    try {
      const res = await collectHost({ config: { pcrIndices: pcrs.indices }, nonce: hostNonce.trim() });
      setHostOutcome(res.success && res.data ? { data: res.data } : { error: refusalMessage(res as Refusal) });
    } catch (err) {
      setHostOutcome({ error: errorMessage(err) });
    } finally {
      setHostBusy(false);
    }
  };

  const onVM = async () => {
    const pcrs = parsePcrIndices(vmPcrs);
    setVmPcrError(pcrs.error);
    if (pcrs.error !== undefined) return;
    setVmBusy(true);
    try {
      const res = await collectVM({
        vmId: vmId.trim(),
        config: { pcrIndices: pcrs.indices },
        nonce: vmNonce.trim(),
      });
      setVmOutcome(res.success && res.data ? { data: res.data } : { error: refusalMessage(res as Refusal) });
    } catch (err) {
      setVmOutcome({ error: errorMessage(err) });
    } finally {
      setVmBusy(false);
    }
  };

  const onContainer = async () => {
    setContainerBusy(true);
    try {
      const res = await collectContainer({ containerId: containerId.trim() });
      setContainerOutcome(
        res.success && res.data ? { data: res.data } : { error: refusalMessage(res as Refusal) }
      );
    } catch (err) {
      setContainerOutcome({ error: errorMessage(err) });
    } finally {
      setContainerBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Collect Attestation"
        description="Collect a TPM attestation from the host, a VM or a container"
      />

      <Card>
        <CardHeader>
          <CardTitle>Host</CardTitle>
          <CardDescription>Quote the host TPM over the selected PCRs with your nonce.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Field
            id="collect-host-pcrs"
            label="PCR indices"
            placeholder="0, 7, 11"
            value={hostPcrs}
            onChange={setHostPcrs}
            error={hostPcrError}
          />
          <Field id="collect-host-nonce" label="Nonce (base64)" value={hostNonce} onChange={setHostNonce} />
          <Button data-testid="collect-host-submit" onClick={onHost} disabled={hostBusy}>
            Collect
          </Button>
          {hostOutcome && "error" in hostOutcome && <RefusalAlert message={hostOutcome.error} />}
          {hostOutcome && "data" in hostOutcome && (
            <div data-testid="collect-host-result" className="text-sm">
              Status:{" "}
              <Badge variant={hostOutcome.data.status.success ? "secondary" : "destructive"}>
                {hostOutcome.data.status.message}
              </Badge>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>VM</CardTitle>
          <CardDescription>Collect and verify the attestation of a virtual machine.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Field id="collect-vm-id" label="VM ID" value={vmId} onChange={setVmId} />
          <Field
            id="collect-vm-pcrs"
            label="PCR indices"
            placeholder="0, 7, 11"
            value={vmPcrs}
            onChange={setVmPcrs}
            error={vmPcrError}
          />
          <Field id="collect-vm-nonce" label="Nonce (base64)" value={vmNonce} onChange={setVmNonce} />
          <Button data-testid="collect-vm-submit" onClick={onVM} disabled={vmBusy}>
            Collect
          </Button>
          {vmOutcome && "error" in vmOutcome && <RefusalAlert message={vmOutcome.error} />}
          {vmOutcome && "data" in vmOutcome && (
            <div data-testid="collect-vm-result" className="space-y-1 text-sm">
              <VerifiedBadge verified={vmOutcome.data.status.success} />
              {vmOutcome.data.attestation?.hostId && <p>Host: {vmOutcome.data.attestation?.hostId}</p>}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Container</CardTitle>
          <CardDescription>Collect and verify the attestation of a container.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Field id="collect-container-id" label="Container ID" value={containerId} onChange={setContainerId} />
          <Button data-testid="collect-container-submit" onClick={onContainer} disabled={containerBusy}>
            Collect
          </Button>
          {containerOutcome && "error" in containerOutcome && <RefusalAlert message={containerOutcome.error} />}
          {containerOutcome && "data" in containerOutcome && (
            <div data-testid="collect-container-result" className="space-y-1 text-sm">
              <VerifiedBadge verified={containerOutcome.data.status.success} />
              <p className="font-mono break-all">Digest: {containerOutcome.data.attestation?.digest}</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
