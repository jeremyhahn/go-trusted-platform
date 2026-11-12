"use client";

/**
 * TPM IDevID and IAK Page
 *
 * Device identity (IEEE 802.1AR / TCG TPM 2.0 Keys for Device Identity)
 * on the local TPM: IDevID and IAK presence, TCG device attributes, IAK
 * key and CSR operations, LDevID issuance, certificate install and delete,
 * and maintenance (flush transient contexts, activate credential).
 *
 * Every destructive action sits behind a confirm dialog.
 */

import * as React from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { RefreshCw } from "lucide-react";
import { useApi, useIDevID, useMutation, useToast } from "@/hooks";
import { ConfirmAction } from "@/components/features/tpm/confirm-action";

/**
 * Proto bytes fields arrive base64-encoded. PEM bytes are shown as text;
 * binary bytes (a TCG_CSR_IDEVID) stay base64 so they can be exported intact.
 */
const decodePem = (value?: string): string => {
  if (!value) return "";
  if (value.startsWith("-----BEGIN")) return value;
  try {
    const decoded = atob(value);
    return decoded.startsWith("-----BEGIN") ? decoded : value;
  } catch {
    return value;
  }
};

const encodePem = (pem: string): string => btoa(pem.trim());

const PresenceBadge = ({ present, testId }: { present?: boolean; testId: string }) => (
  <Badge data-testid={testId} variant={present ? "default" : "secondary"}>
    {present === undefined ? "Unknown" : present ? "Present" : "Absent"}
  </Badge>
);

const ATTRIBUTE_LABELS: Array<[string, string]> = [
  ["tpmManufacturer", "TPM manufacturer"],
  ["tpmModel", "TPM model"],
  ["tpmVersion", "TPM version"],
  ["platformManufacturer", "Platform manufacturer"],
  ["platformModel", "Platform model"],
  ["platformVersion", "Platform version"],
  ["platformSerial", "Platform serial"],
];

export default function TPMIDevIDPage() {
  const { toast } = useToast();
  const idevid = useIDevID();

  const [ldevidCn, setLdevidCn] = React.useState("");
  const [idevidPem, setIdevidPem] = React.useState("");
  const [iakPem, setIakPem] = React.useState("");
  const [credentialBlob, setCredentialBlob] = React.useState("");
  const [credentialSecret, setCredentialSecret] = React.useState("");
  const [result, setResult] = React.useState<{ title: string; body: string } | null>(null);

  const onError = (title: string) => (err: { message: string }) =>
    toast({ title, description: err.message, variant: "destructive" });

  const hasIDevID = useApi(() => idevid.hasIDevID(), [], { onError: onError("Error loading IDevID status") });
  const hasIAK = useApi(() => idevid.hasIAK(), [], { onError: onError("Error loading IAK status") });
  const attributes = useApi(() => idevid.getDeviceAttributes(), [], {
    onError: onError("Error loading device attributes"),
  });

  const refreshStatus = () => {
    hasIDevID.refetch();
    hasIAK.refetch();
    attributes.refetch();
  };

  const done = (title: string, body?: string) => {
    toast({ title, variant: "default" });
    if (body !== undefined) setResult({ title, body });
    refreshStatus();
  };

  const generateIAK = useMutation(() => idevid.generateIAK(), {
    onSuccess: () => done("IAK generated"),
    onError: onError("Error generating IAK"),
  });
  const deleteIAK = useMutation(() => idevid.deleteIAK(), {
    onSuccess: () => done("IAK deleted"),
    onError: onError("Error deleting IAK"),
  });
  const createIAKCSR = useMutation(() => idevid.createIAKCSR(), {
    onSuccess: (r) => done("IAK CSR created (TCG_CSR_IDEVID, base64)", decodePem(r.csrPem)),
    onError: onError("Error creating IAK CSR"),
  });
  const createLDevID = useMutation(
    () => idevid.createLDevID({ template: ldevidCn ? { commonName: ldevidCn } : undefined }),
    {
      onSuccess: (r) => done("LDevID created", decodePem(r.certificatePem)),
      onError: onError("Error creating LDevID"),
    }
  );
  const installIDevIDCert = useMutation(
    () => idevid.installIDevIDCertificate({ certificatePem: encodePem(idevidPem) }),
    {
      onSuccess: () => {
        setIdevidPem("");
        done("IDevID certificate installed");
      },
      onError: onError("Error installing IDevID certificate"),
    }
  );
  const installIAKCert = useMutation(
    () => idevid.installIAKCertificate({ certificatePem: encodePem(iakPem) }),
    {
      onSuccess: () => {
        setIakPem("");
        done("IAK certificate installed");
      },
      onError: onError("Error installing IAK certificate"),
    }
  );
  const deleteIAKCert = useMutation(() => idevid.deleteIAKCertificate(), {
    onSuccess: () => done("IAK certificate deleted"),
    onError: onError("Error deleting IAK certificate"),
  });
  const flush = useMutation(() => idevid.flushTransientContexts(), {
    onSuccess: (r) => done("Transient contexts flushed", `Flushed ${r.flushedCount ?? 0} contexts`),
    onError: onError("Error flushing transient contexts"),
  });
  const activate = useMutation(
    () => idevid.activateCredential({ credentialBlob, secret: credentialSecret }),
    {
      onSuccess: (r) => done("Credential activated", r.decryptedSecret ?? ""),
      onError: onError("Error activating credential"),
    }
  );

  const loading = hasIDevID.isLoading || hasIAK.isLoading || attributes.isLoading;
  const attrs = (attributes.data?.attributes ?? {}) as Record<string, string | undefined>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">IDevID and IAK</h1>
          <p className="text-muted-foreground">
            Device identity keys, certificates and TCG device attributes on the TPM
          </p>
        </div>
        <Button variant="outline" onClick={refreshStatus} disabled={loading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Status</CardTitle>
          <CardDescription>Device identity keys and TCG device attributes</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-6">
            <div className="flex items-center gap-2">
              <span>IDevID</span>
              <PresenceBadge testId="idevid-status" present={hasIDevID.data?.exists} />
            </div>
            <div className="flex items-center gap-2">
              <span>IAK</span>
              <PresenceBadge testId="iak-status" present={hasIAK.data?.exists} />
            </div>
          </div>
          <dl className="grid grid-cols-2 gap-2 text-sm" data-testid="device-attributes">
            {ATTRIBUTE_LABELS.map(([key, label]) => (
              <React.Fragment key={key}>
                <dt className="text-muted-foreground">{label}</dt>
                <dd>{attrs[key] || "—"}</dd>
              </React.Fragment>
            ))}
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>IAK</CardTitle>
          <CardDescription>Attestation key, its CSR, and LDevID issuance</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <Button onClick={() => generateIAK.mutate(undefined)} disabled={generateIAK.isLoading}>
              Generate IAK
            </Button>
            <Button variant="outline" onClick={() => createIAKCSR.mutate(undefined)} disabled={createIAKCSR.isLoading}>
              Create IAK CSR
            </Button>
            <ConfirmAction
              label="Delete IAK"
              title="Delete the IAK?"
              description="The IAK is TPM-resident and this service does not evict it: the request is refused and nothing changes. Remove the IAK certificate with Delete IAK certificate."
              onConfirm={() => deleteIAK.mutate(undefined)}
              disabled={deleteIAK.isLoading}
            />
          </div>
          <div className="flex items-end gap-2">
            <div className="space-y-1">
              <Label htmlFor="ldevid-cn">LDevID common name</Label>
              <Input id="ldevid-cn" value={ldevidCn} onChange={(e) => setLdevidCn(e.target.value)} />
            </div>
            <Button onClick={() => createLDevID.mutate(undefined)} disabled={createLDevID.isLoading}>
              Create LDevID
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Certificates</CardTitle>
          <CardDescription>Install the IDevID and IAK certificates issued by the CA</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1">
            <Label htmlFor="idevid-pem">IDevID certificate (PEM)</Label>
            <Textarea id="idevid-pem" rows={4} value={idevidPem} onChange={(e) => setIdevidPem(e.target.value)} />
            <Button
              onClick={() => installIDevIDCert.mutate(undefined)}
              disabled={!idevidPem.trim() || installIDevIDCert.isLoading}
            >
              Install IDevID certificate
            </Button>
          </div>
          <div className="space-y-1">
            <Label htmlFor="iak-pem">IAK certificate (PEM)</Label>
            <Textarea id="iak-pem" rows={4} value={iakPem} onChange={(e) => setIakPem(e.target.value)} />
            <div className="flex gap-2">
              <Button
                onClick={() => installIAKCert.mutate(undefined)}
                disabled={!iakPem.trim() || installIAKCert.isLoading}
              >
                Install IAK certificate
              </Button>
              <ConfirmAction
                label="Delete IAK certificate"
                title="Delete the IAK certificate?"
                description="The installed IAK certificate is removed. The IAK key stays on the TPM."
                onConfirm={() => deleteIAKCert.mutate(undefined)}
                disabled={deleteIAKCert.isLoading}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Maintenance</CardTitle>
          <CardDescription>Transient TPM contexts and credential activation</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <ConfirmAction
            label="Flush transient contexts"
            title="Flush transient contexts?"
            description="Every transient object loaded in the TPM is flushed. Operations in flight may fail."
            onConfirm={() => flush.mutate(undefined)}
            disabled={flush.isLoading}
          />
          <div className="grid gap-2 md:grid-cols-2">
            <div className="space-y-1">
              <Label htmlFor="credential-blob">Credential blob (base64)</Label>
              <Input id="credential-blob" value={credentialBlob} onChange={(e) => setCredentialBlob(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="credential-secret">Encrypted secret (base64)</Label>
              <Input
                id="credential-secret"
                value={credentialSecret}
                onChange={(e) => setCredentialSecret(e.target.value)}
              />
            </div>
          </div>
          <Button
            onClick={() => activate.mutate(undefined)}
            disabled={!credentialBlob || !credentialSecret || activate.isLoading}
          >
            Activate credential
          </Button>
        </CardContent>
      </Card>

      {result && (
        <Card data-testid="idevid-result">
          <CardHeader>
            <CardTitle>{result.title}</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="whitespace-pre-wrap break-all text-xs">{result.body}</pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
