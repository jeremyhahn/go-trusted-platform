"use client";

/**
 * KMS operations page (#1734, slice 20 of #1665).
 *
 * One card per KMS REST operation that has no page of its own: key import,
 * key status (behind a confirm dialog), key versions, hash, HMAC and its verification, random bytes, data keys and the
 * backend status.
 */

import * as React from "react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { KMS_KEY_STATUSES, useKmsOps } from "@/hooks";
import type { KmsBackendStatus, KmsKeyStatus, KmsKeyVersion } from "@/hooks";
import { AlertCircle } from "lucide-react";

function toInt(text: string, fallback: number): number {
  const n = Number.parseInt(text, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function Field(props: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  multiline?: boolean;
}) {
  return (
    <div className="flex flex-col gap-1">
      <Label htmlFor={props.id}>{props.label}</Label>
      {props.multiline ? (
        <Textarea
          id={props.id}
          value={props.value}
          onChange={(e) => props.onChange(e.target.value)}
        />
      ) : (
        <Input
          id={props.id}
          value={props.value}
          onChange={(e) => props.onChange(e.target.value)}
        />
      )}
    </div>
  );
}

function OpCard(props: {
  id: string;
  title: string;
  description: string;
  children: React.ReactNode;
  result?: React.ReactNode;
}) {
  return (
    <Card data-testid={`op-${props.id}`}>
      <CardHeader className="pb-2">
        <CardTitle className="text-base">{props.title}</CardTitle>
        <CardDescription>{props.description}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {props.children}
        {props.result !== undefined && props.result !== null && (
          <pre
            data-testid={`${props.id}-result`}
            className="whitespace-pre-wrap break-all rounded bg-muted p-2 text-xs"
          >
            {props.result}
          </pre>
        )}
      </CardContent>
    </Card>
  );
}

export default function KmsOperationsPage() {
  const ops = useKmsOps();

  // Import
  const [importName, setImportName] = React.useState("");
  const [importAlg, setImportAlg] = React.useState("aes-256-gcm");
  const [importMaterial, setImportMaterial] = React.useState("");
  const [importResult, setImportResult] = React.useState<string | null>(null);

  // Status
  const [statusKey, setStatusKey] = React.useState("");
  const [statusValue, setStatusValue] = React.useState<KmsKeyStatus>("DISABLED");
  const [statusVersion, setStatusVersion] = React.useState("1");
  const [statusConfirm, setStatusConfirm] = React.useState(false);
  const [statusResult, setStatusResult] = React.useState<string | null>(null);

  // Versions
  const [versionsKey, setVersionsKey] = React.useState("");
  const [versions, setVersions] = React.useState<KmsKeyVersion[] | null>(null);

  // Hash
  const [hashData, setHashData] = React.useState("");
  const [hashAlg, setHashAlg] = React.useState("SHA256");
  const [hashResult, setHashResult] = React.useState<string | null>(null);

  // HMAC
  const [hmacKey, setHmacKey] = React.useState("");
  const [hmacData, setHmacData] = React.useState("");
  const [hmacHash, setHmacHash] = React.useState("SHA256");
  const [hmacResult, setHmacResult] = React.useState<string | null>(null);
  const [vKey, setVKey] = React.useState("");
  const [vData, setVData] = React.useState("");
  const [vMac, setVMac] = React.useState("");
  const [vHash, setVHash] = React.useState("SHA256");
  const [vResult, setVResult] = React.useState<string | null>(null);

  // Random and data keys
  const [randomBytes, setRandomBytes] = React.useState("32");
  const [randomResult, setRandomResult] = React.useState<string | null>(null);
  const [dkKey, setDkKey] = React.useState("");
  const [dkAlg, setDkAlg] = React.useState("AES");
  const [dkSize, setDkSize] = React.useState("256");
  const [dkResult, setDkResult] = React.useState<string | null>(null);
  const [wdkKey, setWdkKey] = React.useState("");
  const [wdkAlg, setWdkAlg] = React.useState("AES");
  const [wdkSize, setWdkSize] = React.useState("256");
  const [wdkResult, setWdkResult] = React.useState<string | null>(null);

  // Backend
  const [backend, setBackend] = React.useState<KmsBackendStatus | null>(null);

  const onImport = async () => {
    const res = await ops.importKey({
      name: importName,
      algorithm: importAlg,
      key_material: importMaterial,
    });
    if (res) {
      setImportResult(`Imported ${res.key_id} v${res.version} (${res.algorithm})`);
    }
  };

  const onStatusConfirmed = async () => {
    setStatusConfirm(false);
    const res = await ops.updateKeyStatus(statusKey, statusValue, toInt(statusVersion, 1));
    if (res) {
      setStatusResult(`${res.key_id} v${res.version} is ${res.status}`);
    }
  };

  const onVersions = async () => {
    setVersions(await ops.getKeyVersions(versionsKey));
  };

  const onHash = async () => {
    const res = await ops.hash(hashData, hashAlg);
    if (res) {
      setHashResult(`${res.hash}: ${res.digest}`);
    }
  };

  const onHmac = async () => {
    const res = await ops.hmac(hmacKey, hmacData, hmacHash);
    if (res !== null) {
      setHmacResult(res);
    }
  };

  const onVerifyHmac = async () => {
    const res = await ops.verifyHmac(vKey, vData, vMac, vHash);
    if (res !== null) {
      setVResult(res ? "HMAC valid" : "HMAC invalid");
    }
  };

  const onRandom = async () => {
    const res = await ops.generateRandom(toInt(randomBytes, 32));
    if (res !== null) {
      setRandomResult(res);
    }
  };

  const onDataKey = async () => {
    const res = await ops.generateDataKey(dkKey, dkAlg, toInt(dkSize, 256));
    if (res) {
      setDkResult(`plaintext: ${res.plaintext_key}\nencrypted: ${res.encrypted_key}`);
    }
  };

  const onWrappedDataKey = async () => {
    const res = await ops.generateWrappedDataKey(wdkKey, wdkAlg, toInt(wdkSize, 256));
    if (res) {
      setWdkResult(`wrapped by ${res.wrapping_key_id}: ${res.wrapped_key}`);
    }
  };

  const onBackend = async () => {
    setBackend(await ops.getBackendStatus());
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">KMS Operations</h1>
        <p className="text-muted-foreground">
          Key import, status and versions, hashing, HMAC,
          random bytes, data keys and the backend status
        </p>
      </div>

      {ops.error && (
        <div
          role="alert"
          data-testid="kms-ops-error"
          className="flex items-center gap-2 rounded-lg border border-destructive p-3 text-sm text-destructive"
        >
          <AlertCircle className="h-4 w-4" />
          {ops.error}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <OpCard
          id="import"
          title="Import Key"
          description="Import existing key material (base64) as a new key"
          result={importResult}
        >
          <Field id="import-name" label="Key name" value={importName} onChange={setImportName} />
          <Field id="import-algorithm" label="Algorithm" value={importAlg} onChange={setImportAlg} />
          <Field
            id="import-material"
            label="Key material (base64)"
            value={importMaterial}
            onChange={setImportMaterial}
          />
          <Button onClick={onImport} disabled={ops.busy || !importName || !importMaterial}>
            Import
          </Button>
        </OpCard>

        <OpCard
          id="status"
          title="Key Status"
          description="Enable or disable a key; asks for confirmation"
          result={statusResult}
        >
          <Field id="status-key" label="Key name" value={statusKey} onChange={setStatusKey} />
          <div className="flex flex-col gap-1">
            <Label htmlFor="status-value">New status</Label>
            <select
              id="status-value"
              className="h-9 rounded-md border bg-transparent px-3 text-sm"
              value={statusValue}
              onChange={(e) => setStatusValue(e.target.value as KmsKeyStatus)}
            >
              {KMS_KEY_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <Field id="status-version" label="Version" value={statusVersion} onChange={setStatusVersion} />
          <Button
            variant="destructive"
            onClick={() => setStatusConfirm(true)}
            disabled={ops.busy || !statusKey}
          >
            Update status
          </Button>
        </OpCard>

        <OpCard
          id="versions"
          title="Key Versions"
          description="List every version of a key with its status"
          result={
            versions === null
              ? null
              : versions.length === 0
                ? "No versions"
                : versions
                    .map((v) => `v${v.version} ${v.status} ${v.algorithm}`)
                    .join("\n")
          }
        >
          <Field id="versions-key" label="Key name" value={versionsKey} onChange={setVersionsKey} />
          <Button onClick={onVersions} disabled={ops.busy || !versionsKey}>
            List versions
          </Button>
        </OpCard>

        <OpCard id="hash" title="Hash" description="Compute a digest of the data" result={hashResult}>
          <Field id="hash-data" label="Data" value={hashData} onChange={setHashData} />
          <Field id="hash-algorithm" label="Hash algorithm" value={hashAlg} onChange={setHashAlg} />
          <Button onClick={onHash} disabled={ops.busy || !hashData}>
            Hash
          </Button>
        </OpCard>

        <OpCard id="hmac" title="HMAC" description="Compute an HMAC with a key" result={hmacResult}>
          <Field id="hmac-key" label="Key name" value={hmacKey} onChange={setHmacKey} />
          <Field id="hmac-data" label="Data" value={hmacData} onChange={setHmacData} />
          <Field id="hmac-hash" label="Hash algorithm" value={hmacHash} onChange={setHmacHash} />
          <Button onClick={onHmac} disabled={ops.busy || !hmacKey || !hmacData}>
            Compute HMAC
          </Button>
        </OpCard>

        <OpCard
          id="verify-hmac"
          title="Verify HMAC"
          description="Check an HMAC (base64) against the data"
          result={vResult}
        >
          <Field id="verify-hmac-key" label="Key name" value={vKey} onChange={setVKey} />
          <Field id="verify-hmac-data" label="Data" value={vData} onChange={setVData} />
          <Field id="verify-hmac-mac" label="HMAC (base64)" value={vMac} onChange={setVMac} />
          <Field id="verify-hmac-hash" label="Hash algorithm" value={vHash} onChange={setVHash} />
          <Button onClick={onVerifyHmac} disabled={ops.busy || !vKey || !vData || !vMac}>
            Verify HMAC
          </Button>
        </OpCard>

        <OpCard
          id="random"
          title="Random Bytes"
          description="Generate random bytes from the backend"
          result={randomResult}
        >
          <Field id="random-bytes" label="Number of bytes" value={randomBytes} onChange={setRandomBytes} />
          <Button onClick={onRandom} disabled={ops.busy}>
            Generate random
          </Button>
        </OpCard>

        <OpCard
          id="data-key"
          title="Data Key"
          description="Mint a data key, returned in plaintext and encrypted"
          result={dkResult}
        >
          <Field id="data-key-key" label="Key name" value={dkKey} onChange={setDkKey} />
          <Field id="data-key-algorithm" label="Algorithm" value={dkAlg} onChange={setDkAlg} />
          <Field id="data-key-size" label="Key size" value={dkSize} onChange={setDkSize} />
          <Button onClick={onDataKey} disabled={ops.busy || !dkKey}>
            Generate data key
          </Button>
        </OpCard>

        <OpCard
          id="wrapped-data-key"
          title="Wrapped Data Key"
          description="Mint a data key returned only wrapped"
          result={wdkResult}
        >
          <Field id="wrapped-data-key-key" label="Wrapping key name" value={wdkKey} onChange={setWdkKey} />
          <Field id="wrapped-data-key-algorithm" label="Algorithm" value={wdkAlg} onChange={setWdkAlg} />
          <Field id="wrapped-data-key-size" label="Key size" value={wdkSize} onChange={setWdkSize} />
          <Button onClick={onWrappedDataKey} disabled={ops.busy || !wdkKey}>
            Generate wrapped data key
          </Button>
        </OpCard>

        <OpCard
          id="backend"
          title="Backend Status"
          description="The KMS backend type and its health"
          result={backend === null ? null : `${backend.backend_type}: ${backend.status}`}
        >
          <Button onClick={onBackend} disabled={ops.busy}>
            Check backend
          </Button>
        </OpCard>
      </div>

      <Dialog open={statusConfirm} onOpenChange={setStatusConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Change key status</DialogTitle>
            <DialogDescription>
              Set {statusKey} to {statusValue}? A disabled key refuses every
              cryptographic operation until it is enabled again.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setStatusConfirm(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={onStatusConfirmed}>
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
