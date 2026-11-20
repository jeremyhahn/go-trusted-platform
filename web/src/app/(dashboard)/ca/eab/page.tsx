"use client";

import * as React from "react";
import Link from "next/link";
import { AlertCircle, RefreshCw, Trash2 } from "lucide-react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Input,
  Label,
} from "@/components/ui";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useEAB, useEABList } from "@/hooks";
import { useEABGate } from "@/hooks/use-eab-gate";
import type { EABOperation } from "@/hooks/use-eab-gate";
import { EABGate } from "./eab-gate";
import { parseExpiresIn } from "@/utils/eab-expiry";
import { normalizeEABStatus } from "@/utils/eab-status";
import type {
  CreateEABCredentialResponse,
  EABCredentialSummary,
  ValidateEABCredentialResponse,
} from "trusted-platform-sdk";

function errorText(err: unknown, fallback: string): string {
  if (err instanceof Error && err.message) return err.message;
  if (typeof err === "object" && err !== null && "message" in err) {
    const message = (err as { message?: unknown }).message;
    if (typeof message === "string" && message) return message;
  }
  return fallback;
}

function statusVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  switch (normalizeEABStatus(status)) {
    case "ACTIVE":
      return "default";
    case "REVOKED":
      return "destructive";
    case "USED":
      return "secondary";
    default:
      return "outline";
  }
}

export default function EABCredentialsPage() {
  const eab = useEAB();
  const list = useEABList();
  const credentials: EABCredentialSummary[] = list.data?.credentials ?? [];

  const [message, setMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  // Create form
  const [profileId, setProfileId] = React.useState("");
  const [tenantId, setTenantId] = React.useState("");
  const [expiresIn, setExpiresIn] = React.useState("");
  const [created, setCreated] = React.useState<CreateEABCredentialResponse | null>(null);

  // Validate form
  const [validateKeyId, setValidateKeyId] = React.useState("");
  const [validateHmac, setValidateHmac] = React.useState("");
  const [validation, setValidation] = React.useState<ValidateEABCredentialResponse | null>(null);

  // Lookup by key ID
  const [lookupKeyId, setLookupKeyId] = React.useState("");
  const [lookupResult, setLookupResult] = React.useState<EABCredentialSummary | null>(null);

  const gate = useEABGate();
  const { report } = gate;

  React.useEffect(() => {
    if (list.error) report("ListCredentials", list.error);
  }, [list.error, report]);

  const run = async (op: EABOperation, action: () => Promise<string>, fallback: string) => {
    setActionError(null);
    setMessage(null);
    try {
      setMessage(await action());
    } catch (err) {
      report(op, err);
      setActionError(errorText(err, fallback));
    }
  };

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    // Profile IDs are uint64 nanosecond timestamps, above Number.MAX_SAFE_INTEGER:
    // send the decimal string unchanged, as protojson expects.
    const profile = profileId.trim();
    if (!/^[1-9][0-9]{0,19}$/.test(profile)) {
      setMessage(null);
      setActionError("Profile ID must be a positive integer");
      return;
    }
    const exp = parseExpiresIn(expiresIn);
    if (!exp.ok) {
      setMessage(null);
      setActionError("Expires in must be a positive whole number of seconds, or blank");
      return;
    }
    void run("CreateCredential", async () => {
      const res = await eab.create.mutateAsync({
        profileId: profile,
        tenantId,
        ...(exp.seconds !== undefined ? { expiresInSeconds: exp.seconds } : {}),
      });
      setCreated(res);
      await list.refetch();
      return "Credential created";
    }, "Failed to create credential");
  };

  const handleRevoke = (id: string) => {
    void run("RevokeCredential", async () => {
      await eab.revoke.mutateAsync(id);
      await list.refetch();
      return `Credential ${id} revoked`;
    }, "Failed to revoke credential");
  };

  const handleDelete = (id: string) => {
    if (!confirm(`Delete EAB credential ${id}?`)) return;
    void run("DeleteCredential", async () => {
      await eab.deleteCredential.mutateAsync(id);
      await list.refetch();
      return `Credential ${id} deleted`;
    }, "Failed to delete credential");
  };

  const handleCleanup = () => {
    void run("CleanupExpiredCredentials", async () => {
      const res = await eab.cleanupExpired.mutateAsync(undefined);
      await list.refetch();
      return `Deleted ${res.deletedCount ?? 0} expired credentials`;
    }, "Failed to clean up expired credentials");
  };

  // Each validation request, and each edit of its inputs, takes a new
  // generation: only the current generation's response is published, so an
  // older or overlapping response never shows beside other inputs.
  const validateGen = React.useRef(0);

  const editValidate = (set: (v: string) => void, value: string) => {
    validateGen.current += 1;
    setValidation(null);
    set(value);
  };

  const handleValidate = (e: React.FormEvent) => {
    e.preventDefault();
    const gen = ++validateGen.current;
    const request = { keyId: validateKeyId, hmacKey: validateHmac };
    setValidation(null);
    setActionError(null);
    setMessage(null);
    void (async () => {
      try {
        const res = await eab.validate.mutateAsync(request);
        if (gen !== validateGen.current) return;
        setValidation(res);
        setMessage(res.valid ? "Credential is valid" : "Credential is not valid");
      } catch (err) {
        report("ValidateCredential", err);
        if (gen !== validateGen.current) return;
        setActionError(errorText(err, "Failed to validate credential"));
      }
    })();
  };

  const handleLookup = (e: React.FormEvent) => {
    e.preventDefault();
    setLookupResult(null);
    void run("GetCredentialByKeyID", async () => {
      const res = await eab.service.getByKeyId(lookupKeyId);
      if (!res.success || !res.data) {
        // Keep the error's status, which the capability gate reads.
        throw res.error ?? new Error("Credential not found");
      }
      setLookupResult(res.data.credential);
      return `Found credential ${res.data.credential.id}`;
    }, "Failed to look up credential");
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">EAB Credentials</h1>
          <p className="text-muted-foreground">
            External account binding credentials for ACME enrollment
          </p>
        </div>
        <div className="flex gap-2">
          <EABGate gate={gate} op="CleanupExpiredCredentials">
            <Button variant="outline" onClick={handleCleanup}>
            <Trash2 className="mr-2 h-4 w-4" />
            Clean Up Expired
          </Button>
          </EABGate>
          <EABGate gate={gate} op="ListCredentials">
            <Button variant="outline" onClick={() => void list.refetch()} disabled={list.isFetching}>
            <RefreshCw className={`mr-2 h-4 w-4 ${list.isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          </EABGate>
        </div>
      </div>

      {message && (
        <div role="status" data-testid="eab-message" className="p-4 rounded-lg border bg-muted">
          {message}
        </div>
      )}

      {(actionError || list.error) && (
        <div
          role="alert"
          className="flex items-center gap-2 p-4 bg-destructive/10 border border-destructive rounded-lg"
        >
          <AlertCircle className="h-4 w-4 text-destructive" />
          <p className="text-sm text-destructive">
            {actionError ?? errorText(list.error, "Failed to load credentials")}
          </p>
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Credentials</CardTitle>
          <CardDescription>Every EAB credential visible to you</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Key ID</TableHead>
                <TableHead>Tenant</TableHead>
                <TableHead>Profile</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {credentials.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground">
                    {list.isLoading ? "Loading..." : "No EAB credentials"}
                  </TableCell>
                </TableRow>
              )}
              {credentials.map((cred) => (
                <TableRow key={cred.id} data-testid={`eab-row-${cred.id}`}>
                  <TableCell>
                    <Link className="underline" href={`/ca/eab/${cred.id}`}>
                      {cred.id}
                    </Link>
                  </TableCell>
                  <TableCell className="font-mono text-sm">{cred.keyId}</TableCell>
                  <TableCell>{cred.tenantId}</TableCell>
                  <TableCell>{cred.profileId}</TableCell>
                  <TableCell>
                    <Badge variant={statusVariant(cred.status)}>{normalizeEABStatus(cred.status)}</Badge>
                  </TableCell>
                  <TableCell>{cred.expiresAt}</TableCell>
                  <TableCell className="flex gap-2">
                    <EABGate gate={gate} op="RevokeCredential">
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={normalizeEABStatus(cred.status) !== "ACTIVE"}
                      onClick={() => handleRevoke(cred.id)}
                    >
                      Revoke
                    </Button>
                    </EABGate>
                    <EABGate gate={gate} op="DeleteCredential">
                    <Button size="sm" variant="destructive" onClick={() => handleDelete(cred.id)}>
                      Delete
                    </Button>
                    </EABGate>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <div className="grid gap-6 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Create Credential</CardTitle>
          </CardHeader>
          <CardContent>
            <EABGate gate={gate} op="CreateCredential">
            <form className="space-y-3" onSubmit={handleCreate}>
              <div className="space-y-1">
                <Label htmlFor="eab-profile-id">Profile ID</Label>
                <Input
                  id="eab-profile-id"
                  type="text"
                  inputMode="numeric"
                  required
                  value={profileId}
                  onChange={(e) => setProfileId(e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="eab-tenant-id">Tenant ID</Label>
                <Input
                  id="eab-tenant-id"
                  required
                  value={tenantId}
                  onChange={(e) => setTenantId(e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="eab-expires-in">Expires in (seconds)</Label>
                <Input
                  id="eab-expires-in"
                  type="number"
                  step={1}
                  value={expiresIn}
                  onChange={(e) => setExpiresIn(e.target.value)}
                />
              </div>
              <Button type="submit">Create</Button>
            </form>
            </EABGate>
            {created?.credential && (
              <div className="mt-4 space-y-1 text-sm" data-testid="eab-created">
                <div>
                  Key ID: <span className="font-mono">{created.credential.keyId}</span>
                </div>
                <div>
                  HMAC key (shown once):{" "}
                  <span className="font-mono break-all">{created.credential.hmacKey}</span>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Validate Credential</CardTitle>
          </CardHeader>
          <CardContent>
            <EABGate gate={gate} op="ValidateCredential">
            <form className="space-y-3" onSubmit={handleValidate}>
              <div className="space-y-1">
                <Label htmlFor="eab-validate-key-id">Key ID</Label>
                <Input
                  id="eab-validate-key-id"
                  required
                  value={validateKeyId}
                  onChange={(e) => editValidate(setValidateKeyId, e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="eab-validate-hmac">HMAC Key</Label>
                <Input
                  id="eab-validate-hmac"
                  required
                  value={validateHmac}
                  onChange={(e) => editValidate(setValidateHmac, e.target.value)}
                />
              </div>
              <Button type="submit">Validate</Button>
            </form>
            </EABGate>
            {validation && (
              <div className="mt-4" data-testid="eab-validation">
                <Badge variant={validation.valid ? "default" : "destructive"}>
                  {validation.valid ? "Valid" : "Invalid"}
                </Badge>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Look Up by Key ID</CardTitle>
          </CardHeader>
          <CardContent>
            <EABGate gate={gate} op="GetCredentialByKeyID">
            <form className="space-y-3" onSubmit={handleLookup}>
              <div className="space-y-1">
                <Label htmlFor="eab-lookup-key-id">Key ID</Label>
                <Input
                  id="eab-lookup-key-id"
                  required
                  value={lookupKeyId}
                  onChange={(e) => setLookupKeyId(e.target.value)}
                />
              </div>
              <Button type="submit">Look Up</Button>
            </form>
            </EABGate>
            {lookupResult && (
              <div className="mt-4 space-y-1 text-sm" data-testid="eab-lookup-result">
                <div>
                  <Link className="underline" href={`/ca/eab/${lookupResult.id}`}>
                    Credential {lookupResult.id}
                  </Link>
                </div>
                <div>Tenant: {lookupResult.tenantId}</div>
                <div>Status: {normalizeEABStatus(lookupResult.status)}</div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
