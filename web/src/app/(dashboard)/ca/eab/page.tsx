"use client";

import * as React from "react";
import { PageHeader } from "@/components/layout/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useEAB, useEABList, usePlatformClient, useToast } from "@/hooks";
import { Gated } from "@/components/features/capabilities/gated";
import {
  EABCredentialDetail,
  unwrapEAB,
} from "@/components/features/ca/eab-credential-detail";

// The server's op strings (METHOD + the mux path template, router.go).
export const EAB_OPS = {
  get: "GET /api/v1/eab/credentials/{id:[0-9]+}",
  revoke: "POST /api/v1/eab/credentials/{id:[0-9]+}/revoke",
  delete: "DELETE /api/v1/eab/credentials/{id:[0-9]+}",
  byKey: "GET /api/v1/eab/credentials/key/{key}",
  validate: "POST /api/v1/eab/credentials/validate",
} as const;

// The REST wire shape: protojson sends the uint64 id and profile id as strings
// and the status as the enum name, unlike the SDK's EABCredential type.
interface EABCredentialWire {
  id: string;
  keyId: string;
  profileId?: string;
  tenantId?: string;
  status?: string;
  expiresAt?: string;
  createdAt?: string;
  usedAt?: string;
}

const STATUS_PREFIX = "EAB_CREDENTIAL_STATUS_";

function statusName(status?: string): string {
  const s = String(status || "").toUpperCase();
  return s.startsWith(STATUS_PREFIX) ? s.slice(STATUS_PREFIX.length) : s;
}

function statusLabel(status?: string): string {
  const name = statusName(status);
  if (!name) return "Unknown";
  return name.charAt(0) + name.slice(1).toLowerCase();
}

function formatDate(value?: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

// The tools card: GetCredentialByKeyID, ValidateCredential and
// CleanupExpiredCredentials through the SDK client (#2050).
function EABTools() {
  const client = usePlatformClient();
  const [keyId, setKeyId] = React.useState("");
  const [hmacKey, setHmacKey] = React.useState("");
  const [result, setResult] = React.useState<{ text: string; failed?: boolean } | null>(null);
  const [busy, setBusy] = React.useState(false);

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    setResult(null);
    try {
      await action();
    } catch (err) {
      setResult({ text: err instanceof Error ? err.message : String(err), failed: true });
    } finally {
      setBusy(false);
    }
  };

  const findByKey = () =>
    run(async () => {
      const res = unwrapEAB(await client.eab.getByKeyId(keyId.trim()), "find the credential");
      const c = res.credential as unknown as EABCredentialWire;
      setResult({ text: `Found ${c.keyId} (id ${c.id}): ${statusLabel(c.status)}` });
    });

  const validate = () =>
    run(async () => {
      const res = unwrapEAB(
        await client.eab.validate({ keyId: keyId.trim(), hmacKey: hmacKey.trim() }),
        "validate the credential",
      );
      setResult(res.valid ? { text: "Valid" } : { text: `Invalid: ${res.errorMessage || "not valid"}`, failed: true });
    });

  const hasKey = keyId.trim() !== "";
  return (
    <Card>
      <CardContent className="space-y-4 pt-6">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="eab-tool-key-id">Key ID</Label>
            <Input id="eab-tool-key-id" value={keyId} onChange={(e) => setKeyId(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="eab-tool-hmac">HMAC key</Label>
            <Input id="eab-tool-hmac" value={hmacKey} onChange={(e) => setHmacKey(e.target.value)} />
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Gated op={EAB_OPS.byKey}>
            <Button size="sm" variant="outline" disabled={busy || !hasKey} onClick={() => void findByKey()}>
              Find by key ID
            </Button>
          </Gated>
          <Gated op={EAB_OPS.validate}>
            <Button
              size="sm"
              variant="outline"
              disabled={busy || !hasKey || hmacKey.trim() === ""}
              onClick={() => void validate()}
            >
              Validate
            </Button>
          </Gated>
        </div>
        {result && (
          <p
            data-testid="eab-tool-result"
            className={result.failed ? "text-sm text-destructive" : "text-sm"}
          >
            {result.text}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

export default function EABCredentialsPage() {
  const { toast } = useToast();
  const { revoke, deleteCredential } = useEAB();
  const { data, isLoading, error, refetch } = useEABList();
  const [processingId, setProcessingId] = React.useState<string | null>(null);
  const [detailId, setDetailId] = React.useState<string | null>(null);

  const credentials = React.useMemo(
    () => (data?.credentials || []) as unknown as EABCredentialWire[],
    [data],
  );

  const runAction = async (
    row: EABCredentialWire,
    question: string,
    action: (id: string) => Promise<unknown>,
    done: string,
    failed: string,
  ) => {
    if (!confirm(question)) return;
    setProcessingId(row.id);
    try {
      // The id is a uint64 above 2^53: Number() would change its digits.
      await action(row.id);
      toast({ title: done, description: row.keyId, variant: "success" });
    } catch (err) {
      toast({
        title: failed,
        description: err instanceof Error ? err.message : failed,
        variant: "destructive",
      });
    } finally {
      setProcessingId(null);
      void refetch();
    }
  };

  const handleRevoke = (row: EABCredentialWire) =>
    runAction(
      row,
      `Revoke EAB credential ${row.keyId}?`,
      (id) => revoke.mutateAsync(id),
      "Credential revoked",
      "Failed to revoke credential",
    );

  const handleDelete = (row: EABCredentialWire) =>
    runAction(
      row,
      `Delete EAB credential ${row.keyId}?`,
      (id) => deleteCredential.mutateAsync(id),
      "Credential deleted",
      "Failed to delete credential",
    );

  return (
    <div className="space-y-6">
      <PageHeader
        title="EAB Credentials"
        description="ACME External Account Binding credentials"
      />
      <EABTools />
      <Card>
        <CardContent className="pt-6">
          {isLoading ? (
            <div className="space-y-4">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          ) : error ? (
            <p className="text-sm text-destructive">
              Error loading EAB credentials: {error.message}
            </p>
          ) : credentials.length === 0 ? (
            <p className="text-sm text-muted-foreground">No EAB credentials</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Key ID</TableHead>
                  <TableHead>Profile</TableHead>
                  <TableHead>Tenant</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {credentials.map((row) => {
                  const busy = processingId === row.id;
                  const active = statusName(row.status) === "ACTIVE";
                  return (
                    <TableRow key={row.id}>
                      <TableCell className="font-mono text-sm">{row.keyId}</TableCell>
                      <TableCell>{row.profileId || "-"}</TableCell>
                      <TableCell>{row.tenantId || "-"}</TableCell>
                      <TableCell>
                        <Badge variant={active ? "default" : "secondary"}>
                          {statusLabel(row.status)}
                        </Badge>
                      </TableCell>
                      <TableCell>{formatDate(row.expiresAt)}</TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Gated op={EAB_OPS.get}>
                            <Button
                              size="sm"
                              variant="outline"
                              aria-label={`Details ${row.keyId}`}
                              onClick={() => setDetailId(detailId === row.id ? null : row.id)}
                            >
                              Details
                            </Button>
                          </Gated>
                          {active && (
                            <Gated op={EAB_OPS.revoke}>
                              <Button
                                size="sm"
                                variant="outline"
                                disabled={busy}
                                onClick={() => void handleRevoke(row)}
                              >
                                Revoke
                              </Button>
                            </Gated>
                          )}
                          <Gated op={EAB_OPS.delete}>
                            <Button
                              size="sm"
                              variant="destructive"
                              disabled={busy}
                              onClick={() => void handleDelete(row)}
                            >
                              Delete
                            </Button>
                          </Gated>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
      {detailId && (
        <Card>
          <CardContent className="pt-6">
            <EABCredentialDetail id={detailId} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
