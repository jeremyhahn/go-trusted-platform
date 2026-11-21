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
import { useEAB, useEABList, useToast } from "@/hooks";

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

export default function EABCredentialsPage() {
  const { toast } = useToast();
  const { revoke, deleteCredential } = useEAB();
  const { data, isLoading, error, refetch } = useEABList();
  const [processingId, setProcessingId] = React.useState<string | null>(null);

  const credentials = React.useMemo(
    () => (data?.credentials || []) as unknown as EABCredentialWire[],
    [data],
  );

  const runAction = async (
    row: EABCredentialWire,
    question: string,
    action: (id: number) => Promise<unknown>,
    done: string,
    failed: string,
  ) => {
    if (!confirm(question)) return;
    setProcessingId(row.id);
    try {
      await action(Number(row.id));
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
                          {active && (
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={busy}
                              onClick={() => void handleRevoke(row)}
                            >
                              Revoke
                            </Button>
                          )}
                          <Button
                            size="sm"
                            variant="destructive"
                            disabled={busy}
                            onClick={() => void handleDelete(row)}
                          >
                            Delete
                          </Button>
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
    </div>
  );
}
