"use client";

import * as React from "react";
import { use } from "react";
import { usePathname, useRouter } from "next/navigation";
import { resolveDynamicId } from "@/utils/dynamic-route";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { KeyOperations } from "@/components/features/kms/key-operations";
import { useKMS, useApi, useMutation, useToast } from "@/hooks";
import type { KeyDetail } from "@/types/security";
import { ArrowLeft, Loader2, AlertCircle, RefreshCw, Ban, Trash2 } from "lucide-react";

/**
 * Key Detail Page
 *
 * Features:
 * - View complete key details
 * - Display key versions
 * - View usage history
 * - Test key operations (encrypt/decrypt, sign/verify)
 * - Rotate, disable, or schedule deletion
 */
export default function KeyDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const resolved = use(params);
  const pathname = usePathname();
  const id = resolveDynamicId(resolved as any, pathname, "kms");
  const router = useRouter();
  const kms = useKMS();
  const { toast } = useToast();

  const { data: response, isLoading: loading, error, refetch } = useApi(
    () => kms.getKey(id),
    [id]
  );

  // Transform server response to UI KeyDetail. The platform KMS REST
  // handler returns the key record directly (snake_case) so the older
  // {key, metadata} envelope expected here was always missing. Read
  // both shapes and tolerate ISO-string timestamps.
  const keyDetail = React.useMemo(() => {
    if (!response) return null;

    const r: any = response;
    const key: any = r.key ?? r;
    const metadata: any = r.metadata ?? key ?? {};
    const keyId: string = key.keyId ?? key.key_id ?? '';
    const algorithm: string = key.algorithm ?? '';
    const toIso = (v: any): string => {
      if (!v) return new Date().toISOString();
      if (typeof v === 'number') return new Date(v * 1000).toISOString();
      const s = String(v);
      if (s.startsWith('0001-')) return new Date().toISOString();
      return s;
    };
    const createdRaw = metadata.createdAt ?? metadata.created_at ?? key.createdAt ?? key.created_at;
    const status: string = String(key.status ?? metadata.status ?? '').toUpperCase();
    return {
      id: keyId,
      name: metadata.name || key.name || keyId,
      algorithm: algorithm as any,
      type: algorithm.includes('AES') || algorithm.includes('HMAC') ? 'symmetric' as const : 'asymmetric' as const,
      status: (status === 'ENABLED' ? 'active' : status === 'DISABLED' ? 'disabled' : 'active') as 'active' | 'disabled' | 'pending_deletion',
      createdAt: toIso(createdRaw),
      rotationCount: 0,
      versions: [
        {
          version: metadata.version ?? key.version ?? 1,
          createdAt: toIso(createdRaw),
          status: status === 'ENABLED' ? 'active' as const : 'inactive' as const,
        }
      ],
      usageHistory: [],
      metadata: metadata.tags || {},
    };
  }, [response]);

  const deleteMutation = useMutation(
    (keyId: string) => kms.deleteKey({ keyId }),
    {
      onSuccess: () => {
        toast({
          title: "Success",
          description: "Key disabled successfully",
        });
        refetch();
      },
      onError: (error) => {
        toast({
          title: "Error",
          description: error.message,
          variant: "destructive",
        });
      },
    }
  );

  const handleRotate = async () => {
    if (!keyDetail || !confirm(`Rotate key "${keyDetail.name}"? This will create a new version.`)) {
      return;
    }

    toast({
      title: "Info",
      description: "Key rotation is not currently supported via the SDK. Please use the API directly.",
    });
  };

  const handleDisable = async () => {
    if (!keyDetail || !confirm(`Disable key "${keyDetail.name}"? This will prevent its use.`)) {
      return;
    }

    deleteMutation.mutate(id);
  };

  const handleEncrypt = async (plaintext: string): Promise<string> => {
    try {
      const result = await kms.encrypt({ keyId: id, plaintext });
      return result.data?.ciphertext || "";
    } catch (err) {
      const error = err as Error;
      throw new Error(error.message);
    }
  };

  const handleDecrypt = async (ciphertext: string): Promise<string> => {
    try {
      const result = await kms.decrypt({ keyId: id, ciphertext });
      return result.data?.plaintext || "";
    } catch (err) {
      const error = err as Error;
      throw new Error(error.message);
    }
  };

  const handleSign = async (data: string): Promise<string> => {
    try {
      const result = await kms.sign({ keyId: id, message: data });
      return result.data?.signature || "";
    } catch (err) {
      const error = err as Error;
      throw new Error(error.message);
    }
  };

  const handleVerify = async (data: string, signature: string): Promise<boolean> => {
    try {
      const result = await kms.verify({ keyId: id, message: data, signature });
      return result.data?.valid || false;
    } catch (err) {
      const error = err as Error;
      throw new Error(error.message);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] gap-4">
        <AlertCircle className="h-12 w-12 text-destructive" />
        <div className="text-center">
          <p className="font-medium text-destructive">Error loading key</p>
          <p className="text-sm text-muted-foreground">{error.message}</p>
        </div>
        <Button variant="outline" onClick={() => router.push("/kms")}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Keys
        </Button>
      </div>
    );
  }

  if (!keyDetail) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] gap-4">
        <p className="text-muted-foreground">Key not found</p>
        <Button variant="outline" onClick={() => router.push("/kms")}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Keys
        </Button>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => router.push("/kms")}>
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold tracking-tight">{keyDetail.name}</h1>
            <p className="text-muted-foreground">View and test key operations</p>
          </div>
        </div>
        <div className="flex gap-2">
          {keyDetail.status === "active" && (
            <>
              <Button variant="outline" size="sm" onClick={handleRotate}>
                <RefreshCw className="mr-2 h-4 w-4" />
                Rotate
              </Button>
              <Button variant="outline" size="sm" onClick={handleDisable}>
                <Ban className="mr-2 h-4 w-4" />
                Disable
              </Button>
            </>
          )}
        </div>
      </div>

      {/* Key Information */}
      <Card>
        <CardHeader>
          <CardTitle>Key Information</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="text-sm font-medium text-muted-foreground">ID</div>
              <code className="mt-1 text-xs bg-muted px-2 py-1 rounded">{keyDetail.id}</code>
            </div>
            <div>
              <div className="text-sm font-medium text-muted-foreground">Algorithm</div>
              <Badge variant="outline" className="mt-1 font-mono">
                {keyDetail.algorithm}
              </Badge>
            </div>
            <div>
              <div className="text-sm font-medium text-muted-foreground">Type</div>
              <Badge variant="secondary" className="mt-1 capitalize">
                {keyDetail.type}
              </Badge>
            </div>
            <div>
              <div className="text-sm font-medium text-muted-foreground">Status</div>
              <Badge
                variant={
                  keyDetail.status === "active"
                    ? "default"
                    : keyDetail.status === "disabled"
                    ? "secondary"
                    : "destructive"
                }
                className="mt-1"
              >
                {keyDetail.status === "pending_deletion" ? "Pending Deletion" : keyDetail.status}
              </Badge>
            </div>
            <div>
              <div className="text-sm font-medium text-muted-foreground">Created At</div>
              <div className="mt-1 text-sm">
                {new Date(keyDetail.createdAt).toLocaleString()}
              </div>
            </div>
            <div>
              <div className="text-sm font-medium text-muted-foreground">Rotation Count</div>
              <div className="mt-1 text-sm">{keyDetail.rotationCount}</div>
            </div>
          </div>

          {/* Metadata */}
          {keyDetail.metadata && Object.keys(keyDetail.metadata).length > 0 && (
            <>
              <Separator />
              <div>
                <div className="text-sm font-medium text-muted-foreground mb-2">Metadata</div>
                <div className="space-y-1">
                  {Object.entries(keyDetail.metadata).map(([key, value]) => (
                    <div key={key} className="flex items-center justify-between p-2 bg-muted rounded text-sm">
                      <span className="font-medium">{key}:</span>
                      <span>{String(value)}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Key Versions */}
      {keyDetail.versions.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Key Versions</CardTitle>
            <CardDescription>History of key rotations</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Version</TableHead>
                    <TableHead>Created At</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {keyDetail.versions.map((version: any) => (
                    <TableRow key={version.version}>
                      <TableCell className="font-medium">{version.version}</TableCell>
                      <TableCell className="text-sm">
                        {new Date(version.createdAt).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={version.status === "active" ? "default" : "secondary"}
                        >
                          {version.status}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Usage History */}
      {keyDetail.usageHistory.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Recent Usage</CardTitle>
            <CardDescription>Key operation history</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>Operation</TableHead>
                    <TableHead>User</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {keyDetail.usageHistory.slice(0, 10).map((entry: any, idx: number) => (
                    <TableRow key={idx}>
                      <TableCell className="text-sm">
                        {new Date(entry.timestamp).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="capitalize">
                          {entry.operation}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm">{entry.user}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Key Operations Test Panel */}
      <KeyOperations
        keyItem={keyDetail}
        onEncrypt={handleEncrypt}
        onDecrypt={handleDecrypt}
        onSign={handleSign}
        onVerify={handleVerify}
      />
    </div>
  );
}
