"use client";

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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  RefreshCw,
  Key,
  Shield,
  Lock,
  Fingerprint,
  AlertCircle,
  Eye,
  Copy,
  MoreHorizontal,
  Loader2,
} from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useApi, useTPM, useToast } from "@/hooks";
import type { KeyAlgorithm } from "trusted-platform-sdk";

/**
 * TPM Key types
 */
type TPMKeyType = "EK" | "SRK" | "AK";
type TPMKeyStatus = "active" | "disabled" | "pending";

interface TPMKey {
  id: string;
  name: string;
  type: TPMKeyType;
  algorithm: KeyAlgorithm;
  status: TPMKeyStatus;
  handle: number;
  publicKey: string;
  createdAt: string;
  parentHandle?: string;
}

/**
 * TPM Keys Management Page
 *
 * Features:
 * - View all TPM keys (EK, SRK, AK)
 * - Display key details and attributes
 * - Public key hash viewing
 */
export default function TPMKeysPage() {
  const { toast } = useToast();
  const tpm = useTPM();

  const {
    data: ekData,
    isLoading: ekLoading,
    error: ekError,
    refetch: refetchEK,
  } = useApi(
    () => tpm.getEK().catch(() => ({ success: false, data: null })),
    [],
    { onError: () => {} }
  );

  const {
    data: srkData,
    isLoading: srkLoading,
    error: srkError,
    refetch: refetchSRK,
  } = useApi(
    () => tpm.getSRK().catch(() => ({ success: false, data: null })),
    [],
    { onError: () => {} }
  );

  const {
    data: akData,
    isLoading: akLoading,
    error: akError,
    refetch: refetchAK,
  } = useApi(
    () => tpm.getAK().catch(() => ({ success: false, data: null })),
    [],
    { onError: () => {} }
  );

  const loading = ekLoading || srkLoading || akLoading;
  const error = ekError || srkError || akError;

  const keys: TPMKey[] = React.useMemo(() => {
    const result: TPMKey[] = [];

    if (ekData?.publicKey) {
      result.push({
        id: "ek",
        name: "Endorsement Key",
        type: "EK",
        algorithm: ekData.algorithm,
        status: "active",
        handle: ekData.handle,
        publicKey: ekData.publicKey,
        createdAt: new Date().toISOString(),
      });
    }

    if (srkData?.publicKey) {
      result.push({
        id: "srk",
        name: "Storage Root Key",
        type: "SRK",
        algorithm: srkData.algorithm,
        status: "active",
        handle: srkData.handle,
        publicKey: srkData.publicKey,
        createdAt: new Date().toISOString(),
      });
    }

    if (akData?.publicKey) {
      result.push({
        id: "ak",
        name: "Attestation Key",
        type: "AK",
        algorithm: akData.algorithm,
        status: "active",
        handle: akData.handle,
        publicKey: akData.publicKey,
        createdAt: new Date().toISOString(),
      });
    }

    return result;
  }, [ekData, srkData, akData]);

  const handleRefresh = () => {
    refetchEK();
    refetchSRK();
    refetchAK();
  };

  const getKeyTypeIcon = (type: TPMKeyType) => {
    switch (type) {
      case "EK":
        return <Fingerprint className="h-4 w-4" />;
      case "SRK":
        return <Lock className="h-4 w-4" />;
      case "AK":
        return <Shield className="h-4 w-4" />;
    }
  };

  const getKeyTypeBadgeVariant = (type: TPMKeyType): "default" | "secondary" | "outline" => {
    return "default";
  };

  const getStatusBadgeVariant = (status: TPMKeyStatus): "default" | "secondary" | "destructive" => {
    switch (status) {
      case "active":
        return "default";
      case "disabled":
        return "destructive";
      case "pending":
        return "secondary";
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied to clipboard",
      description: "Public key has been copied to clipboard",
      variant: "success",
    });
  };

  const keyStats = React.useMemo(() => {
    return {
      total: keys.length,
      ek: keys.filter((k) => k.type === "EK").length,
      srk: keys.filter((k) => k.type === "SRK").length,
      ak: keys.filter((k) => k.type === "AK").length,
    };
  }, [keys]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">TPM Keys</h1>
          <p className="text-muted-foreground">
            Manage TPM cryptographic keys (EK, SRK, AK)
          </p>
        </div>
        <Button variant="outline" onClick={handleRefresh} disabled={loading}>
          <RefreshCw
            className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`}
          />
          Refresh
        </Button>
      </div>

      {/* Error Message */}
      {error && (
        <div className="flex items-center gap-2 p-4 bg-destructive/10 border border-destructive rounded-lg">
          <AlertCircle className="h-4 w-4 text-destructive" />
          <div>
            <p className="font-medium text-destructive">Error</p>
            <p className="text-sm text-destructive">{error.message}</p>
          </div>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Keys</CardTitle>
            <Key className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{keyStats.total}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Endorsement Key</CardTitle>
            <Fingerprint className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{keyStats.ek}</div>
            <p className="text-xs text-muted-foreground">Device identity</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Storage Root Key</CardTitle>
            <Lock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{keyStats.srk}</div>
            <p className="text-xs text-muted-foreground">Key hierarchy root</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Attestation Key</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{keyStats.ak}</div>
            <p className="text-xs text-muted-foreground">TPM quotes</p>
          </CardContent>
        </Card>

      </div>

      {/* Keys Table */}
      <Card>
        <CardHeader>
          <CardTitle>Key Inventory</CardTitle>
          <CardDescription>
            All TPM-resident cryptographic keys
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              <span className="ml-2 text-muted-foreground">Loading keys...</span>
            </div>
          ) : keys.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No TPM keys found. Keys may need to be provisioned.
            </div>
          ) : (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Algorithm</TableHead>
                    <TableHead>Handle</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="w-12"></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {keys.map((key) => (
                    <TableRow key={key.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {getKeyTypeIcon(key.type)}
                          <div>
                            <div className="font-medium">{key.name}</div>
                            <code className="text-xs text-muted-foreground">
                              {key.publicKey.slice(0, 16)}...
                            </code>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={getKeyTypeBadgeVariant(key.type)}>
                          {key.type}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="text-sm">{key.algorithm}</span>
                      </TableCell>
                      <TableCell>
                        <code className="text-sm bg-muted px-2 py-1 rounded">
                          0x{key.handle.toString(16).toUpperCase().padStart(8, '0')}
                        </code>
                      </TableCell>
                      <TableCell>
                        <Badge variant={getStatusBadgeVariant(key.status)}>
                          {key.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="text-sm text-muted-foreground">
                          {new Date(key.createdAt).toLocaleDateString()}
                        </span>
                      </TableCell>
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem>
                              <Eye className="mr-2 h-4 w-4" />
                              View Details
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={() => copyToClipboard(key.publicKey)}
                            >
                              <Copy className="mr-2 h-4 w-4" />
                              Copy Public Key
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Key Hierarchy */}
      <Card>
        <CardHeader>
          <CardTitle>Key Hierarchy</CardTitle>
          <CardDescription>
            TPM key relationships and parent-child structure
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="text-sm text-muted-foreground">
              <p>
                The TPM maintains a key hierarchy where the Storage Root Key (SRK)
                serves as the parent for most user-created keys. The Endorsement Key
                (EK) is unique to each TPM and used for device identity, while
                Attestation Keys (AK) are used for signing TPM quotes.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              {keys.map((key) => (
                <div
                  key={key.id}
                  className="flex items-center gap-1 text-xs bg-muted px-2 py-1 rounded"
                >
                  {getKeyTypeIcon(key.type)}
                  <span>{key.name}</span>
                  {key.parentHandle && key.parentHandle !== "0x40000001" && (
                    <span className="text-muted-foreground">
                      (parent: {key.parentHandle})
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
