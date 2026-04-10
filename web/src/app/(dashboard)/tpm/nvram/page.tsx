"use client";

import * as React from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  RefreshCw,
  HardDrive,
  AlertCircle,
  Database,
  Loader2,
} from "lucide-react";
import { useApi, useTPM, useToast } from "@/hooks";


/**
 * TPM NVRAM Management Page
 *
 * Features:
 * - View NVRAM capacity and usage
 * - TPM NVRAM information
 */
export default function TPMNVRAMPage() {
  const { toast } = useToast();
  const tpm = useTPM();

  const {
    data: tpmInfo,
    isLoading: loading,
    error,
    refetch,
  } = useApi(
    () => tpm.getInfo(),
    [],
    {
      onError: (err) => {
        toast({
          title: "Error loading TPM info",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">NVRAM Management</h1>
          <p className="text-muted-foreground">
            View TPM Non-Volatile RAM information
          </p>
        </div>
        <Button variant="outline" onClick={() => refetch()} disabled={loading}>
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

      {/* Loading State */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          <span className="ml-2 text-muted-foreground">Loading NVRAM info...</span>
        </div>
      )}

      {/* Capacity Cards */}
      {!loading && tpmInfo && (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-2">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Max NVRAM Size</CardTitle>
              <HardDrive className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{formatBytes(tpmInfo.maxNvramSize)}</div>
              <p className="text-xs text-muted-foreground">
                Total available NVRAM storage
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">TPM Version</CardTitle>
              <Database className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{tpmInfo.version}</div>
              <p className="text-xs text-muted-foreground">
                Platform module version
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* NVRAM Info Card */}
      {!loading && tpmInfo && (
        <Card>
          <CardHeader>
            <CardTitle>NVRAM Information</CardTitle>
            <CardDescription>
              TPM Non-Volatile RAM specifications
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-center py-8 text-muted-foreground">
              <p>Maximum NVRAM size: {formatBytes(tpmInfo.maxNvramSize)}</p>
              <p className="text-sm mt-2">
                Individual NVRAM index management requires direct TPM access.
                Use the TPM CLI tools or platform APIs for detailed NVRAM operations.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* NVRAM Documentation */}
      <Card>
        <CardHeader>
          <CardTitle>NVRAM Reference</CardTitle>
          <CardDescription>
            Understanding TPM Non-Volatile Storage
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4 text-sm text-muted-foreground">
            <p>
              TPM NVRAM provides persistent storage that survives power cycles.
              Each index has specific attributes controlling access and behavior.
            </p>
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <h4 className="font-medium text-foreground mb-2">Index Types</h4>
                <ul className="list-disc list-inside space-y-1">
                  <li><strong>Ordinary:</strong> General-purpose storage</li>
                  <li><strong>Counter:</strong> Monotonic counter (can only increment)</li>
                  <li><strong>Bits:</strong> Bit field (bits can only be set)</li>
                  <li><strong>Extend:</strong> PCR-like extend operations</li>
                  <li><strong>PIN Pass/Fail:</strong> PIN attempt counters</li>
                </ul>
              </div>
              <div>
                <h4 className="font-medium text-foreground mb-2">Access Control</h4>
                <ul className="list-disc list-inside space-y-1">
                  <li><strong>O:R/W:</strong> Owner hierarchy read/write</li>
                  <li><strong>P:R/W:</strong> Platform hierarchy read/write</li>
                  <li><strong>Policy:</strong> Policy-based authorization</li>
                  <li><strong>Write Lock:</strong> Prevents further writes</li>
                </ul>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
