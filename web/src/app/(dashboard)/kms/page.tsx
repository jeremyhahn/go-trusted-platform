"use client";

/**
 * Key Management Service - Keys List Page
 *
 * Features:
 * - View all cryptographic keys
 * - Generate new keys
 * - Rotate keys
 * - Export keys (if exportable)
 * - Delete keys
 * - Filter by algorithm, type, and status
 *
 * Uses the trusted-platform-sdk for API interactions.
 */

import * as React from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { KeyTable } from "@/components/features/kms/key-table";
import { KeyForm } from "@/components/features/kms/key-form";
import { useKMS, useApi, useMutation, useToast } from "@/hooks";
import type { Key, GenerateKeyInput } from "@/types/security";
import { Plus, AlertCircle, RefreshCw } from "lucide-react";

export default function KMSKeysPage() {
  const router = useRouter();
  const { toast } = useToast();
  const kms = useKMS();
  const [isGenerateDialogOpen, setIsGenerateDialogOpen] = React.useState(false);

  // Fetch keys using SDK
  const {
    data: keysData,
    isLoading: loading,
    error,
    refetch: loadKeys,
  } = useApi(
    () => kms.listKeys(),
    [],
    {
      onError: (err) => {
        toast({
          title: "Error loading keys",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Map SDK algorithm to web app algorithm format
  const mapAlgorithm = (sdkAlgo: string): Key['algorithm'] => {
    const mapping: Record<string, Key['algorithm']> = {
      'AES_256': 'AES-256',
      'RSA_2048': 'RSA-2048',
      'RSA_4096': 'RSA-4096',
      'ECDSA_P256': 'ECDSA-P256',
      'ECDSA_P384': 'ECDSA-P384',
    };
    return mapping[sdkAlgo] || 'AES-256';
  };

  // Map web app algorithm to SDK algorithm format
  const mapToSDKAlgorithm = (webAlgo: GenerateKeyInput['algorithm']): string => {
    const mapping: Record<string, string> = {
      'AES-256': 'AES_256',
      'RSA-2048': 'RSA_2048',
      'RSA-4096': 'RSA_4096',
      'ECDSA-P256': 'ECDSA_P256',
      'ECDSA-P384': 'ECDSA_P384',
    };
    return mapping[webAlgo] || 'AES_256';
  };

  // Helper to determine key type from algorithm
  const getKeyType = (algorithm: string): "symmetric" | "asymmetric" => {
    const symmetricAlgorithms = ["AES_128", "AES_192", "AES_256", "CHACHA20_POLY1305", "HMAC_SHA256", "HMAC_SHA384", "HMAC_SHA512"];
    return symmetricAlgorithms.includes(algorithm) ? "symmetric" : "asymmetric";
  };

  // Transform server key list to local Key type. The platform KMS REST
  // handler emits snake_case (`key_id`, `created_at`) and ISO-string
  // timestamps; the SDK type uses camelCase. Tolerate both.
  const keys: Key[] = React.useMemo(() => {
    const list = (keysData?.keys ?? []) as any[];
    const toIso = (v: any): string => {
      if (!v) return new Date().toISOString();
      if (typeof v === "number") return new Date(v * 1000).toISOString();
      const s = String(v);
      // Treat the Go zero time as "unset".
      if (s.startsWith("0001-")) return new Date().toISOString();
      return s;
    };
    return list.map((key: any) => {
      const id = key.keyId ?? key.key_id ?? "";
      return {
        id,
        name: key.name || id,
        algorithm: mapAlgorithm(key.algorithm),
        type: getKeyType(key.algorithm),
        status: (key.status ?? "").toString().toLowerCase() === "enabled" ? "active" : "disabled",
        createdAt: toIso(key.createdAt ?? key.created_at),
        rotationCount: ((key.version ?? 1) - 1),
      };
    });
  }, [keysData]);

  // Generate key mutation
  const generateMutation = useMutation(
    async (data: GenerateKeyInput) => {
      const sdkAlgorithm = mapToSDKAlgorithm(data.algorithm);
      return kms.generateKey({
        keySpec: {
          algorithm: sdkAlgorithm as Parameters<typeof kms.generateKey>[0]['keySpec']['algorithm'],
          usage: ["ENCRYPT", "DECRYPT"],
        },
        name: data.name,
      });
    },
    {
      onSuccess: () => {
        toast({
          title: "Key generated",
          description: "Key generated successfully",
          variant: "success",
        });
        setIsGenerateDialogOpen(false);
        loadKeys();
      },
      onError: (err) => {
        toast({
          title: "Error generating key",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Rotate key mutation
  const rotateMutation = useMutation(
    async (keyId: string) => {
      return kms.rotateKey({ keyId, retainOldVersion: true });
    },
    {
      onSuccess: () => {
        toast({
          title: "Key rotated",
          description: "Key rotated successfully",
          variant: "success",
        });
        loadKeys();
      },
      onError: (err) => {
        toast({
          title: "Error rotating key",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Delete key mutation
  const deleteMutation = useMutation(
    async (keyId: string) => {
      return kms.deleteKey({ keyId });
    },
    {
      onSuccess: () => {
        toast({
          title: "Key deleted",
          description: "Key deleted successfully",
          variant: "success",
        });
        loadKeys();
      },
      onError: (err) => {
        toast({
          title: "Error deleting key",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Export key mutation
  const exportMutation = useMutation(
    async (keyId: string) => {
      return kms.exportKey({ keyId });
    },
    {
      onSuccess: (result) => {
        if (result?.wrappedMaterial) {
          // Create a downloadable file with the key material
          const keyData = JSON.stringify({
            keyId: result.keyId,
            format: result.format,
            wrappedMaterial: result.wrappedMaterial,
            version: result.version,
          }, null, 2);
          const blob = new Blob([keyData], { type: "application/json" });
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `key_export.json`;
          document.body.appendChild(a);
          a.click();
          window.URL.revokeObjectURL(url);
          document.body.removeChild(a);
        }
      },
      onError: (err) => {
        toast({
          title: "Error exporting key",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  const handleView = (key: Key) => {
    router.push(`/kms/${encodeURIComponent(key.id)}`);
  };

  const handleRotate = async (key: Key) => {
    if (!confirm(`Rotate key "${key.name}"? This will create a new version.`)) {
      return;
    }
    rotateMutation.mutate(key.id);
  };

  const handleExport = async (key: Key) => {
    if (!confirm(`Export key "${key.name}"? This will expose the key material.`)) {
      return;
    }
    exportMutation.mutate(key.id);
  };

  const handleDelete = async (key: Key) => {
    const warning = `Delete key "${key.name}"? This action cannot be undone.`;
    if (!confirm(warning)) {
      return;
    }
    deleteMutation.mutate(key.id);
  };

  const handleGenerateKey = async (data: GenerateKeyInput) => {
    await generateMutation.mutateAsync(data);
  };

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Cryptographic Keys</h1>
          <p className="text-muted-foreground">
            Manage encryption and signing keys
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => loadKeys()} disabled={loading}>
            <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Dialog open={isGenerateDialogOpen} onOpenChange={setIsGenerateDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" />
                Generate Key
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl">
              <DialogHeader>
                <DialogTitle>Generate New Key</DialogTitle>
                <DialogDescription>
                  Create a new cryptographic key for encryption or signing
                </DialogDescription>
              </DialogHeader>
              <KeyForm onSubmit={handleGenerateKey} loading={generateMutation.isLoading} />
            </DialogContent>
          </Dialog>
        </div>
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

      {/* Keys Table */}
      <KeyTable
        keys={keys}
        onView={handleView}
        onRotate={handleRotate}
        onExport={handleExport}
        onDelete={handleDelete}
        loading={loading}
      />
    </div>
  );
}
