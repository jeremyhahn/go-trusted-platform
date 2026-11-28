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
 * - Show the KMS backend status
 *
 * Uses the trusted-platform-sdk for API interactions.
 */

import * as React from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Gated } from "@/components/features/capabilities/gated";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { KeyTable } from "@/components/features/kms/key-table";
import { KeyForm } from "@/components/features/kms/key-form";
import { useKMS, useApi, useMutation, useToast } from "@/hooks";
import type { Key, GenerateKeyInput } from "@/types/security";
import { Plus, AlertCircle, RefreshCw } from "lucide-react";
import { usePlatformClient } from "trusted-platform-sdk";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { KmsDigestCard } from "@/components/features/kms/kms-digest-card";
import { KmsKeyAdminCard } from "@/components/features/kms/kms-key-admin-card";
import { KmsBatchCard } from "@/components/features/kms/kms-batch-card";

// A key as the platform KMS REST handler emits it: snake_case or camelCase
// names and ISO-string or epoch-second timestamps, which differs from the
// SDK/proto declaration (#445).
interface KeyWire {
  keyId?: string;
  key_id?: string;
  name?: string;
  algorithm: string;
  status?: string;
  createdAt?: string | number;
  created_at?: string | number;
  version?: number;
}

// The KMS backend status as GET /kms/backend/status emits it
// (rest/kms BackendStatusResponse); the SDK's declared type differs (#445).
interface BackendStatusWire {
  backend_type?: string;
  status?: string;
  device?: string;
  region?: string;
  capabilities?: Record<string, boolean>;
}

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

  // Read the KMS backend status; the card shows its own refusal (no toast).
  const { data: backendData, error: backendError } = useApi(
    () => kms.getBackendStatus(),
    []
  );
  const backend = backendData as unknown as BackendStatusWire | null | undefined;
  const enabledCapabilities = Object.entries(backend?.capabilities ?? {})
    .filter(([, on]) => on)
    .map(([name]) => name)
    .sort();

  // GenerateRandom as POST /kms/random takes and answers it (rest/kms
  // GenerateRandomRequest/Response: num_bytes in, base64 bytes out). The SDK's
  // generateRandom sends numBytes and reads randomBytes (#1675 fixes it), so
  // this goes through the SDK ApiClient with the wire shape.
  const apiClient = usePlatformClient().getApiClient();
  const [randomCount, setRandomCount] = React.useState("32");
  const [randomHex, setRandomHex] = React.useState<string | null>(null);
  const [randomBusy, setRandomBusy] = React.useState(false);

  const generateRandom = async () => {
    const n = Number.parseInt(randomCount, 10);
    setRandomBusy(true);
    try {
      const res = await apiClient.post<{ bytes?: string }>("/v1/kms/random", { num_bytes: n });
      if (res.error) {
        setRandomHex(null);
        toast({ title: "Random bytes refused", description: res.error.message, variant: "destructive" });
        return;
      }
      const raw = atob(res.data?.bytes ?? "");
      setRandomHex(Array.from(raw, (c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join(""));
    } finally {
      setRandomBusy(false);
    }
  };

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
    const list = (keysData?.keys ?? []) as unknown as KeyWire[];
    const toIso = (v: unknown): string => {
      if (!v) return new Date().toISOString();
      if (typeof v === "number") return new Date(v * 1000).toISOString();
      const s = String(v);
      // Treat the Go zero time as "unset".
      if (s.startsWith("0001-")) return new Date().toISOString();
      return s;
    };
    return list.map((key: KeyWire) => {
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

      {/* KMS backend status */}
      <Card data-testid="kms-backend-status">
        <CardHeader>
          <CardTitle>KMS Backend</CardTitle>
          <CardDescription>The backend that holds this platform&apos;s keys</CardDescription>
        </CardHeader>
        <CardContent>
          {backendError ? (
            <p className="text-sm text-destructive">
              Backend status could not be read: {backendError.message}
            </p>
          ) : backend ? (
            <dl className="grid gap-3 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-muted-foreground">Backend</dt>
                <dd data-testid="kms-backend-type" className="font-mono">
                  {backend.backend_type || "-"}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Status</dt>
                <dd data-testid="kms-backend-state">{backend.status || "-"}</dd>
              </div>
              {backend.device && (
                <div>
                  <dt className="text-muted-foreground">Device</dt>
                  <dd data-testid="kms-backend-device" className="font-mono">
                    {backend.device}
                  </dd>
                </div>
              )}
              {backend.region && (
                <div>
                  <dt className="text-muted-foreground">Region</dt>
                  <dd data-testid="kms-backend-region">{backend.region}</dd>
                </div>
              )}
              <div className="sm:col-span-2">
                <dt className="text-muted-foreground">Capabilities</dt>
                <dd data-testid="kms-backend-capabilities">
                  {enabledCapabilities.length ? enabledCapabilities.join(", ") : "none reported"}
                </dd>
              </div>
            </dl>
          ) : (
            <p className="text-sm text-muted-foreground">Reading backend status...</p>
          )}
        </CardContent>
      </Card>

      {/* GenerateRandom */}
      <Card data-testid="kms-random">
        <CardHeader>
          <CardTitle>Random bytes</CardTitle>
          <CardDescription>Draw random bytes from the KMS backend</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <div className="flex items-end gap-2">
            <div className="grid gap-1">
              <Label htmlFor="kms-random-count">Bytes</Label>
              <Input
                id="kms-random-count"
                type="number"
                min={1}
                value={randomCount}
                onChange={(e) => setRandomCount(e.target.value)}
                className="w-32"
              />
            </div>
            <Gated op="POST /api/v1/kms/random">
              <Button variant="outline" onClick={() => void generateRandom()} disabled={randomBusy}>
                Generate random bytes
              </Button>
            </Gated>
          </div>
          {randomHex !== null && (
            <code data-testid="kms-random-hex" className="break-all font-mono text-sm">
              {randomHex}
            </code>
          )}
        </CardContent>
      </Card>

      <KmsDigestCard />
      <KmsKeyAdminCard />
      <KmsBatchCard />

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
