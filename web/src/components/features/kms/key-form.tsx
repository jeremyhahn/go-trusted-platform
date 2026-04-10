"use client";

import * as React from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { GenerateKeyInput } from "@/types/security";
import { Loader2 } from "lucide-react";

interface KeyFormProps {
  onSubmit: (data: GenerateKeyInput) => void | Promise<void>;
  loading?: boolean;
}

/**
 * Key generation form component
 *
 * Features:
 * - Input validation
 * - Algorithm selection
 * - Metadata configuration
 * - Loading state during generation
 * - Algorithm recommendations
 */
export function KeyForm({ onSubmit, loading = false }: KeyFormProps) {
  const [formData, setFormData] = React.useState<GenerateKeyInput>({
    name: "",
    algorithm: "AES-256",
    metadata: {},
  });

  const [metadataKey, setMetadataKey] = React.useState("");
  const [metadataValue, setMetadataValue] = React.useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await onSubmit(formData);
  };

  const handleChange = (field: keyof GenerateKeyInput, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
  };

  const handleAddMetadata = () => {
    if (metadataKey && metadataValue) {
      setFormData((prev) => ({
        ...prev,
        metadata: {
          ...prev.metadata,
          [metadataKey]: metadataValue,
        },
      }));
      setMetadataKey("");
      setMetadataValue("");
    }
  };

  const handleRemoveMetadata = (key: string) => {
    setFormData((prev) => {
      const newMetadata = { ...prev.metadata };
      delete newMetadata[key];
      return { ...prev, metadata: newMetadata };
    });
  };

  const getAlgorithmDescription = (algorithm: string) => {
    switch (algorithm) {
      case "AES-256":
        return "Symmetric encryption, best for data encryption";
      case "RSA-2048":
        return "Asymmetric, good balance of security and performance";
      case "RSA-4096":
        return "Asymmetric, maximum security for long-term use";
      case "ECDSA-P256":
        return "Asymmetric, fast with smaller keys (recommended)";
      case "ECDSA-P384":
        return "Asymmetric, higher security than P-256";
      default:
        return "";
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Generate New Key</CardTitle>
        <CardDescription>
          Create a new cryptographic key for encryption, signing, or verification
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Key Name */}
          <div className="space-y-2">
            <Label htmlFor="name">
              Key Name <span className="text-destructive">*</span>
            </Label>
            <Input
              id="name"
              placeholder="my-encryption-key"
              value={formData.name}
              onChange={(e) => handleChange("name", e.target.value)}
              required
              disabled={loading}
            />
            <p className="text-xs text-muted-foreground">
              A unique identifier for this key
            </p>
          </div>

          {/* Algorithm */}
          <div className="space-y-2">
            <Label htmlFor="algorithm">
              Algorithm <span className="text-destructive">*</span>
            </Label>
            <Select
              value={formData.algorithm}
              onValueChange={(value) => handleChange("algorithm", value)}
              disabled={loading}
            >
              <SelectTrigger id="algorithm">
                <SelectValue placeholder="Select algorithm" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="AES-256">AES-256 (Symmetric)</SelectItem>
                <SelectItem value="RSA-2048">RSA-2048 (Asymmetric)</SelectItem>
                <SelectItem value="RSA-4096">RSA-4096 (Asymmetric)</SelectItem>
                <SelectItem value="ECDSA-P256">ECDSA P-256 (Asymmetric)</SelectItem>
                <SelectItem value="ECDSA-P384">ECDSA P-384 (Asymmetric)</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              {getAlgorithmDescription(formData.algorithm)}
            </p>
          </div>

          {/* Metadata */}
          <div className="space-y-2">
            <Label>Metadata (Optional)</Label>
            <div className="flex gap-2">
              <Input
                placeholder="Key"
                value={metadataKey}
                onChange={(e) => setMetadataKey(e.target.value)}
                disabled={loading}
                className="flex-1"
              />
              <Input
                placeholder="Value"
                value={metadataValue}
                onChange={(e) => setMetadataValue(e.target.value)}
                disabled={loading}
                className="flex-1"
              />
              <Button
                type="button"
                variant="outline"
                onClick={handleAddMetadata}
                disabled={loading || !metadataKey || !metadataValue}
              >
                Add
              </Button>
            </div>

            {/* Display existing metadata */}
            {formData.metadata && Object.keys(formData.metadata).length > 0 && (
              <div className="mt-2 space-y-1">
                {Object.entries(formData.metadata).map(([key, value]) => (
                  <div
                    key={key}
                    className="flex items-center justify-between p-2 bg-muted rounded text-sm"
                  >
                    <span>
                      <span className="font-medium">{key}:</span> {value}
                    </span>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => handleRemoveMetadata(key)}
                      disabled={loading}
                    >
                      Remove
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Submit Button */}
          <div className="flex justify-end gap-2">
            <Button type="submit" disabled={loading || !formData.name}>
              {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {loading ? "Generating..." : "Generate Key"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
