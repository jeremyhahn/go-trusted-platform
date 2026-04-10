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
import type { IssueCertInput } from "@/types/security";
import { Loader2 } from "lucide-react";

interface IssueCertFormProps {
  onSubmit: (data: IssueCertInput) => void | Promise<void>;
  loading?: boolean;
}

/**
 * Certificate issuance form component
 *
 * Features:
 * - Input validation
 * - Algorithm selection
 * - Certificate type selection
 * - Validity period configuration
 * - Loading state during submission
 */
export function IssueCertForm({ onSubmit, loading = false }: IssueCertFormProps) {
  const [formData, setFormData] = React.useState<IssueCertInput>({
    subject: "",
    type: "leaf",
    validityDays: 365,
    keyAlgorithm: "RSA-2048",
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await onSubmit(formData);
  };

  const handleChange = (field: keyof IssueCertInput, value: string | number) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Issue New Certificate</CardTitle>
        <CardDescription>
          Create a new certificate with the specified parameters
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Subject */}
          <div className="space-y-2">
            <Label htmlFor="subject">
              Subject <span className="text-destructive">*</span>
            </Label>
            <Input
              id="subject"
              placeholder="CN=example.com,O=Organization,C=US"
              value={formData.subject}
              onChange={(e) => handleChange("subject", e.target.value)}
              required
              disabled={loading}
            />
            <p className="text-xs text-muted-foreground">
              Distinguished Name (DN) in RFC 2253 format
            </p>
          </div>

          {/* Certificate Type */}
          <div className="space-y-2">
            <Label htmlFor="type">
              Certificate Type <span className="text-destructive">*</span>
            </Label>
            <Select
              value={formData.type}
              onValueChange={(value) => handleChange("type", value)}
              disabled={loading}
            >
              <SelectTrigger id="type">
                <SelectValue placeholder="Select type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="root">Root CA</SelectItem>
                <SelectItem value="intermediate">Intermediate CA</SelectItem>
                <SelectItem value="leaf">Leaf Certificate</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              Root and Intermediate CAs can sign other certificates
            </p>
          </div>

          {/* Key Algorithm */}
          <div className="space-y-2">
            <Label htmlFor="keyAlgorithm">
              Key Algorithm <span className="text-destructive">*</span>
            </Label>
            <Select
              value={formData.keyAlgorithm}
              onValueChange={(value) => handleChange("keyAlgorithm", value)}
              disabled={loading}
            >
              <SelectTrigger id="keyAlgorithm">
                <SelectValue placeholder="Select algorithm" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="RSA-2048">RSA 2048-bit</SelectItem>
                <SelectItem value="RSA-4096">RSA 4096-bit</SelectItem>
                <SelectItem value="ECDSA-P256">ECDSA P-256</SelectItem>
                <SelectItem value="ECDSA-P384">ECDSA P-384</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              ECDSA provides better performance with smaller key sizes
            </p>
          </div>

          {/* Validity Period */}
          <div className="space-y-2">
            <Label htmlFor="validityDays">
              Validity Period (days) <span className="text-destructive">*</span>
            </Label>
            <Input
              id="validityDays"
              type="number"
              min={1}
              max={3650}
              value={formData.validityDays}
              onChange={(e) => handleChange("validityDays", parseInt(e.target.value))}
              required
              disabled={loading}
            />
            <p className="text-xs text-muted-foreground">
              Common values: 90 (3 months), 365 (1 year), 730 (2 years)
            </p>
          </div>

          {/* Submit Button */}
          <div className="flex justify-end gap-2">
            <Button type="submit" disabled={loading || !formData.subject}>
              {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {loading ? "Issuing..." : "Issue Certificate"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
