"use client";

import * as React from "react";
import Link from "next/link";
import { PageHeader } from "@/components/layout/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useEAB, useToast } from "@/hooks";

// The server answers with protojson: uint64 fields (id, profileId) arrive as
// JSON strings and status as the enum name, so the created credential is
// read through this wire shape rather than the SDK EABCredential type.
interface CreatedEABCredentialWire {
  id?: string | number;
  keyId?: string;
  hmacKey?: string;
  profileId?: string | number;
  tenantId?: string;
  status?: string;
}

interface CreateEABCredentialWireResponse {
  credential?: CreatedEABCredentialWire;
}

export default function NewEABCredentialPage() {
  const { create } = useEAB();
  const { toast } = useToast();

  const [profileId, setProfileId] = React.useState("");
  const [tenantId, setTenantId] = React.useState("");
  const [expiry, setExpiry] = React.useState("");
  const [created, setCreated] = React.useState<CreatedEABCredentialWire | null>(null);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setCreated(null);
    try {
      const expiryTrimmed = expiry.trim();
      const response = (await create.mutateAsync({
        profileId: Number(profileId),
        tenantId: tenantId.trim(),
        ...(expiryTrimmed ? { expiresInSeconds: Number(expiryTrimmed) } : {}),
      })) as unknown as CreateEABCredentialWireResponse | undefined;
      const credential = response?.credential;
      if (!credential?.hmacKey) {
        throw new Error("The server returned no HMAC key");
      }
      setCreated(credential);
      toast({
        title: "EAB credential created",
        description: `Key ID ${credential.keyId ?? ""}`,
        variant: "success",
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to create EAB credential";
      toast({
        title: "Failed to create EAB credential",
        description: message,
        variant: "destructive",
      });
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="New EAB Credential"
        description="Create an External Account Binding credential for an ACME client"
        actions={
          <Button variant="outline" asChild>
            <Link href="/ca/eab">Back to EAB credentials</Link>
          </Button>
        }
      />

      <Card>
        <CardContent className="pt-6">
          <form className="space-y-4" onSubmit={handleSubmit}>
            <div className="space-y-2">
              <Label htmlFor="eab-profile-id">Profile ID</Label>
              <Input
                id="eab-profile-id"
                type="number"
                min={1}
                required
                value={profileId}
                onChange={(e) => setProfileId(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="eab-tenant-id">Tenant ID</Label>
              <Input
                id="eab-tenant-id"
                type="text"
                required
                value={tenantId}
                onChange={(e) => setTenantId(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="eab-expires-in">Expires in (seconds)</Label>
              <Input
                id="eab-expires-in"
                type="number"
                min={1}
                value={expiry}
                onChange={(e) => setExpiry(e.target.value)}
              />
            </div>
            <Button type="submit" disabled={create.isLoading}>
              Create credential
            </Button>
          </form>
        </CardContent>
      </Card>

      {created && (
        <Card>
          <CardHeader>
            <CardTitle>Credential created</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p role="alert" className="text-sm font-medium text-destructive">
              Copy the HMAC key now; it will not be shown again.
            </p>
            <div className="space-y-1">
              <div className="text-sm text-muted-foreground">Key ID</div>
              <code className="block break-all rounded bg-muted px-2 py-1 font-mono text-sm">
                {created.keyId}
              </code>
            </div>
            <div className="space-y-1">
              <div className="text-sm text-muted-foreground">HMAC key</div>
              <code className="block break-all rounded bg-muted px-2 py-1 font-mono text-sm">
                {created.hmacKey}
              </code>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
