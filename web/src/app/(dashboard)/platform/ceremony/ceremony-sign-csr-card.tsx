"use client";

/**
 * CeremonySignCSRCard signs an officer CSR with the ceremony CA:
 * CeremonyService.SignCSR through `useCeremony().signCSR`,
 * `POST /api/v1/ceremony/sign-csr`. The SO PIN is cleared once the CSR is
 * signed; a refusal is shown verbatim.
 */
import * as React from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  useCeremony,
  type CeremonyOfficerRole,
  type CeremonySignCSRResponse,
} from "@/hooks/use-ceremony";

export const CEREMONY_OFFICER_ROLES = [
  "CEREMONY_OFFICER_ROLE_SO",
  "CEREMONY_OFFICER_ROLE_ADMIN",
  "CEREMONY_OFFICER_ROLE_USER",
] as const;

/** officerRoleLabel names a CeremonyOfficerRole for the operator. */
export function officerRoleLabel(role: string): string {
  switch (role) {
    case "CEREMONY_OFFICER_ROLE_SO":
      return "Security officer";
    case "CEREMONY_OFFICER_ROLE_ADMIN":
      return "Admin";
    case "CEREMONY_OFFICER_ROLE_USER":
      return "User";
    default:
      return "Unspecified";
  }
}

export function CeremonySignCSRCard() {
  const ceremony = useCeremony();
  const [username, setUsername] = React.useState("");
  const [soPin, setSoPin] = React.useState("");
  const [csrPem, setCsrPem] = React.useState("");
  const [role, setRole] = React.useState<CeremonyOfficerRole>("CEREMONY_OFFICER_ROLE_USER");
  const [running, setRunning] = React.useState(false);
  const [refusal, setRefusal] = React.useState<string | null>(null);
  const [result, setResult] = React.useState<CeremonySignCSRResponse | null>(null);

  const disabled = username.trim() === "" || soPin === "" || csrPem.trim() === "" || running;

  const handleSign = async () => {
    setRunning(true);
    setRefusal(null);
    try {
      const res = await ceremony.signCSR({
        username: username.trim(),
        soPin,
        csrPem: csrPem.trim(),
        role,
      });
      if (res.success && res.data) {
        setSoPin("");
        setResult(res.data);
      } else {
        setResult(null);
        setRefusal(res.error?.message ?? "");
      }
    } catch (err) {
      setRefusal(err instanceof Error ? err.message : String(err));
    } finally {
      setRunning(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Sign officer CSR</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="ceremony-sign-username">Username</Label>
          <Input
            id="ceremony-sign-username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="ceremony-sign-so-pin">SO PIN</Label>
          <Input
            id="ceremony-sign-so-pin"
            type="password"
            autoComplete="off"
            value={soPin}
            onChange={(e) => setSoPin(e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="ceremony-sign-csr">CSR (PEM)</Label>
          <Textarea
            id="ceremony-sign-csr"
            value={csrPem}
            onChange={(e) => setCsrPem(e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="ceremony-sign-role">Role</Label>
          <select
            id="ceremony-sign-role"
            className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            value={role}
            onChange={(e) => setRole(e.target.value as CeremonyOfficerRole)}
          >
            {CEREMONY_OFFICER_ROLES.map((r) => (
              <option key={r} value={r}>
                {officerRoleLabel(r)}
              </option>
            ))}
          </select>
        </div>
        <Button disabled={disabled} onClick={handleSign}>
          Sign CSR
        </Button>

        {refusal !== null && <p role="alert">Sign CSR refused: {refusal}</p>}

        {result && (
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="ceremony-sign-certificate">Certificate</Label>
              <Textarea id="ceremony-sign-certificate" readOnly value={result.certificatePem} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ceremony-sign-chain">Chain</Label>
              <Textarea id="ceremony-sign-chain" readOnly value={result.chainPem} />
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
