"use client";

import * as React from "react";
import { AlertCircle } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useCeremony } from "@/hooks/use-ceremony";
import type {
  CeremonyCertificateResponse,
  CeremonyClaimCertBeginResponse,
  CeremonyClaimShareBeginResponse,
  CeremonyClaimShareCompleteResponse,
  CeremonyInitResponse,
} from "trusted-platform-sdk";
import { CeremonyGate, ceremonyGateReason, ceremonyInitReason } from "./ceremony-gate";

function splitList(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function Pem({ testId, label, value }: { testId: string; label: string; value: string }) {
  if (value === "") return null;
  return (
    <div className="flex flex-col gap-1">
      <span className="text-sm font-medium">{label}</span>
      <pre data-testid={testId} className="max-h-48 overflow-auto rounded bg-muted p-2 text-xs">
        {value}
      </pre>
    </div>
  );
}

export default function CeremonyPage() {
  const c = useCeremony();
  const gate = ceremonyGateReason(c.statusError, c.loading);
  const busy = c.pending !== null;

  const [soPin, setSoPin] = React.useState("");
  const [userPin, setUserPin] = React.useState("");
  const [threshold, setThreshold] = React.useState("");
  const [hostname, setHostname] = React.useState("");
  const [sans, setSans] = React.useState("");
  const [initOut, setInitOut] = React.useState<CeremonyInitResponse | null>(null);

  const [certUser, setCertUser] = React.useState("");
  const [authType, setAuthType] = React.useState("");
  const [slot, setSlot] = React.useState("");
  const [credentialId, setCredentialId] = React.useState("");
  const [certBegin, setCertBegin] = React.useState<CeremonyClaimCertBeginResponse | null>(null);
  const [certSig, setCertSig] = React.useState("");
  const [certOut, setCertOut] = React.useState<CeremonyCertificateResponse | null>(null);

  const [shareUser, setShareUser] = React.useState("");
  const [shareBegin, setShareBegin] = React.useState<CeremonyClaimShareBeginResponse | null>(null);
  const [shareSig, setShareSig] = React.useState("");
  const [shareOut, setShareOut] = React.useState<CeremonyClaimShareCompleteResponse | null>(null);

  const [csrUser, setCsrUser] = React.useState("");
  const [csrPin, setCsrPin] = React.useState("");
  const [csrRole, setCsrRole] = React.useState("");
  const [csrPem, setCsrPem] = React.useState("");
  const [csrOut, setCsrOut] = React.useState<CeremonyCertificateResponse | null>(null);

  const status = c.status;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Key ceremony</h1>
        <p className="text-muted-foreground">
          Initialise the ceremony, let officers claim their certificate and secret share, and sign
          officer CSRs.
        </p>
      </div>

      {c.statusError !== null && (
        <div data-testid="ceremony-error" role="alert" className="flex items-center gap-2 text-destructive">
          <AlertCircle className="h-4 w-4" />
          <span>{c.statusError}</span>
        </div>
      )}
      {c.stepError !== null && (
        <div data-testid="ceremony-step-error" role="alert" className="flex items-center gap-2 text-destructive">
          <AlertCircle className="h-4 w-4" />
          <span>{c.stepError}</span>
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Status</CardTitle>
          <CardDescription>CeremonyService.Status</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2 text-sm sm:grid-cols-2">
          <div>
            Ceremony: <span data-testid="ceremony-id">{status?.ceremony_id ?? ""}</span>
          </div>
          <div>
            State: <span data-testid="ceremony-state">{status ? status.state || "uninitialized" : ""}</span>
          </div>
          <div>Threshold: {status?.threshold ?? ""}</div>
          <div>
            Officers:{" "}
            <span data-testid="ceremony-officers">
              {status ? `${status.officers_enrolled} / ${status.officers_required}` : ""}
            </span>
          </div>
          {status?.initialized_at && <div>Initialised: {status.initialized_at}</div>}
          <div>
            <CeremonyGate gateId="ceremony-refresh" variant="outline" reason={null} busy={c.loading} onClick={() => void c.refresh()}>
              Refresh
            </CeremonyGate>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Initialise</CardTitle>
          <CardDescription>CeremonyService.Init</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          <div className="grid gap-1">
            <Label htmlFor="init-so-pin">SO PIN</Label>
            <Input id="init-so-pin" type="password" value={soPin} onChange={(e) => setSoPin(e.target.value)} />
          </div>
          <div className="grid gap-1">
            <Label htmlFor="init-user-pin">User PIN</Label>
            <Input id="init-user-pin" type="password" value={userPin} onChange={(e) => setUserPin(e.target.value)} />
          </div>
          <div className="grid gap-1">
            <Label htmlFor="init-threshold">Threshold</Label>
            <Input id="init-threshold" placeholder="2-of-3" value={threshold} onChange={(e) => setThreshold(e.target.value)} />
          </div>
          <div className="grid gap-1">
            <Label htmlFor="init-hostname">Hostname</Label>
            <Input id="init-hostname" value={hostname} onChange={(e) => setHostname(e.target.value)} />
          </div>
          <div className="grid gap-1 sm:col-span-2">
            <Label htmlFor="init-sans">Subject alternative names</Label>
            <Input id="init-sans" placeholder="comma or space separated" value={sans} onChange={(e) => setSans(e.target.value)} />
          </div>
          <div className="sm:col-span-2">
            <CeremonyGate
              gateId="ceremony-init"
              reason={ceremonyInitReason(gate, status?.state)}
              busy={busy}
              onClick={async () => {
                const out = await c.init({
                  so_pin: soPin || undefined,
                  user_pin: userPin || undefined,
                  threshold: threshold || undefined,
                  hostname: hostname || undefined,
                  sans: sans ? splitList(sans) : undefined,
                });
                setInitOut(out);
              }}
            >
              Initialize
            </CeremonyGate>
          </div>
          {initOut && (
            <div className="grid gap-2 sm:col-span-2">
              <div>
                SPKI pin: <span data-testid="init-spki-pin">{initOut.spki_pin}</span>
              </div>
              <Pem testId="init-admin-cert" label="Admin certificate" value={initOut.admin_cert_pem} />
              <Pem testId="init-admin-key" label="Admin key (shown once)" value={initOut.admin_key_pem} />
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Claim officer certificate</CardTitle>
          <CardDescription>CeremonyService.ClaimCertBegin and ClaimCertComplete</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          <div className="grid gap-1">
            <Label htmlFor="claim-cert-username">Officer</Label>
            <Input id="claim-cert-username" data-testid="claim-cert-username" value={certUser} onChange={(e) => setCertUser(e.target.value)} />
          </div>
          <div className="grid gap-1">
            <Label htmlFor="claim-cert-auth">Authenticator type</Label>
            <Input id="claim-cert-auth" placeholder="piv or fido2" value={authType} onChange={(e) => setAuthType(e.target.value)} />
          </div>
          <div className="grid gap-1">
            <Label htmlFor="claim-cert-slot">PIV slot</Label>
            <Input id="claim-cert-slot" value={slot} onChange={(e) => setSlot(e.target.value)} />
          </div>
          <div className="grid gap-1">
            <Label htmlFor="claim-cert-credential">FIDO2 credential ID</Label>
            <Input id="claim-cert-credential" value={credentialId} onChange={(e) => setCredentialId(e.target.value)} />
          </div>
          <div className="sm:col-span-2">
            <CeremonyGate
              gateId="claim-cert-begin"
              reason={gate}
              busy={busy}
              onClick={async () => {
                setCertOut(null);
                setCertBegin(
                  await c.claimCertBegin({
                    username: certUser,
                    authenticator_type: authType || undefined,
                    slot: slot || undefined,
                    credential_id: credentialId || undefined,
                  }),
                );
              }}
            >
              Begin certificate claim
            </CeremonyGate>
          </div>
          {certBegin && (
            <div className="grid gap-2 sm:col-span-2">
              <div>
                Nonce to sign: <code data-testid="claim-cert-nonce">{certBegin.nonce}</code>
              </div>
              <Label htmlFor="claim-cert-signature">Signature over the nonce</Label>
              <Textarea id="claim-cert-signature" value={certSig} onChange={(e) => setCertSig(e.target.value)} />
              <CeremonyGate
                gateId="claim-cert-complete"
                reason={gate}
                busy={busy}
                onClick={async () =>
                  setCertOut(await c.claimCertComplete({ username: certUser, nonce: certBegin.nonce, signature: certSig }))
                }
              >
                Complete certificate claim
              </CeremonyGate>
            </div>
          )}
          {certOut && (
            <div className="grid gap-2 sm:col-span-2">
              <Pem testId="claim-cert-certificate" label="Certificate" value={certOut.certificate_pem} />
              <Pem testId="claim-cert-chain" label="Chain" value={certOut.chain_pem} />
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Claim secret share</CardTitle>
          <CardDescription>CeremonyService.ClaimShareBegin and ClaimShareComplete</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3">
          <div className="grid gap-1">
            <Label htmlFor="claim-share-username">Officer</Label>
            <Input id="claim-share-username" data-testid="claim-share-username" value={shareUser} onChange={(e) => setShareUser(e.target.value)} />
          </div>
          <div>
            <CeremonyGate
              gateId="claim-share-begin"
              reason={gate}
              busy={busy}
              onClick={async () => {
                setShareOut(null);
                setShareBegin(await c.claimShareBegin({ username: shareUser }));
              }}
            >
              Begin share claim
            </CeremonyGate>
          </div>
          {shareBegin && (
            <div className="grid gap-2">
              <div>
                Nonce to sign: <code data-testid="claim-share-nonce">{shareBegin.nonce}</code>
              </div>
              <Label htmlFor="claim-share-signature">Signature over the nonce (base64)</Label>
              <Textarea id="claim-share-signature" value={shareSig} onChange={(e) => setShareSig(e.target.value)} />
              <CeremonyGate
                gateId="claim-share-complete"
                reason={gate}
                busy={busy}
                onClick={async () =>
                  setShareOut(await c.claimShareComplete({ username: shareUser, nonce: shareBegin.nonce, signature: shareSig }))
                }
              >
                Complete share claim
              </CeremonyGate>
            </div>
          )}
          {shareOut && (
            <div className="grid gap-1">
              <div>
                Share index: <span data-testid="claim-share-index">{shareOut.index}</span>
              </div>
              <Pem testId="claim-share-share" label="Share (shown once)" value={shareOut.share} />
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Sign officer CSR</CardTitle>
          <CardDescription>CeremonyService.SignCSR</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          <div className="grid gap-1">
            <Label htmlFor="sign-csr-username">Officer</Label>
            <Input id="sign-csr-username" data-testid="sign-csr-username" value={csrUser} onChange={(e) => setCsrUser(e.target.value)} />
          </div>
          <div className="grid gap-1">
            <Label htmlFor="sign-csr-pin">Security officer PIN</Label>
            <Input id="sign-csr-pin" type="password" value={csrPin} onChange={(e) => setCsrPin(e.target.value)} />
          </div>
          <div className="grid gap-1">
            <Label htmlFor="sign-csr-role">Role</Label>
            <Input id="sign-csr-role" placeholder="admin or officer" value={csrRole} onChange={(e) => setCsrRole(e.target.value)} />
          </div>
          <div className="grid gap-1 sm:col-span-2">
            <Label htmlFor="sign-csr-pem">CSR (PEM)</Label>
            <Textarea id="sign-csr-pem" value={csrPem} onChange={(e) => setCsrPem(e.target.value)} />
          </div>
          <div className="sm:col-span-2">
            <CeremonyGate
              gateId="sign-csr"
              reason={gate}
              busy={busy}
              onClick={async () =>
                setCsrOut(await c.signCSR({ username: csrUser, so_pin: csrPin, csr_pem: csrPem, role: csrRole }))
              }
            >
              Sign CSR
            </CeremonyGate>
          </div>
          {csrOut && (
            <div className="grid gap-2 sm:col-span-2">
              <Pem testId="sign-csr-certificate" label="Certificate" value={csrOut.certificate_pem} />
              <Pem testId="sign-csr-chain" label="Chain" value={csrOut.chain_pem} />
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
