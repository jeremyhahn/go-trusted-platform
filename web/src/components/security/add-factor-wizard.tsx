"use client";

/**
 * AddFactorWizard — 4-step modal wizard for enrolling a new auth factor.
 *
 * Step 1: pick type (mTLS / FIDO2 / PIV)
 * Step 2: type-specific credential collection
 * Step 3: label the factor + confirm
 * Step 4: success
 *
 * Matches the identical UX spec in §5e of the bootstrap-auth-architecture doc.
 */

import React, { useState, useRef } from "react";
import {
  startRegistration,
} from "@simplewebauthn/browser";
import type { PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/browser";
import {
  Key,
  Fingerprint,
  CreditCard,
  CheckCircle2,
  Loader2,
  Upload,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { VendorBadge } from "./vendor-badge";
import { authFactorsApi, isFIDO2Available } from "@/utils/auth-factors-api";
import type { AuthFactor, AuthFactorType } from "@/types/auth-factors";
import { getBaseUrl } from "@/utils/getBaseUrl";
import { getCookie } from "@/utils/cookie";

interface AddFactorWizardProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  userId: string;
  onAdded: (factor: AuthFactor) => void;
  /** Rotate mode: pre-select a factor type and skip step 1. */
  rotateFactorId?: string;
  rotateFactorType?: AuthFactorType;
}

type WizardStep = 1 | 2 | 3 | 4;

type MTLSMode = "generate" | "upload";

interface WizardState {
  step: WizardStep;
  type: AuthFactorType | null;
  label: string;
  // mTLS
  mtlsMode: MTLSMode;
  mtlsCertPEM: string;
  // FIDO2 — the raw response from navigator.credentials.create
  fido2Response: unknown;
  fido2VendorName: string;
  // PIV
  pivCertPEM: string;
  pivSlot: string;
  pivVendorName: string;
  // shared error
  error: string;
  busy: boolean;
}

const INITIAL: WizardState = {
  step: 1,
  type: null,
  label: "",
  mtlsMode: "generate",
  mtlsCertPEM: "",
  fido2Response: null,
  fido2VendorName: "",
  pivCertPEM: "",
  pivSlot: "9a",
  pivVendorName: "",
  error: "",
  busy: false,
};

function StepIndicator({ step }: { step: WizardStep }) {
  const steps = ["Type", "Credential", "Label", "Done"];
  return (
    <div
      className="flex items-center gap-1 mb-6"
      role="progressbar"
      aria-valuenow={step}
      aria-valuemin={1}
      aria-valuemax={4}
      aria-label={`Step ${step} of 4`}
    >
      {steps.map((label, i) => {
        const n = (i + 1) as WizardStep;
        const active = n === step;
        const done = n < step;
        return (
          <React.Fragment key={n}>
            <div className="flex flex-col items-center gap-1">
              <div
                className={`h-7 w-7 rounded-full flex items-center justify-center text-xs font-semibold
                  ${done ? "bg-primary text-primary-foreground" : active ? "bg-primary/20 border-2 border-primary text-primary" : "bg-muted text-muted-foreground"}`}
              >
                {done ? <CheckCircle2 className="h-4 w-4" /> : n}
              </div>
              <span
                className={`text-xs hidden sm:block ${active ? "text-primary font-medium" : "text-muted-foreground"}`}
              >
                {label}
              </span>
            </div>
            {i < steps.length - 1 && (
              <div
                className={`flex-1 h-0.5 mt-[-16px] ${done ? "bg-primary" : "bg-muted"}`}
              />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}

/** Step 1: pick factor type */
function StepPickType({
  value,
  onChange,
  fido2Available,
}: {
  value: AuthFactorType | null;
  onChange: (t: AuthFactorType) => void;
  fido2Available: boolean;
}) {
  const options: {
    type: AuthFactorType;
    icon: React.ReactNode;
    title: string;
    description: React.ReactNode;
    disabled?: boolean;
  }[] = [
    {
      type: "mtls",
      icon: <Key className="h-5 w-5 text-blue-500" />,
      title: "mTLS Certificate",
      description: "Generate a new client cert or upload an existing PEM.",
    },
    {
      type: "fido2",
      icon: <Fingerprint className="h-5 w-5 text-purple-500" />,
      title: "FIDO2 / Passkey",
      description: fido2Available
        ? "Tap your security key or use a built-in authenticator."
        : "WebAuthn not available on this device.",
      disabled: !fido2Available,
    },
    {
      type: "piv",
      icon: <CreditCard className="h-5 w-5 text-green-500" />,
      title: "PIV Smartcard",
      description: (
        <>
          Insert your PIV card and enter your User PIN.
          <br />
          <span className="text-xs text-amber-600">
            PC/SC not available in browser — use the xKey desktop app.
          </span>
        </>
      ),
      disabled: true,
    },
  ];

  return (
    <div className="space-y-3" role="group" aria-labelledby="pick-type-label">
      <p id="pick-type-label" className="text-sm text-muted-foreground">
        Choose the type of authentication factor to add.
      </p>
      <div className="space-y-2">
        {options.map((opt) => (
          <label
            key={opt.type}
            className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors
              ${value === opt.type ? "border-primary bg-primary/5" : "border-border hover:bg-muted/50"}
              ${opt.disabled ? "opacity-50 cursor-not-allowed pointer-events-none" : ""}`}
          >
            <input
              type="radio"
              name="factor-type"
              value={opt.type}
              checked={value === opt.type}
              onChange={() => !opt.disabled && onChange(opt.type)}
              disabled={opt.disabled}
              className="mt-1 accent-primary"
              aria-label={opt.title}
            />
            <div className="flex items-start gap-2">
              {opt.icon}
              <div>
                <div className="text-sm font-medium">{opt.title}</div>
                <div className="text-xs text-muted-foreground mt-0.5">
                  {opt.description}
                </div>
              </div>
            </div>
          </label>
        ))}
      </div>
    </div>
  );
}

/** Step 2a: mTLS */
function StepMTLS({
  mode,
  certPEM,
  onModeChange,
  onCertPEM,
  onGenerated,
  userId,
  error,
  busy,
}: {
  mode: MTLSMode;
  certPEM: string;
  onModeChange: (m: MTLSMode) => void;
  onCertPEM: (pem: string) => void;
  onGenerated: (pem: string) => void;
  userId: string;
  error: string;
  busy: boolean;
}) {
  const fileRef = useRef<HTMLInputElement>(null);

  async function handleGenerate() {
    try {
      // Generate ECDSA P-256 keypair via WebCrypto and send CSR to platform CA.
      const kp = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );
      const pubExported = await crypto.subtle.exportKey("spki", kp.publicKey);
      const pubB64 = btoa(String.fromCharCode(...new Uint8Array(pubExported)));

      const jwt = getCookie("jwt");
      const resp = await fetch(`${getBaseUrl()}/api/v1/users/${encodeURIComponent(userId)}/factors/mtls/issue-cert`, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          ...(jwt ? { Authorization: `Bearer ${jwt}` } : {}),
        },
        body: JSON.stringify({ public_key_spki_b64: pubB64 }),
      });

      if (!resp.ok) {
        const body = (await resp.json()) as { error?: string };
        throw new Error(body.error ?? `HTTP ${resp.status}`);
      }

      const { cert_pem } = (await resp.json()) as { cert_pem: string };
      onGenerated(cert_pem);
    } catch (err) {
      onGenerated("");
    }
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      onCertPEM((ev.target?.result as string) ?? "");
    };
    reader.readAsText(file);
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-4" role="group" aria-label="mTLS source">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="radio"
            name="mtls-mode"
            value="generate"
            checked={mode === "generate"}
            onChange={() => onModeChange("generate")}
            className="accent-primary"
            aria-label="Generate new cert"
          />
          <span className="text-sm">Generate new cert</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="radio"
            name="mtls-mode"
            value="upload"
            checked={mode === "upload"}
            onChange={() => onModeChange("upload")}
            className="accent-primary"
            aria-label="Upload existing cert"
          />
          <span className="text-sm">Upload existing cert</span>
        </label>
      </div>

      {mode === "generate" && (
        <div className="space-y-3">
          <p className="text-xs text-muted-foreground">
            A new ECDSA P-256 keypair will be generated in the browser. The
            platform CA will sign the CSR and return the certificate.
          </p>
          {certPEM ? (
            <div className="rounded-md bg-muted p-3 font-mono text-xs break-all">
              {certPEM.slice(0, 120)}…
            </div>
          ) : (
            <Button
              variant="outline"
              onClick={handleGenerate}
              disabled={busy}
              type="button"
            >
              {busy ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Key className="h-4 w-4 mr-2" />
              )}
              Generate certificate
            </Button>
          )}
        </div>
      )}

      {mode === "upload" && (
        <div className="space-y-3">
          <input
            type="file"
            ref={fileRef}
            accept=".pem,.crt,.cer"
            className="hidden"
            onChange={handleFileChange}
            aria-label="Select PEM file"
          />
          <Button
            variant="outline"
            onClick={() => fileRef.current?.click()}
            type="button"
          >
            <Upload className="h-4 w-4 mr-2" />
            Select PEM file
          </Button>
          {certPEM && (
            <div className="rounded-md bg-muted p-3 font-mono text-xs break-all">
              {certPEM.slice(0, 120)}…
            </div>
          )}
        </div>
      )}

      {error && <p className="text-sm text-destructive">{error}</p>}
    </div>
  );
}

/** Step 2b: FIDO2 */
function StepFIDO2({
  onResponse,
  vendorName,
  error,
  busy,
  userId,
}: {
  onResponse: (resp: unknown, vendor: string) => void;
  vendorName: string;
  error: string;
  busy: boolean;
  userId: string;
}) {
  const [tapped, setTapped] = useState(false);

  async function handleRegister() {
    try {
      const jwt = getCookie("jwt");
      const optResp = await fetch(
        `${getBaseUrl()}/api/v1/webauthn/register/begin`,
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            ...(jwt ? { Authorization: `Bearer ${jwt}` } : {}),
          },
          body: JSON.stringify({ user_id: userId }),
        }
      );

      if (!optResp.ok) {
        const body = (await optResp.json()) as { error?: string };
        throw new Error(body.error ?? `HTTP ${optResp.status}`);
      }

      const opts = (await optResp.json()) as {
        publicKey: PublicKeyCredentialCreationOptionsJSON;
        vendor?: string;
      };

      setTapped(true);
      const credential = await startRegistration({ optionsJSON: opts.publicKey });
      onResponse(credential, opts.vendor ?? "FIDO2 Key");
    } catch (err) {
      setTapped(false);
      onResponse(null, "");
    }
  }

  return (
    <div className="space-y-4 text-center">
      <div className="flex flex-col items-center gap-3 py-4">
        <Fingerprint
          className={`h-16 w-16 ${tapped ? "text-purple-500 animate-pulse" : "text-muted-foreground"}`}
        />
        <p className="text-sm text-muted-foreground">
          {tapped
            ? "Waiting for authenticator — tap your security key or follow the prompt."
            : "Click below to start FIDO2 registration."}
        </p>
        {vendorName && (
          <p className="text-sm font-medium text-purple-600">
            Registered: {vendorName}
          </p>
        )}
      </div>

      {!vendorName && (
        <Button
          onClick={handleRegister}
          disabled={busy || tapped}
          className="w-full"
          type="button"
        >
          {busy || tapped ? (
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          ) : (
            <Fingerprint className="h-4 w-4 mr-2" />
          )}
          {tapped ? "Waiting for authenticator…" : "Register security key"}
        </Button>
      )}

      {error && <p className="text-sm text-destructive">{error}</p>}
    </div>
  );
}

/** Step 2c: PIV — web UI shows a prompt to use the desktop app */
function StepPIV() {
  return (
    <div className="space-y-4 text-center">
      <CreditCard className="h-16 w-16 mx-auto text-muted-foreground" />
      <div className="space-y-2">
        <p className="text-sm font-medium">PIV smartcard registration</p>
        <p className="text-sm text-muted-foreground">
          PC/SC reader access is not available in the browser. Use the{" "}
          <strong>xKey desktop app</strong> to register a PIV card, then log in
          here with your other factor.
        </p>
      </div>
    </div>
  );
}

/** Step 3: label */
function StepLabel({
  label,
  onChange,
  type,
}: {
  label: string;
  onChange: (s: string) => void;
  type: AuthFactorType;
}) {
  const placeholder =
    type === "mtls"
      ? "Work laptop cert"
      : type === "fido2"
      ? "YubiKey 5C — work"
      : "PIV card";

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Give this factor a friendly name so you can identify it later.
      </p>
      <div className="space-y-2">
        <Label htmlFor="factor-label">Label</Label>
        <Input
          id="factor-label"
          value={label}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          autoFocus
          maxLength={80}
          aria-describedby="factor-label-hint"
        />
        <p id="factor-label-hint" className="text-xs text-muted-foreground">
          Max 80 characters.
        </p>
      </div>
    </div>
  );
}

/** Step 4: success */
function StepSuccess({ factor }: { factor: AuthFactor }) {
  return (
    <div className="text-center space-y-4 py-4">
      <CheckCircle2 className="h-16 w-16 mx-auto text-green-500" />
      <p className="text-sm font-medium">Factor added successfully</p>
      <div className="flex items-center justify-center gap-2">
        <span className="text-sm">{factor.label}</span>
        <VendorBadge factor={factor} />
      </div>
    </div>
  );
}

export function AddFactorWizard({
  open,
  onOpenChange,
  userId,
  onAdded,
  rotateFactorId,
  rotateFactorType,
}: AddFactorWizardProps) {
  const fido2Available = isFIDO2Available();
  const [state, setState] = useState<WizardState>({
    ...INITIAL,
    step: rotateFactorType ? 2 : 1,
    type: rotateFactorType ?? null,
  });
  const [addedFactor, setAddedFactor] = useState<AuthFactor | null>(null);

  function reset() {
    setState({
      ...INITIAL,
      step: rotateFactorType ? 2 : 1,
      type: rotateFactorType ?? null,
    });
    setAddedFactor(null);
  }

  function handleClose(open: boolean) {
    if (!open) reset();
    onOpenChange(open);
  }

  function canAdvance(): boolean {
    switch (state.step) {
      case 1:
        return state.type !== null && state.type !== "piv";
      case 2:
        if (state.type === "mtls") return !!state.mtlsCertPEM;
        if (state.type === "fido2") return !!state.fido2Response;
        return false;
      case 3:
        return state.label.trim().length > 0;
      default:
        return false;
    }
  }

  async function handleNext() {
    if (state.step === 3) {
      await submit();
      return;
    }
    setState((s) => ({ ...s, step: (s.step + 1) as WizardStep, error: "" }));
  }

  function handleBack() {
    setState((s) => ({
      ...s,
      step: (s.step - 1) as WizardStep,
      error: "",
    }));
  }

  async function submit() {
    setState((s) => ({ ...s, busy: true, error: "" }));

    const result = rotateFactorId
      ? await authFactorsApi.rotate(userId, {
          factor_id: rotateFactorId,
          cert_pem: state.type === "mtls" ? state.mtlsCertPEM : undefined,
          webauthn_response:
            state.type === "fido2" ? state.fido2Response : undefined,
        })
      : await authFactorsApi.add(userId, {
          type: state.type!,
          label: state.label,
          cert_pem: state.type === "mtls" ? state.mtlsCertPEM : undefined,
          webauthn_response:
            state.type === "fido2" ? state.fido2Response : undefined,
        });

    setState((s) => ({ ...s, busy: false }));

    if (!result.ok) {
      setState((s) => ({ ...s, error: result.error }));
      return;
    }

    const factor = result.data.factor;
    setAddedFactor(factor);
    setState((s) => ({ ...s, step: 4 }));
    onAdded(factor);
  }

  const title =
    state.step === 4
      ? "Factor added"
      : rotateFactorId
      ? "Rotate authentication factor"
      : "Add authentication factor";

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {state.step < 4
              ? "Follow the steps below to add a new way to sign in."
              : "Your new factor is ready to use."}
          </DialogDescription>
        </DialogHeader>

        <StepIndicator step={state.step} />

        <div className="min-h-[180px]">
          {state.step === 1 && (
            <StepPickType
              value={state.type}
              onChange={(t) =>
                setState((s) => ({ ...s, type: t, error: "" }))
              }
              fido2Available={fido2Available}
            />
          )}

          {state.step === 2 && state.type === "mtls" && (
            <StepMTLS
              mode={state.mtlsMode}
              certPEM={state.mtlsCertPEM}
              onModeChange={(m) => setState((s) => ({ ...s, mtlsMode: m, mtlsCertPEM: "" }))}
              onCertPEM={(pem) => setState((s) => ({ ...s, mtlsCertPEM: pem }))}
              onGenerated={(pem) => setState((s) => ({ ...s, mtlsCertPEM: pem }))}
              userId={userId}
              error={state.error}
              busy={state.busy}
            />
          )}

          {state.step === 2 && state.type === "fido2" && (
            <StepFIDO2
              onResponse={(resp, vendor) =>
                setState((s) => ({
                  ...s,
                  fido2Response: resp,
                  fido2VendorName: vendor,
                  error: resp ? "" : "Registration failed — please try again.",
                }))
              }
              vendorName={state.fido2VendorName}
              error={state.error}
              busy={state.busy}
              userId={userId}
            />
          )}

          {state.step === 2 && state.type === "piv" && <StepPIV />}

          {state.step === 3 && (
            <StepLabel
              label={state.label}
              onChange={(l) => setState((s) => ({ ...s, label: l }))}
              type={state.type!}
            />
          )}

          {state.step === 4 && addedFactor && (
            <StepSuccess factor={addedFactor} />
          )}
        </div>

        {state.error && state.step !== 2 && (
          <p className="text-sm text-destructive">{state.error}</p>
        )}

        <DialogFooter className="gap-2">
          {state.step < 4 && state.step > 1 && !rotateFactorType && (
            <Button variant="outline" onClick={handleBack} disabled={state.busy}>
              Back
            </Button>
          )}

          {state.step < 4 && (
            <Button
              onClick={handleNext}
              disabled={!canAdvance() || state.busy}
            >
              {state.busy ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : null}
              {state.step === 3 ? "Add factor" : "Next"}
            </Button>
          )}

          {state.step === 4 && (
            <Button onClick={() => handleClose(false)}>Done</Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
