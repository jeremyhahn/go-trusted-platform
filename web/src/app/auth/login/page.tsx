"use client";

/**
 * Login page (/auth/login)
 *
 * Auto-detects available factor types and shows three buttons
 * (mTLS / FIDO2 / PIV). Each button is enabled only when its factor type
 * is reachable from the client device, per §5e of the bootstrap-auth-architecture.
 *
 * On success, stores the JWT cookie and redirects to /dashboard.
 */

import React, { useState, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { startAuthentication } from "@simplewebauthn/browser";
import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser";
import { Key, Fingerprint, CreditCard, Loader2, Link2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { getBaseUrl } from "@/utils/getBaseUrl";
import { setCookie } from "@/utils/cookie";
import { isFIDO2Available, isMTLSAvailable } from "@/utils/auth-factors-api";

type LoginMethod = "mtls" | "fido2" | "piv";

interface MethodAvailability {
  mtls: boolean;
  fido2: boolean;
  piv: false; // PIV always disabled in browser; cross-device via xKey desktop
  loading: boolean;
}

function LoginContent() {
  const router = useRouter();
  const params = useSearchParams();
  const redirectTo = params.get("redirect") ?? "/dashboard";

  const [username, setUsername] = useState("");
  const [availability, setAvailability] = useState<MethodAvailability>({
    mtls: false,
    fido2: false,
    piv: false,
    loading: true,
  });
  const [activeMethod, setActiveMethod] = useState<LoginMethod | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // Probe available factor types on mount.
  useEffect(() => {
    async function probe() {
      const [mtls, fido2] = await Promise.all([
        isMTLSAvailable(),
        Promise.resolve(isFIDO2Available()),
      ]);
      setAvailability({ mtls, fido2, piv: false, loading: false });
    }
    probe();
  }, []);

  async function loginWithMTLS() {
    // mTLS: browser auto-selects cert on TLS handshake.
    // We hit a dedicated mTLS login endpoint that reads the client cert
    // from the TLS connection and returns a JWT.
    setBusy(true);
    setError("");
    try {
      const resp = await fetch(`${getBaseUrl()}/api/v1/auth/mtls/login`, {
        method: "POST",
        credentials: "same-origin",
      });
      if (!resp.ok) {
        const body = (await resp.json()) as { error?: string };
        throw new Error(body.error ?? `HTTP ${resp.status}`);
      }
      const { token } = (await resp.json()) as { token: string };
      storeJWT(token);
    } catch (err) {
      setError(err instanceof Error ? err.message : "mTLS login failed");
    } finally {
      setBusy(false);
    }
  }

  async function loginWithFIDO2() {
    if (!username.trim()) {
      setError("Enter your username to use FIDO2 login.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const beginResp = await fetch(`${getBaseUrl()}/api/v1/webauthn/login/begin`, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
      });
      if (!beginResp.ok) {
        const body = (await beginResp.json()) as { error?: string };
        throw new Error(body.error ?? `HTTP ${beginResp.status}`);
      }
      const { publicKey, user_id: userId, session_id: sessionId } = (await beginResp.json()) as {
        publicKey: PublicKeyCredentialRequestOptionsJSON;
        session_id?: string;
        user_id: string;
      };

      const assertion = await startAuthentication({ optionsJSON: publicKey });

      const finishResp = await fetch(`${getBaseUrl()}/api/v1/webauthn/login/finish`, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-User-Id": userId ?? "",
          "X-Session-Id": sessionId ?? "",
        },
        body: JSON.stringify(assertion),
      });
      if (!finishResp.ok) {
        const body = (await finishResp.json()) as { error?: string };
        throw new Error(body.error ?? `HTTP ${finishResp.status}`);
      }

      const data = (await finishResp.json()) as {
        success?: boolean;
        payload?: string | { token: string };
      };
      const jwt =
        typeof data.payload === "string" ? data.payload : data.payload?.token;
      if (!data.success || !jwt) {
        throw new Error("FIDO2 authentication failed");
      }
      storeJWT(jwt);
    } catch (err) {
      setError(err instanceof Error ? err.message : "FIDO2 login failed");
    } finally {
      setBusy(false);
    }
  }

  function storeJWT(token: string) {
    setCookie("jwt", token, {
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      secure: true,
      sameSite: "Strict",
    });
    router.push(redirectTo);
  }

  async function handleMethod(method: LoginMethod) {
    setActiveMethod(method);
    setError("");
    if (method === "mtls") {
      await loginWithMTLS();
    } else if (method === "fido2") {
      await loginWithFIDO2();
    }
    setActiveMethod(null);
  }

  const { loading } = availability;

  // If exactly one method is available, show a single "Sign in" button.
  const availableMethods: LoginMethod[] = [];
  if (availability.mtls) availableMethods.push("mtls");
  if (availability.fido2) availableMethods.push("fido2");

  return (
    <div className="flex min-h-screen items-center justify-center p-4 bg-background">
      <div className="w-full max-w-sm space-y-6">
        {/* Brand */}
        <div className="text-center space-y-2">
          <h1 className="text-2xl font-bold tracking-tight">Sign in</h1>
          <p className="text-sm text-muted-foreground">
            Trusted Platform — secure access
          </p>
        </div>

        {/* Username field (needed for FIDO2 discovery) */}
        <div className="space-y-2">
          <Label htmlFor="username">Username</Label>
          <Input
            id="username"
            type="text"
            placeholder="your@email.com"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && availability.fido2)
                handleMethod("fido2");
            }}
            autoComplete="username"
            aria-label="Username"
          />
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {loading && (
          <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground py-4">
            <Loader2 className="h-4 w-4 animate-spin" />
            Detecting available sign-in methods…
          </div>
        )}

        {!loading && (
          <div className="space-y-3">
            {/* Single-method shortcut */}
            {availableMethods.length === 1 && (
              <Button
                className="w-full"
                onClick={() => handleMethod(availableMethods[0])}
                disabled={busy}
                aria-label="Sign in"
              >
                {busy && activeMethod === availableMethods[0] ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : availableMethods[0] === "mtls" ? (
                  <Key className="h-4 w-4 mr-2" />
                ) : (
                  <Fingerprint className="h-4 w-4 mr-2" />
                )}
                Sign in
              </Button>
            )}

            {/* Multi-method buttons */}
            {availableMethods.length > 1 && (
              <>
                <Button
                  variant={availability.mtls ? "default" : "outline"}
                  className="w-full"
                  onClick={() => handleMethod("mtls")}
                  disabled={!availability.mtls || busy}
                  aria-label="Sign in with mTLS certificate"
                >
                  {busy && activeMethod === "mtls" ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Key className="h-4 w-4 mr-2" />
                  )}
                  Sign in with mTLS
                </Button>

                <Button
                  variant={availability.fido2 ? "default" : "outline"}
                  className="w-full"
                  onClick={() => handleMethod("fido2")}
                  disabled={!availability.fido2 || busy}
                  aria-label="Sign in with FIDO2 / passkey"
                >
                  {busy && activeMethod === "fido2" ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Fingerprint className="h-4 w-4 mr-2" />
                  )}
                  Sign in with FIDO2
                </Button>

                <Button
                  variant="outline"
                  className="w-full opacity-60"
                  disabled
                  aria-label="PIV smartcard — use desktop app"
                  title="PIV smartcard login requires the xKey desktop app (PC/SC not available in browser)"
                >
                  <CreditCard className="h-4 w-4 mr-2" />
                  Sign in with PIV
                  <span className="ml-2 text-xs text-muted-foreground">
                    (use desktop app)
                  </span>
                </Button>
              </>
            )}

            {/* No methods detected */}
            {availableMethods.length === 0 && (
              <>
                <Button
                  variant="outline"
                  className="w-full opacity-60"
                  disabled
                  aria-label="mTLS not available — no client cert loaded"
                >
                  <Key className="h-4 w-4 mr-2" />
                  Sign in with mTLS
                  <span className="ml-2 text-xs">(no cert loaded)</span>
                </Button>

                <Button
                  variant="outline"
                  className="w-full opacity-60"
                  disabled
                  aria-label="FIDO2 not available on this device"
                >
                  <Fingerprint className="h-4 w-4 mr-2" />
                  Sign in with FIDO2
                  <span className="ml-2 text-xs">(not available)</span>
                </Button>

                <Button
                  variant="outline"
                  className="w-full opacity-60"
                  disabled
                  aria-label="PIV smartcard — use desktop app"
                >
                  <CreditCard className="h-4 w-4 mr-2" />
                  Sign in with PIV
                  <span className="ml-2 text-xs">(use desktop app)</span>
                </Button>
              </>
            )}
          </div>
        )}

        <Separator />

        {/* Cross-device WebAuthn (CTAP2 over BLE/QR) */}
        <div className="text-center">
          <button
            className="text-sm text-muted-foreground hover:text-primary underline-offset-4 hover:underline flex items-center gap-1 mx-auto"
            onClick={() => handleMethod("fido2")}
            disabled={busy || loading}
            type="button"
            aria-label="Use a security key on another device"
          >
            <Link2 className="h-3 w-3" />
            Other device?
          </button>
          <p className="text-xs text-muted-foreground mt-1">
            Sign in with a security key on a different device (CTAP2 over BLE
            or QR code).
          </p>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={<div className="flex min-h-screen items-center justify-center"><Loader2 className="h-8 w-8 animate-spin" /></div>}>
      <LoginContent />
    </Suspense>
  );
}
