"use client";

/**
 * TPM Quote / Attestation Page
 *
 * Generates a TPM 2.0 quote — a signed structure attesting to the
 * current PCR state — using the platform's IAK (Initial Attestation
 * Key, persistent handle 0x81010002). Modeled after the xkey TPM
 * Svelte view's "Attestation" tab; see memory
 * `reference_xkey_tpm_gui.md`.
 *
 * Flow:
 *   1. Operator picks a set of PCRs to attest (defaults to the
 *      golden set: 0, 1, 4, 7, 9 — boot integrity).
 *   2. Operator supplies a nonce (anti-replay). We auto-generate a
 *      32-byte random nonce on page load; the operator can override.
 *   3. POST /api/v1/tpm/quote with the PCR selection + nonce.
 *   4. Server returns the quote (signed TPMS_ATTEST blob) + the
 *      signature + the TPM's PCR digest snapshot + channelBinding,
 *      the TLS exporter of the connection the request arrived on.
 *   5. The node quoted SHA-256(nonce || channelBinding), never the
 *      nonce as sent (#482). The page refuses a quote whose
 *      qualifying data is anything else. A browser cannot read the
 *      TLS exporter, so it cannot prove channelBinding is its own
 *      connection — only that the quote is bound to the binding the
 *      node returned with it (docs/attestation/engineering.md).
 *
 * The page also exposes a Verify panel that re-checks a quote's
 * signature against the IAK public key and confirms the PCR
 * digest matches what was signed. The channel binding travels with
 * the nonce: a bound quote verifies only against both.
 */

import * as React from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import {
  RefreshCw,
  Shield,
  AlertCircle,
  Copy,
  ShieldCheck,
} from "lucide-react";
import { useTPM, useToast } from "@/hooks";
import { checkQuoteBinding } from "trusted-platform-sdk";
import type { QuoteResponse, VerifyQuoteResponse } from "trusted-platform-sdk";
import { errorMessage } from "@/utils/errors";

// Attestation key handle the quote and verify flows use (TCG persistent range).
const AK_HANDLE = 0x81010002;

const GOLDEN_PCRS = [0, 1, 4, 7, 9];

const PCR_LABELS: Record<number, string> = {
  0: "BIOS/UEFI code",
  1: "BIOS/UEFI configuration",
  2: "Option ROM code",
  3: "Option ROM configuration",
  4: "Master Boot Record",
  5: "MBR/GPT configuration",
  6: "Wake events",
  7: "Secure Boot policy",
  8: "GRUB cmdline",
  9: "Kernel + initrd",
  10: "IMA measurements",
  14: "MOK",
  23: "Platform PCR (golden)",
};

const randomHex = (bytes: number): string => {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
};

// hexToBase64 converts a hex string into the base64 wire form that
// protojson expects for `bytes` fields. The server's REST handler
// uses protojson.UnmarshalOptions to decode QuoteRequest, so all
// bytes fields (nonce, quote, signature, ak_public) must be
// base64-encoded over the wire even though the operator types
// them as hex in the UI.
const hexToBase64 = (hex: string): string => {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
};

// looksBase64 returns true when the supplied string is plausibly
// already a base64 blob (no hex-only chars, contains '+'/'/'/'='
// or has a length that's not a multiple of 2). Used to avoid
// double-encoding when the operator pastes a base64 value from a
// previous quote into the verify panel.
const looksBase64 = (s: string): boolean => {
  if (!s) return false;
  if (/[+/=]/.test(s)) return true;
  if (!/^[0-9a-fA-F]+$/.test(s)) return true;
  return s.length % 2 !== 0;
};

export default function TPMQuotePage() {
  const { toast } = useToast();
  const tpm = useTPM();

  const [selectedPCRs, setSelectedPCRs] = React.useState<number[]>([...GOLDEN_PCRS]);
  const [nonce, setNonce] = React.useState<string>(() => randomHex(32));
  const [quoting, setQuoting] = React.useState(false);
  const [quoteResult, setQuoteResult] = React.useState<QuoteResponse | null>(null);
  const [quoteError, setQuoteError] = React.useState<string | null>(null);

  // Verify panel state
  const [verifyQuote, setVerifyQuote] = React.useState("");
  const [verifySignature, setVerifySignature] = React.useState("");
  const [verifyNonce, setVerifyNonce] = React.useState("");
  const [verifyBinding, setVerifyBinding] = React.useState("");
  const [verifyScheme, setVerifyScheme] = React.useState("");
  const [verifying, setVerifying] = React.useState(false);
  const [verifyResult, setVerifyResult] = React.useState<VerifyQuoteResponse | null>(null);
  const [verifyError, setVerifyError] = React.useState<string | null>(null);

  const togglePCR = (pcr: number) => {
    setSelectedPCRs((prev) =>
      prev.includes(pcr) ? prev.filter((p) => p !== pcr) : [...prev, pcr].sort((a, b) => a - b),
    );
  };

  const handleQuote = async () => {
    setQuoting(true);
    setQuoteError(null);
    setQuoteResult(null);
    try {
      // Default akHandle to the IAK at 0x81010002. The server's
      // QuoteRequest.ak_handle is required (uint32); without a
      // handle the server returns 400 Bad Request before reaching
      // the TPM. Future enhancement: let the operator pick from a
      // dropdown of all attestation-capable handles fetched via
      // /api/v1/tpm/keys.
      const nonceB64 = hexToBase64(nonce);
      const resp = await tpm.quote({
        akHandle: AK_HANDLE,
        pcrIndices: selectedPCRs,
        nonce: nonceB64,
      });
      const payload = resp.data ?? null;
      // Refuse a quote not bound to SHA-256(nonce || channelBinding).
      await checkQuoteBinding(payload?.quote ?? "", nonceB64, payload?.channelBinding);
      setQuoteResult(payload);
      // Pre-fill verify panel for convenience.
      const q = payload?.quote;
      const s = payload?.signature;
      if (q) setVerifyQuote(q);
      if (s) setVerifySignature(s);
      setVerifyNonce(nonce);
      setVerifyBinding(payload?.channelBinding ?? "");
      setVerifyScheme(payload?.signatureAlgorithm ?? "");
      toast({
        title: "Quote generated",
        description: `Attested ${selectedPCRs.length} PCR(s)`,
        variant: "success",
      });
    } catch (e) {
      setQuoteError(errorMessage(e, "Quote failed"));
      toast({
        title: "Quote failed",
        description: errorMessage(e, "Unknown error"),
        variant: "destructive",
      });
    } finally {
      setQuoting(false);
    }
  };

  const handleVerify = async () => {
    setVerifying(true);
    setVerifyError(null);
    setVerifyResult(null);
    try {
      // The verify-quote endpoint also takes protojson bytes
      // fields. Quote/signature come from the previous quote
      // response (already base64 from the server). The nonce may
      // be either the original hex the operator typed or a
      // base64 value pasted from elsewhere — normalize to base64.
      // No akPublic: the server verifies against the platform IAK — the
      // key the quote above was produced with — when it is absent. The
      // `pcrIndices` this page used to send is not a VerifyQuoteRequest
      // field and was dropped by the server. The channel binding is
      // base64 as the quote response returned it; without it a bound
      // quote does not verify against the nonce alone.
      const resp = await tpm.verifyQuote({
        quote: verifyQuote,
        signature: verifySignature,
        nonce: looksBase64(verifyNonce) ? verifyNonce : hexToBase64(verifyNonce),
        ...(verifyBinding ? { channelBinding: verifyBinding } : {}),
        // The signature is checked under the scheme the quote declared.
        signatureAlgorithm: verifyScheme,
      });
      const payload = resp.data ?? null;
      setVerifyResult(payload);
      toast({
        title: payload?.verified ? "Quote VERIFIED" : "Quote INVALID",
        description: payload?.message || "",
        variant: payload?.verified ? "success" : "destructive",
      });
    } catch (e) {
      setVerifyError(errorMessage(e, "Verify failed"));
      toast({
        title: "Verify failed",
        description: errorMessage(e, "Unknown error"),
        variant: "destructive",
      });
    } finally {
      setVerifying(false);
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: `${label} copied`, variant: "success" });
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Quote / Attestation</h1>
        <p className="text-muted-foreground">
          Generate signed TPM quotes attesting to current PCR state, then
          verify them against the platform&apos;s IAK public key
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Generate Quote
            </CardTitle>
            <CardDescription>
              Select PCRs + provide a nonce; signs with the IAK at 0x81010002
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label className="text-sm font-medium">PCR Selection</Label>
              <p className="text-xs text-muted-foreground mb-2">
                Defaults to golden boot-integrity set: {GOLDEN_PCRS.join(", ")}
              </p>
              <div className="grid grid-cols-2 gap-2 mt-2">
                {Object.entries(PCR_LABELS).map(([pcr, label]) => {
                  const idx = parseInt(pcr, 10);
                  return (
                    <div key={pcr} className="flex items-center space-x-2">
                      <Checkbox
                        id={`pcr-${pcr}`}
                        checked={selectedPCRs.includes(idx)}
                        onCheckedChange={() => togglePCR(idx)}
                      />
                      <label
                        htmlFor={`pcr-${pcr}`}
                        className="text-sm leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer"
                      >
                        <span className="font-medium">PCR {pcr}</span>{" "}
                        <span className="text-muted-foreground">{label}</span>
                      </label>
                    </div>
                  );
                })}
              </div>
            </div>

            <div>
              <Label htmlFor="nonce" className="text-sm font-medium">
                Nonce (hex, anti-replay)
              </Label>
              <div className="flex gap-2 mt-1">
                <Input
                  id="nonce"
                  value={nonce}
                  onChange={(e) => setNonce(e.target.value)}
                  className="font-mono text-xs"
                />
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => setNonce(randomHex(32))}
                  title="Generate new random nonce"
                >
                  <RefreshCw className="h-4 w-4" />
                </Button>
              </div>
            </div>

            <Button
              onClick={handleQuote}
              disabled={quoting || selectedPCRs.length === 0}
              className="w-full"
            >
              {quoting ? (
                <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Shield className="mr-2 h-4 w-4" />
              )}
              {quoting ? "Generating quote…" : "Generate Quote"}
            </Button>

            {quoteError && (
              <div className="flex items-center gap-2 p-3 bg-destructive/10 border border-destructive rounded">
                <AlertCircle className="h-4 w-4 text-destructive" />
                <p className="text-sm text-destructive">{quoteError}</p>
              </div>
            )}

            {quoteResult && (
              <div className="space-y-3 pt-3 border-t">
                <div>
                  <Label className="text-xs text-muted-foreground">Attestation</Label>
                  <div className="flex gap-2 mt-1">
                    <Textarea
                      value={quoteResult.quote || ""}
                      readOnly
                      className="font-mono text-xs h-20"
                    />
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() =>
                        copyToClipboard(
                          quoteResult.quote || "",
                          "Attestation",
                        )
                      }
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">Signature</Label>
                  <div className="flex gap-2 mt-1">
                    <Textarea
                      value={quoteResult.signature || ""}
                      readOnly
                      className="font-mono text-xs h-20"
                    />
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() =>
                        copyToClipboard(quoteResult.signature || "", "Signature")
                      }
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5" />
              Verify Quote
            </CardTitle>
            <CardDescription>
              Re-validate a quote against the IAK public key and current state
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="vquote" className="text-sm font-medium">Attestation</Label>
              <Textarea
                id="vquote"
                value={verifyQuote}
                onChange={(e) => setVerifyQuote(e.target.value)}
                placeholder="Paste the quote/attestation blob"
                className="font-mono text-xs h-20 mt-1"
              />
            </div>
            <div>
              <Label htmlFor="vsig" className="text-sm font-medium">Signature</Label>
              <Textarea
                id="vsig"
                value={verifySignature}
                onChange={(e) => setVerifySignature(e.target.value)}
                placeholder="Paste the signature"
                className="font-mono text-xs h-20 mt-1"
              />
            </div>
            <div>
              <Label htmlFor="vnonce" className="text-sm font-medium">Nonce</Label>
              <Input
                id="vnonce"
                value={verifyNonce}
                onChange={(e) => setVerifyNonce(e.target.value)}
                className="font-mono text-xs mt-1"
              />
            </div>
            <div>
              <Label htmlFor="vscheme" className="text-sm font-medium">
                Signature scheme
              </Label>
              <Input
                id="vscheme"
                value={verifyScheme}
                onChange={(e) => setVerifyScheme(e.target.value)}
                placeholder="The signatureAlgorithm returned with the quote, e.g. SHA256-RSAPSS"
                className="font-mono text-xs mt-1"
              />
            </div>
            <div>
              <Label htmlFor="vbinding" className="text-sm font-medium">
                Channel binding (base64)
              </Label>
              <Input
                id="vbinding"
                value={verifyBinding}
                onChange={(e) => setVerifyBinding(e.target.value)}
                placeholder="The channelBinding returned with the quote"
                className="font-mono text-xs mt-1"
              />
            </div>

            <Button
              onClick={handleVerify}
              disabled={verifying || !verifyQuote || !verifySignature}
              className="w-full"
              variant="outline"
            >
              {verifying ? (
                <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <ShieldCheck className="mr-2 h-4 w-4" />
              )}
              {verifying ? "Verifying…" : "Verify Quote"}
            </Button>

            {verifyError && (
              <div className="flex items-center gap-2 p-3 bg-destructive/10 border border-destructive rounded">
                <AlertCircle className="h-4 w-4 text-destructive" />
                <p className="text-sm text-destructive">{verifyError}</p>
              </div>
            )}

            {verifyResult && (
              <div
                className={`p-4 border rounded ${
                  verifyResult.verified
                    ? "bg-green-50 border-green-300 dark:bg-green-950/30 dark:border-green-800"
                    : "bg-destructive/10 border-destructive"
                }`}
              >
                <div className="flex items-center gap-2">
                  {verifyResult.verified ? (
                    <ShieldCheck className="h-5 w-5 text-green-600" />
                  ) : (
                    <AlertCircle className="h-5 w-5 text-destructive" />
                  )}
                  <Badge variant={verifyResult.verified ? "default" : "destructive"}>
                    {verifyResult.verified ? "VERIFIED" : "INVALID"}
                  </Badge>
                </div>
                {verifyResult.message && (
                  <p className="text-sm mt-2">{verifyResult.message}</p>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>About TPM Quotes</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-3">
          <p>
            A TPM <strong>quote</strong> is a digitally-signed structure
            (TPMS_ATTEST) that includes a digest of the selected PCRs at the
            moment of signing, plus a caller-supplied nonce. The signature is
            produced by the IAK (Initial Attestation Key) at persistent handle{" "}
            <code>0x81010002</code> — an attestation-only key whose private
            half can never leave the TPM.
          </p>
          <p>
            A remote verifier can replay the quote to confirm: (1) the
            signature was produced by this specific TPM&apos;s IAK (matched
            against the IAK certificate that anchors back to the TCG IDevID),
            (2) the PCR snapshot matches a known-good golden value, (3) the
            nonce matches what the verifier sent (anti-replay).
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
