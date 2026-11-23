"use client";

/**
 * AttestationQuoteCard: GetAttestationQuote and VerifyAttestationQuote
 * through the SDK AttestationService (#2038). Each button sits in <Gated>
 * on the server's route, so a node without attestation withholds it.
 */

import * as React from "react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Gated } from "@/components/features/capabilities/gated";
import { useAttestation, useToast } from "@/hooks";

type AttestationClient = ReturnType<typeof useAttestation>;
type QuoteRequest = Parameters<AttestationClient["getQuote"]>[0];
type VerifyRequest = Parameters<AttestationClient["verifyQuote"]>[0];
type Quote = VerifyRequest["quote"];

interface QuoteResult {
  quote?: Quote;
  channelBinding?: string;
}

interface Verdict {
  verified: boolean;
  message?: string;
}

/** parsePcrIndices reads "0,7, 10" as [0, 7, 10]; an entry that is not a PCR index is an error. */
export function parsePcrIndices(text: string): number[] {
  const parts = text
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p !== "");
  return parts.map((p) => {
    const n = Number(p);
    if (!/^\d+$/.test(p) || n > 23) {
      throw new Error(`invalid PCR index: ${p}`);
    }
    return n;
  });
}

/**
 * Encode a PEM key for a proto `bytes` field: protojson decodes bytes from
 * base64, so a raw PEM would be refused before verification runs.
 */
export function pemToBase64(pem: string): string {
  const bytes = new TextEncoder().encode(pem);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function AttestationQuoteCard() {
  const attestation = useAttestation();
  const { toast } = useToast();

  const [nonce, setNonce] = React.useState("");
  const [pcrs, setPcrs] = React.useState("");
  const [akHandle, setAkHandle] = React.useState("");
  const [quoting, setQuoting] = React.useState(false);
  const [result, setResult] = React.useState<QuoteResult | null>(null);
  const [quoteError, setQuoteError] = React.useState<string | null>(null);

  const [quoteJson, setQuoteJson] = React.useState("");
  const [akPem, setAkPem] = React.useState("");
  const [expectedNonce, setExpectedNonce] = React.useState("");
  const [verifying, setVerifying] = React.useState(false);
  const [verdict, setVerdict] = React.useState<Verdict | null>(null);
  const [verifyError, setVerifyError] = React.useState<string | null>(null);

  const failed = (title: string, description: string) =>
    toast({ title, description, variant: "destructive" });

  const getQuote = async (e: React.FormEvent) => {
    e.preventDefault();
    setQuoteError(null);
    const config: QuoteRequest["config"] = {};
    try {
      const indices = parsePcrIndices(pcrs);
      if (indices.length > 0) config.pcrIndices = indices;
      if (akHandle.trim() !== "") {
        const handle = Number(akHandle.trim());
        if (!Number.isInteger(handle) || handle < 0) {
          throw new Error(`invalid AK handle: ${akHandle}`);
        }
        config.akHandle = handle;
      }
    } catch (err) {
      setQuoteError(errorText(err));
      return;
    }
    setQuoting(true);
    try {
      const res = await attestation.getQuote({ nonce: nonce.trim(), config });
      if (!res.success || !res.data) {
        failed("Quote request failed", res.error?.message ?? "no quote in the answer");
        return;
      }
      setResult({ quote: res.data.quote, channelBinding: res.data.channelBinding });
      setVerdict(null);
      if (res.data.quote) {
        setQuoteJson(JSON.stringify(res.data.quote, null, 2));
        // The quote's own nonce is SHA-256(nonce || channelBinding) when bound;
        // the verify wants the nonce the quote was requested with.
        setExpectedNonce(nonce.trim());
      }
    } catch (err) {
      failed("Quote request failed", errorText(err));
    } finally {
      setQuoting(false);
    }
  };

  const verifyQuote = async (e: React.FormEvent) => {
    e.preventDefault();
    setVerifyError(null);
    setVerdict(null);
    let quote: Quote;
    try {
      quote = JSON.parse(quoteJson) as Quote;
      if (quote === null || typeof quote !== "object" || Array.isArray(quote)) {
        throw new Error("the quote must be a JSON object");
      }
    } catch (err) {
      setVerifyError(`Invalid quote JSON: ${errorText(err)}`);
      return;
    }
    setVerifying(true);
    try {
      const request: VerifyRequest = {
        quote,
        akPublicKeyPem: pemToBase64(akPem.trim()),
        expectedNonce: expectedNonce.trim(),
      };
      if (result?.channelBinding && result.quote && JSON.stringify(result.quote) === JSON.stringify(quote)) {
        request.channelBinding = result.channelBinding;
      }
      const res = await attestation.verifyQuote(request);
      if (!res.success || !res.data) {
        failed("Quote verification failed", res.error?.message ?? "no verdict in the answer");
        return;
      }
      setVerdict({ verified: res.data.verified === true, message: res.data.message });
    } catch (err) {
      failed("Quote verification failed", errorText(err));
    } finally {
      setVerifying(false);
    }
  };

  return (
    <Card data-testid="attestation-quote-card">
      <CardHeader>
        <CardTitle>TPM quote</CardTitle>
        <CardDescription>
          Ask this node&apos;s TPM for a quote over a nonce, and verify a quote against an AK public key
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-6 lg:grid-cols-2">
        <form className="flex flex-col gap-3" onSubmit={getQuote}>
          <h3 className="text-sm font-semibold">Get quote</h3>
          <div className="grid gap-1">
            <Label htmlFor="attestation-quote-nonce">Nonce (base64)</Label>
            <Input
              id="attestation-quote-nonce"
              data-testid="attestation-quote-nonce"
              value={nonce}
              onChange={(e) => setNonce(e.target.value)}
            />
          </div>
          <div className="grid gap-1">
            <Label htmlFor="attestation-quote-pcrs">PCR indices</Label>
            <Input
              id="attestation-quote-pcrs"
              data-testid="attestation-quote-pcrs"
              placeholder="0,1,7"
              value={pcrs}
              onChange={(e) => setPcrs(e.target.value)}
            />
          </div>
          <div className="grid gap-1">
            <Label htmlFor="attestation-quote-ak-handle">AK handle (optional)</Label>
            <Input
              id="attestation-quote-ak-handle"
              data-testid="attestation-quote-ak-handle"
              value={akHandle}
              onChange={(e) => setAkHandle(e.target.value)}
            />
          </div>
          {quoteError && (
            <p className="text-sm text-destructive" data-testid="attestation-quote-error">
              {quoteError}
            </p>
          )}
          <div>
            <Gated op="POST /api/v1/attestation/quote">
              <Button type="submit" disabled={quoting}>
                Get quote
              </Button>
            </Gated>
          </div>
          {result && (
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm" data-testid="attestation-quote-result">
              <dt className="text-muted-foreground">Signature algorithm</dt>
              <dd className="font-mono" data-testid="attestation-quote-signature-algorithm">
                {result.quote?.signatureAlgorithm || "none"}
              </dd>
              <dt className="text-muted-foreground">Nonce</dt>
              <dd className="font-mono break-all" data-testid="attestation-quote-result-nonce">
                {result.quote?.nonce || "none"}
              </dd>
              <dt className="text-muted-foreground">PCRs</dt>
              <dd data-testid="attestation-quote-pcr-count">{result.quote?.pcrValues?.length ?? 0}</dd>
              <dt className="text-muted-foreground">Channel binding</dt>
              <dd className="font-mono break-all" data-testid="attestation-quote-channel-binding">
                {result.channelBinding || "none"}
              </dd>
            </dl>
          )}
        </form>

        <form className="flex flex-col gap-3" onSubmit={verifyQuote}>
          <h3 className="text-sm font-semibold">Verify quote</h3>
          <div className="grid gap-1">
            <Label htmlFor="attestation-verify-quote">Quote (JSON)</Label>
            <Textarea
              id="attestation-verify-quote"
              data-testid="attestation-verify-quote"
              rows={5}
              className="font-mono text-xs"
              value={quoteJson}
              onChange={(e) => {
                setQuoteJson(e.target.value);
                setVerdict(null);
              }}
            />
          </div>
          <div className="grid gap-1">
            <Label htmlFor="attestation-verify-ak-pem">AK public key (PEM)</Label>
            <Textarea
              id="attestation-verify-ak-pem"
              data-testid="attestation-verify-ak-pem"
              rows={4}
              className="font-mono text-xs"
              value={akPem}
              onChange={(e) => {
                setAkPem(e.target.value);
                setVerdict(null);
              }}
            />
          </div>
          <div className="grid gap-1">
            <Label htmlFor="attestation-verify-nonce">Expected nonce (base64)</Label>
            <Input
              id="attestation-verify-nonce"
              data-testid="attestation-verify-nonce"
              value={expectedNonce}
              onChange={(e) => {
                setExpectedNonce(e.target.value);
                setVerdict(null);
              }}
            />
          </div>
          {verifyError && (
            <p className="text-sm text-destructive" data-testid="attestation-verify-error">
              {verifyError}
            </p>
          )}
          <div>
            <Gated op="POST /api/v1/attestation/quote/verify">
              <Button type="submit" disabled={verifying}>
                Verify quote
              </Button>
            </Gated>
          </div>
          {verdict && (
            <div className="text-sm" data-testid="attestation-quote-verdict">
              <span className={verdict.verified ? "font-semibold text-green-600" : "font-semibold text-destructive"}>
                {verdict.verified ? "verified" : "not verified"}
              </span>
              {verdict.message && <span className="ml-2 text-muted-foreground">{verdict.message}</span>}
            </div>
          )}
        </form>
      </CardContent>
    </Card>
  );
}
