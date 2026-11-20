"use client";

import * as React from "react";
import { FileSignature, Loader2, ShieldCheck } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAttestationVerify } from "@/hooks/use-attestation-verify";

/**
 * GetAttestationQuote and VerifyAttestationQuote (#2038): request a quote
 * over a fresh nonce, then verify it against an AK public key. Verify stays
 * disabled until a quote is held; both stay disabled once the server says
 * quoting is not configured (503).
 */
export function QuoteCard() {
  const ops = useAttestationVerify();
  const [akPem, setAkPem] = React.useState("");
  const { quote, verdict } = ops;
  const held = quote.result?.quote;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Quote and verify</CardTitle>
        <CardDescription>
          Ask this node&apos;s TPM for a quote over a fresh nonce, then verify the quote with an
          attestation key.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div>
          <Button onClick={() => ops.getQuote()} disabled={quote.pending || quote.unavailable}>
            {quote.pending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <FileSignature className="mr-2 h-4 w-4" />
            )}
            Get quote
          </Button>
        </div>
        {(quote.error || held) && (
          <div data-testid="quote-result" className="text-sm">
            {quote.error ? (
              <Alert variant="destructive">
                <AlertTitle>{quote.unavailable ? "Quoting unavailable" : "Quote failed"}</AlertTitle>
                <AlertDescription>{quote.error}</AlertDescription>
              </Alert>
            ) : (
              <div className="flex flex-col gap-1">
                <p>Signature algorithm: {held?.signatureAlgorithm}</p>
                <p>PCRs: {held?.pcrValues?.length ?? 0}</p>
                <p className="break-all font-mono text-xs">Nonce: {ops.quoteNonce}</p>
              </div>
            )}
          </div>
        )}
        <Label htmlFor="ak-public-key">AK public key (PEM)</Label>
        <Textarea
          id="ak-public-key"
          rows={4}
          value={akPem}
          onChange={(e) => setAkPem(e.target.value)}
          className="font-mono text-xs"
        />
        <div>
          <Button
            variant="outline"
            onClick={() => ops.verifyQuote(akPem.trim())}
            disabled={!held || verdict.pending || verdict.unavailable || !akPem.trim()}
            title={held ? undefined : "Get a quote first"}
          >
            {verdict.pending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <ShieldCheck className="mr-2 h-4 w-4" />
            )}
            Verify quote
          </Button>
        </div>
        {(verdict.error || verdict.result) && (
          <div data-testid="quote-verify-result" className="text-sm">
            {verdict.error ? (
              <Alert variant="destructive">
                <AlertTitle>Quote verification failed</AlertTitle>
                <AlertDescription>{verdict.error}</AlertDescription>
              </Alert>
            ) : (
              <p>
                {verdict.result?.verified ? "Verified" : "Not verified"}
                {verdict.result?.message ? `: ${verdict.result.message}` : ""}
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
