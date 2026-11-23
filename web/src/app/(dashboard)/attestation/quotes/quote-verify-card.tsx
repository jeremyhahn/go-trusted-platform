"use client";

/**
 * QuoteVerifyCard asks a node for a TPM quote (GetAttestationQuote) and
 * verifies it (VerifyAttestationQuote) through useAttestationVerify and the
 * SDK client (#2038). The verify sends back the nonce and the channel binding
 * the quote came back with.
 */

import * as React from "react";
import type {
  AttestationQuote,
  AttestationQuoteConfig,
  VerifyAttestationQuoteResponse,
} from "trusted-platform-sdk";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Gated } from "@/components/features/capabilities/gated";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks";
import { quoteVerdictLabel, useAttestationVerify } from "@/hooks/use-attestation-verify";
import { textToBase64 } from "@/hooks/use-tpm-ops";

type HashAlgorithm = NonNullable<AttestationQuoteConfig["hashAlgorithm"]>;

const HASH_ALGORITHMS: HashAlgorithm[] = ["SHA1", "SHA256", "SHA384", "SHA512"] as HashAlgorithm[];

/** "0x81010001" or "2164326401" -> 2164326401; blank -> undefined; anything else -> NaN. */
export function parseAkHandle(s: string): number | undefined {
  const t = s.trim();
  if (t === "") return undefined;
  if (/^0x[0-9a-f]+$/i.test(t)) return parseInt(t.slice(2), 16);
  if (/^[0-9]+$/.test(t)) return parseInt(t, 10);
  return NaN;
}

/** "0, 7,,23" -> [0, 7, 23]; blank -> undefined; a non-integer entry -> null (invalid). */
export function parsePcrIndices(s: string): number[] | undefined | null {
  const parts = s
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p !== "");
  if (parts.length === 0) return undefined;
  const out: number[] = [];
  for (const p of parts) {
    if (!/^[0-9]+$/.test(p)) return null;
    out.push(parseInt(p, 10));
  }
  return out;
}

export function QuoteVerifyCard(): React.JSX.Element {
  const { toast } = useToast();
  const verify = useAttestationVerify();

  const [akHandle, setAkHandle] = React.useState("");
  const [pcrs, setPcrs] = React.useState("");
  const [hashAlgorithm, setHashAlgorithm] = React.useState<HashAlgorithm>("SHA256" as HashAlgorithm);
  const [nonce, setNonce] = React.useState("");
  const [pem, setPem] = React.useState("");
  const [quote, setQuote] = React.useState<AttestationQuote | undefined>();
  const [channelBinding, setChannelBinding] = React.useState<string | undefined>();
  const [verdict, setVerdict] = React.useState<VerifyAttestationQuoteResponse | undefined>();
  const [busy, setBusy] = React.useState(false);

  const handle = parseAkHandle(akHandle);
  const pcrIndices = parsePcrIndices(pcrs);
  const canQuote = nonce.trim() !== "" && !Number.isNaN(handle) && pcrIndices !== null && !busy;
  const canVerify = !!quote && pem.trim() !== "" && !busy;

  const onGetQuote = async () => {
    const config: AttestationQuoteConfig = { hashAlgorithm };
    if (handle !== undefined) config.akHandle = handle;
    if (pcrIndices) config.pcrIndices = pcrIndices;
    setBusy(true);
    try {
      const res = await verify.getQuote({ config, nonce: nonce.trim() });
      setVerdict(undefined);
      if (!res.success || !res.data?.quote) {
        setQuote(undefined);
        setChannelBinding(undefined);
        toast({
          title: "Quote request failed",
          description: res.error?.message,
          variant: "destructive",
        });
        return;
      }
      setQuote(res.data.quote);
      setChannelBinding(res.data.channelBinding || undefined);
    } finally {
      setBusy(false);
    }
  };

  const onVerifyQuote = async () => {
    if (!quote) return;
    setBusy(true);
    try {
      const res = await verify.verifyQuote({
        quote,
        // ak_public_key_pem is a proto `bytes` field: the JSON gateway
        // base64-decodes it, so the PEM text goes as base64.
        akPublicKeyPem: textToBase64(pem.trim()),
        expectedNonce: nonce.trim(),
        ...(channelBinding ? { channelBinding } : {}),
      });
      if (!res.success || !res.data) {
        toast({
          title: "Quote verification failed",
          description: res.error?.message,
          variant: "destructive",
        });
        return;
      }
      setVerdict(res.data);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="quote-verify">
      <CardHeader>
        <CardTitle>Ask for a quote</CardTitle>
        <CardDescription>
          Ask the node for a TPM quote over the nonce, then verify it with the AK public key.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid gap-4 md:grid-cols-4">
          <Input
            aria-label="AK handle"
            placeholder="0x81010001"
            value={akHandle}
            onChange={(e) => setAkHandle(e.target.value)}
          />
          <Input
            aria-label="PCRs"
            placeholder="0,7"
            value={pcrs}
            onChange={(e) => setPcrs(e.target.value)}
          />
          <select
            aria-label="Hash algorithm"
            className="h-9 rounded-md border border-input bg-transparent px-3 text-sm"
            value={hashAlgorithm}
            onChange={(e) => setHashAlgorithm(e.target.value as HashAlgorithm)}
          >
            {HASH_ALGORITHMS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
          <Input
            aria-label="Nonce"
            placeholder="base64 nonce"
            value={nonce}
            onChange={(e) => setNonce(e.target.value)}
          />
        </div>
        <Textarea
          aria-label="AK public key (PEM)"
          placeholder="-----BEGIN PUBLIC KEY-----"
          value={pem}
          onChange={(e) => setPem(e.target.value)}
        />
        <div className="flex gap-2">
          <Gated op="POST /api/v1/attestation/quote">
            <Button onClick={onGetQuote} disabled={!canQuote}>
              Get quote
            </Button>
          </Gated>
          <Gated op="POST /api/v1/attestation/quote/verify">
            <Button variant="outline" onClick={onVerifyQuote} disabled={!canVerify}>
              Verify quote
            </Button>
          </Gated>
        </div>
        {quote && (
          <dl data-testid="quote-result" className="grid grid-cols-2 gap-1 text-sm">
            <dt className="text-muted-foreground">Signature algorithm</dt>
            <dd>{quote.signatureAlgorithm}</dd>
            <dt className="text-muted-foreground">Nonce</dt>
            <dd className="font-mono">{quote.nonce}</dd>
            <dt className="text-muted-foreground">PCR values</dt>
            <dd>{quote.pcrValues?.length ?? 0}</dd>
            <dt className="text-muted-foreground">Binding</dt>
            <dd>{channelBinding ? "Bound" : "Unbound"}</dd>
          </dl>
        )}
        {verdict && (
          <p data-testid="quote-verdict" className="text-sm font-medium">
            {quoteVerdictLabel(verdict)}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
