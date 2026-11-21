"use client";

import * as React from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Loader2 } from "lucide-react";
import { checkQuoteBinding } from "trusted-platform-sdk";
import { useTPMKeyOperations, useToast } from "@/hooks";
import type { OperationResponse, TPMClient, TPMKeyOperation } from "@/hooks";

/** Persistent handles of the TCG key inventory, the forms' defaults. */
const DEFAULT_EK_HANDLE = "0x81010001";
const DEFAULT_SRK_HANDLE = "0x81000001";
const DEFAULT_AK_HANDLE = "0x81010002";

/**
 * The handle of the platform IAK. The server's Quote ignores akHandle and
 * always signs with the IAK it is configured with (#1751), so the page sends
 * this handle and never an operator-chosen one.
 */
const PLATFORM_IAK_HANDLE = 0x81010002;

/** parseHandle reads a decimal or 0x-prefixed hex handle; NaN when neither. */
export function parseHandle(value: string): number {
  const trimmed = value.trim();
  if (trimmed === "") return Number.NaN;
  return Number(trimmed);
}

/**
 * parsePCRList reads "0, 1,7" as [0, 1, 7] (duplicates removed, order kept).
 * Null when the list is empty or any entry is not a PCR index 0-23: the
 * quote is never taken over fewer PCRs than the operator asked for (#1751).
 */
export function parsePCRList(value: string): number[] | null {
  const indices: number[] = [];
  for (const token of value.split(",").map((s) => s.trim())) {
    if (!/^\d+$/.test(token)) return null;
    const n = Number(token);
    if (n > 23) return null;
    if (!indices.includes(n)) indices.push(n);
  }
  return indices.length === 0 ? null : indices;
}

/**
 * The base64 DER payload of a PEM certificate: the body between the
 * BEGIN/END CERTIFICATE markers, whitespace removed. Null when the markers
 * are missing or the body is empty. The server's EK certificate store takes
 * DER only, so the page never sends the PEM text itself.
 */
export function pemToBase64DER(pem: string): string | null {
  const match = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(pem);
  if (!match) return null;
  const body = (match[1] ?? "").replace(/\s+/g, "");
  return body === "" ? null : body;
}

/** randomNonce returns 32 random bytes, base64. */
function randomNonce(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

/** TPM_ALG_ID of the only PCR bank this panel quotes (TPM_ALG_SHA256). */
const TPM_ALG_SHA256 = 0x000b;

/**
 * quotePCRBanks returns the hash algorithm of every TPMS_PCR_SELECTION in a
 * base64 TPMS_ATTEST quote: magic(4) type(2) qualifiedSigner extraData
 * clockInfo(17) firmwareVersion(8), then TPMS_QUOTE_INFO's
 * TPML_PCR_SELECTION. It throws on a truncated structure. The server's Quote
 * may sign over the IAK's own bank whatever pcrBank asked (#1751), so the
 * caller checks the banks before announcing anything.
 */
export function quotePCRBanks(quoteB64: string): number[] {
  const bytes = Uint8Array.from(atob(quoteB64), (c) => c.charCodeAt(0));
  const view = new DataView(bytes.buffer);
  const need = (at: number, n: number) => {
    if (at + n > bytes.byteLength) throw new Error("quote is truncated before its PCR selection");
  };
  let at = 6;
  for (let i = 0; i < 2; i++) {
    need(at, 2);
    at += 2 + view.getUint16(at); // qualifiedSigner, then extraData
  }
  at += 17 + 8;
  need(at, 4);
  const count = view.getUint32(at);
  at += 4;
  const banks: number[] = [];
  for (let i = 0; i < count; i++) {
    need(at, 3);
    banks.push(view.getUint16(at));
    const sizeofSelect = view.getUint8(at + 2);
    need(at + 3, sizeofSelect);
    at += 3 + sizeofSelect;
  }
  return banks;
}

interface QuoteResult {
  quote?: string;
  signature?: string;
  signatureAlgorithm?: string;
  channelBinding?: string;
}

interface PendingConfirm {
  op: TPMKeyOperation;
  title: string;
  description: string;
  call: (client: TPMClient) => Promise<OperationResponse>;
}

/**
 * TPMKeyOperations renders a control for every TPM key lifecycle
 * operation (#1735). Clear and the Delete* operations open a confirm
 * dialog first.
 */
/** A security verdict carried in a successful answer (e.g. verifyQuote). */
interface Verdict {
  valid: boolean;
  title: string;
  message: string;
}

/**
 * VerifyQuote answers 200 with verified:false for a bad signature, a nonce
 * mismatch or a malformed attestation: only verified === true is valid, as
 * on the TPM Quote page.
 */
function quoteVerdict(data: unknown): Verdict {
  const { verified, message } = (data ?? {}) as { verified?: unknown; message?: unknown };
  const valid = verified === true;
  return {
    valid,
    title: valid ? "Quote VERIFIED" : "Quote INVALID",
    message: typeof message === "string" ? message : "",
  };
}

export function TPMKeyOperations({ onChanged }: { onChanged?: () => void }) {
  const { toast } = useToast();
  const { pending, results, errors, run } = useTPMKeyOperations();

  const [ownerPassword, setOwnerPassword] = React.useState("");
  const [ekHandle, setEkHandle] = React.useState(DEFAULT_EK_HANDLE);
  const [srkHandle, setSrkHandle] = React.useState(DEFAULT_SRK_HANDLE);
  const [akHandle, setAkHandle] = React.useState(DEFAULT_AK_HANDLE);
  const [ekCertificate, setEkCertificate] = React.useState("");
  const [pcrList, setPcrList] = React.useState("0,1,7");
  const [certifyHandle, setCertifyHandle] = React.useState(DEFAULT_SRK_HANDLE);
  const [certifyKeyPassword, setCertifyKeyPassword] = React.useState("");
  const [confirm, setConfirm] = React.useState<PendingConfirm | null>(null);

  // The nonce is kept with the quote it produced: a later failed attempt
  // never pairs a retained quote with another nonce (#1751).
  const [quoted, setQuoted] = React.useState<{ result: QuoteResult; nonce: string } | null>(null);
  const [verdicts, setVerdicts] = React.useState<Partial<Record<TPMKeyOperation, Verdict>>>({});

  const execute = React.useCallback(
    async (
      op: TPMKeyOperation,
      call: (client: TPMClient) => Promise<OperationResponse>,
      mutates = false,
      check?: (data: unknown) => Verdict,
    ): Promise<unknown | null> => {
      setVerdicts((prev) => ({ ...prev, [op]: undefined }));
      const data = await run(op, call);
      if (data === null) return null;
      if (check) {
        // A security verdict travels in a 200 answer: report what it says,
        // not that the request went through.
        const verdict = check(data);
        setVerdicts((prev) => ({ ...prev, [op]: verdict }));
        toast({
          title: verdict.title,
          description: verdict.message,
          variant: verdict.valid ? "success" : "destructive",
        });
      } else {
        toast({ title: "Done", description: `${op} succeeded`, variant: "success" });
      }
      if (mutates) onChanged?.();
      return data;
    },
    [run, toast, onChanged],
  );

  const handleOrToast = (op: TPMKeyOperation, raw: string): number | null => {
    const handle = parseHandle(raw);
    if (!Number.isFinite(handle)) {
      toast({ title: "Invalid handle", description: `${op}: ${raw}`, variant: "destructive" });
      return null;
    }
    return handle;
  };

  const askDelete = (op: "deleteEK" | "deleteSRK" | "deleteAK", label: string, raw: string) => {
    const handle = handleOrToast(op, raw);
    if (handle === null) return;
    const call = (c: TPMClient): Promise<OperationResponse> =>
      op === "deleteEK" ? c.deleteEK({ handle }) : op === "deleteSRK" ? c.deleteSRK({ handle }) : c.deleteAK({ handle });
    setConfirm({
      op,
      title: `Delete ${label}?`,
      // DeleteAK names the platform IAK, which the server never evicts: the
      // request is still sent so the operator sees its refusal (#1751).
      description:
        op === "deleteAK"
          ? `The server refuses to evict the platform Attestation Key at handle ${raw}: it is the device identity key. The request is sent and its refusal is shown.`
          : `The ${label} at handle ${raw} is evicted from the TPM. This cannot be undone.`,
      call,
    });
  };

  const runQuote = async () => {
    const pcrIndices = parsePCRList(pcrList);
    if (pcrIndices === null) {
      toast({
        title: "Invalid PCR list",
        description: "Enter PCR indices 0-23 separated by commas, e.g. 0,1,7",
        variant: "destructive",
      });
      return;
    }
    const nonce = randomNonce();
    setQuoted(null);
    setVerdicts((prev) => ({ ...prev, verifyQuote: undefined }));
    const data = await execute("quote", async (c) => {
      const res = await c.quote({ akHandle: PLATFORM_IAK_HANDLE, pcrIndices, pcrBank: "SHA256", nonce });
      if (res.success !== false) {
        // Refuse a quote not bound to SHA-256(nonce || channelBinding), as
        // the TPM Quote page does: a thrown QuoteBindingError lands in
        // errors.quote, so nothing is announced and nothing can be verified.
        const quote = (res.data ?? {}) as QuoteResult;
        await checkQuoteBinding(quote.quote ?? "", nonce, quote.channelBinding);
        // The binding covers qualifying data only: refuse a quote whose PCR
        // selection is not the SHA256 bank requested (#1751).
        const banks = quotePCRBanks(quote.quote ?? "");
        if (banks.length === 0 || banks.some((b) => b !== TPM_ALG_SHA256)) {
          const got = banks.map((b) => `0x${b.toString(16).padStart(4, "0")}`).join(", ") || "none";
          throw new Error(`quote covers PCR bank ${got}, not the SHA256 bank requested; refused`);
        }
      }
      return res;
    });
    if (data !== null) setQuoted({ result: data as QuoteResult, nonce });
  };

  const runVerify = () => {
    if (!quoted?.result.quote || !quoted.result.signature) return;
    const { result, nonce } = quoted;
    void execute(
      "verifyQuote",
      (c) =>
        c.verifyQuote({
          quote: result.quote ?? "",
          signature: result.signature ?? "",
          signatureAlgorithm: result.signatureAlgorithm,
          channelBinding: result.channelBinding,
          nonce,
        }),
      false,
      quoteVerdict,
    );
  };

  const runCertify = () => {
    const handle = handleOrToast("certify", certifyHandle);
    if (handle === null) return;
    // The target key's authValue: TPM2_Certify needs it for a
    // password-protected key (#1751).
    void execute("certify", (c) =>
      c.certify({
        keyHandle: handle,
        nonce: randomNonce(),
        ...(certifyKeyPassword ? { keyPassword: certifyKeyPassword } : {}),
      }),
    );
  };

  const opButton = (op: TPMKeyOperation, label: string, onClick: () => void, opts: { destructive?: boolean; disabled?: boolean } = {}) => (
    <Button
      data-testid={`tpm-op-${op}`}
      variant={opts.destructive ? "destructive" : "outline"}
      size="sm"
      disabled={pending !== null || opts.disabled}
      onClick={onClick}
    >
      {pending === op && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
      {label}
    </Button>
  );

  const outcome = (op: TPMKeyOperation) => (
    <>
      {verdicts[op] && (
        <p
          data-testid={`tpm-verdict-${op}`}
          className={verdicts[op]?.valid ? "text-xs text-green-600" : "text-xs text-destructive"}
        >
          {verdicts[op]?.valid ? "VERIFIED" : "INVALID"}
          {verdicts[op]?.message ? `: ${verdicts[op]?.message}` : ""}
        </p>
      )}
      {errors[op] && (
        <p data-testid={`tpm-error-${op}`} className="text-xs text-destructive">
          {errors[op]}
        </p>
      )}
      {results[op] !== undefined && (
        <pre
          data-testid={`tpm-result-${op}`}
          className="bg-muted p-2 rounded text-xs font-mono whitespace-pre-wrap break-all max-h-48 overflow-y-auto"
        >
          {JSON.stringify(results[op], null, 2)}
        </pre>
      )}
    </>
  );

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Provisioning</CardTitle>
          <CardDescription>Provision or clear the TPM, and read what it supports</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-2 max-w-sm">
            <Label htmlFor="tpm-owner-password">Owner password</Label>
            <Input
              id="tpm-owner-password"
              type="password"
              value={ownerPassword}
              onChange={(e) => setOwnerPassword(e.target.value)}
            />
          </div>
          <div className="flex flex-wrap gap-2">
            {opButton("provision", "Provision", () =>
              void execute(
                "provision",
                (c) => c.provision({ ownerPassword, createEk: true, createSrk: true, createAk: true }),
                true,
              ),
            )}
            {opButton(
              "clear",
              "Clear TPM",
              () =>
                setConfirm({
                  op: "clear",
                  title: "Clear the TPM?",
                  description: "Clearing destroys every key in the owner and endorsement hierarchies. This cannot be undone.",
                  call: (c: TPMClient) => c.clear({ ownerPassword, confirm: true }),
                }),
              { destructive: true },
            )}
            {opButton("capabilities", "Capabilities", () => void execute("capabilities", (c) => c.getCapabilities()))}
            {opButton("platform", "Platform Attributes", () => void execute("platform", (c) => c.getPlatformAttributes()))}
          </div>
          {outcome("provision")}
          {outcome("clear")}
          {outcome("capabilities")}
          {outcome("platform")}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Endorsement and Storage Root Keys</CardTitle>
          <CardDescription>Create, delete and certify the EK and SRK</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-2 md:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="tpm-ek-handle">EK handle</Label>
              <Input id="tpm-ek-handle" value={ekHandle} onChange={(e) => setEkHandle(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="tpm-srk-handle">SRK handle</Label>
              <Input id="tpm-srk-handle" value={srkHandle} onChange={(e) => setSrkHandle(e.target.value)} />
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {opButton("createEK", "Create EK", () => void execute("createEK", (c) => c.createEK({ persistent: true }), true))}
            {opButton("deleteEK", "Delete EK", () => askDelete("deleteEK", "Endorsement Key", ekHandle), { destructive: true })}
            {opButton("createSRK", "Create SRK", () => void execute("createSRK", (c) => c.createSRK({ persistent: true }), true))}
            {opButton("deleteSRK", "Delete SRK", () => askDelete("deleteSRK", "Storage Root Key", srkHandle), { destructive: true })}
          </div>
          <div className="grid gap-2">
            <Label htmlFor="tpm-ek-certificate">EK certificate (PEM)</Label>
            <Textarea
              id="tpm-ek-certificate"
              rows={4}
              value={ekCertificate}
              onChange={(e) => setEkCertificate(e.target.value)}
            />
            <div>
              {opButton(
                "importEKCertificate",
                "Import EK Certificate",
                () => {
                  const der = pemToBase64DER(ekCertificate);
                  if (der === null) {
                    toast({
                      title: "Invalid certificate",
                      description: "Paste one PEM certificate (BEGIN/END CERTIFICATE)",
                      variant: "destructive",
                    });
                    return;
                  }
                  void execute(
                    "importEKCertificate",
                    (c) => c.importEKCertificate({ certificate: der, format: "DER" }),
                    true,
                  );
                },
                { disabled: ekCertificate.trim() === "" },
              )}
            </div>
          </div>
          <div className="grid gap-2 max-w-sm">
            <Label htmlFor="tpm-certify-handle">Key handle to certify</Label>
            <Input id="tpm-certify-handle" value={certifyHandle} onChange={(e) => setCertifyHandle(e.target.value)} />
            <Label htmlFor="tpm-certify-key-password">Key password (optional)</Label>
            <Input
              id="tpm-certify-key-password"
              type="password"
              value={certifyKeyPassword}
              onChange={(e) => setCertifyKeyPassword(e.target.value)}
            />
            <div>{opButton("certify", "Certify", runCertify)}</div>
          </div>
          {outcome("createEK")}
          {outcome("deleteEK")}
          {outcome("createSRK")}
          {outcome("deleteSRK")}
          {outcome("importEKCertificate")}
          {outcome("certify")}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Attestation Key and Quotes</CardTitle>
          <CardDescription>
            Create and read the AK; quote PCRs and verify the quote. The server refuses to evict the platform AK (IAK).
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-2 md:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="tpm-ak-handle">AK handle (Delete AK)</Label>
              <Input id="tpm-ak-handle" value={akHandle} onChange={(e) => setAkHandle(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="tpm-quote-pcrs">PCRs to quote</Label>
              <Input id="tpm-quote-pcrs" value={pcrList} onChange={(e) => setPcrList(e.target.value)} />
              <p data-testid="tpm-quote-key" className="text-xs text-muted-foreground">
                Quotes are signed by the platform IAK the server is configured with; the key cannot be chosen here.
              </p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {opButton("createAK", "Create AK", () => void execute("createAK", (c) => c.createAK({ persistent: true }), true))}
            {opButton("getAK", "Get AK", () => void execute("getAK", (c) => c.getAK()))}
            {opButton("deleteAK", "Delete AK", () => askDelete("deleteAK", "Attestation Key", akHandle), { destructive: true })}
            {opButton("quote", "Quote", () => void runQuote())}
            {opButton("verifyQuote", "Verify Quote", runVerify, { disabled: !quoted?.result.quote })}
          </div>
          {outcome("createAK")}
          {outcome("getAK")}
          {outcome("deleteAK")}
          {outcome("quote")}
          {outcome("verifyQuote")}
        </CardContent>
      </Card>

      <Dialog open={confirm !== null} onOpenChange={(o) => { if (!o) setConfirm(null); }}>
        <DialogContent data-testid="tpm-confirm-dialog">
          {confirm && (
            <>
              <DialogHeader>
                <DialogTitle>{confirm.title}</DialogTitle>
                <DialogDescription>{confirm.description}</DialogDescription>
              </DialogHeader>
              <div className="flex justify-end gap-2">
                <Button variant="outline" data-testid="tpm-confirm-cancel" onClick={() => setConfirm(null)}>
                  Cancel
                </Button>
                <Button
                  variant="destructive"
                  data-testid="tpm-confirm-ok"
                  onClick={() => {
                    const { op, call } = confirm;
                    setConfirm(null);
                    void execute(op, call, true);
                  }}
                >
                  Confirm
                </Button>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
