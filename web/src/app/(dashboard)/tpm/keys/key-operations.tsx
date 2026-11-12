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
import { useTPMKeyOperations, useToast } from "@/hooks";
import type { OperationResponse, TPMClient, TPMKeyOperation } from "@/hooks";

/** Persistent handles of the TCG key inventory, the forms' defaults. */
const DEFAULT_EK_HANDLE = "0x81010001";
const DEFAULT_SRK_HANDLE = "0x81000001";
const DEFAULT_AK_HANDLE = "0x81010002";

/** parseHandle reads a decimal or 0x-prefixed hex handle; NaN when neither. */
export function parseHandle(value: string): number {
  const trimmed = value.trim();
  if (trimmed === "") return Number.NaN;
  return Number(trimmed);
}

/** parsePCRList reads "0, 1,7" as [0, 1, 7], dropping what is not an index. */
export function parsePCRList(value: string): number[] {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => /^\d+$/.test(s))
    .map(Number)
    .filter((n) => n >= 0 && n <= 23);
}

/** randomNonce returns 32 random bytes, base64. */
function randomNonce(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
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
export function TPMKeyOperations({ onChanged }: { onChanged?: () => void }) {
  const { toast } = useToast();
  const { pending, results, errors, run } = useTPMKeyOperations();

  const [ownerPassword, setOwnerPassword] = React.useState("");
  const [ekHandle, setEkHandle] = React.useState(DEFAULT_EK_HANDLE);
  const [srkHandle, setSrkHandle] = React.useState(DEFAULT_SRK_HANDLE);
  const [akHandle, setAkHandle] = React.useState(DEFAULT_AK_HANDLE);
  const [ekCertificate, setEkCertificate] = React.useState("");
  const [pcrList, setPcrList] = React.useState("0,1,7");
  const [quoteNonce, setQuoteNonce] = React.useState("");
  const [certifyHandle, setCertifyHandle] = React.useState(DEFAULT_SRK_HANDLE);
  const [confirm, setConfirm] = React.useState<PendingConfirm | null>(null);

  const execute = React.useCallback(
    async (op: TPMKeyOperation, call: (client: TPMClient) => Promise<OperationResponse>, mutates = false) => {
      const data = await run(op, call);
      if (data !== null) {
        toast({ title: "Done", description: `${op} succeeded`, variant: "success" });
        if (mutates) onChanged?.();
      }
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
      description: `The ${label} at handle ${raw} is evicted from the TPM. This cannot be undone.`,
      call,
    });
  };

  const runQuote = () => {
    const handle = handleOrToast("quote", akHandle);
    if (handle === null) return;
    const nonce = randomNonce();
    setQuoteNonce(nonce);
    void execute("quote", (c) => c.quote({ akHandle: handle, pcrIndices: parsePCRList(pcrList), pcrBank: "SHA256", nonce }));
  };

  const lastQuote = results.quote as QuoteResult | undefined;
  const runVerify = () => {
    if (!lastQuote?.quote || !lastQuote.signature) return;
    void execute("verifyQuote", (c) =>
      c.verifyQuote({
        quote: lastQuote.quote ?? "",
        signature: lastQuote.signature ?? "",
        signatureAlgorithm: lastQuote.signatureAlgorithm,
        channelBinding: lastQuote.channelBinding,
        nonce: quoteNonce,
      }),
    );
  };

  const runCertify = () => {
    const handle = handleOrToast("certify", certifyHandle);
    if (handle === null) return;
    void execute("certify", (c) => c.certify({ keyHandle: handle, nonce: randomNonce() }));
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
                () =>
                  void execute(
                    "importEKCertificate",
                    (c) => c.importEKCertificate({ certificate: btoa(ekCertificate.trim()), format: "PEM" }),
                    true,
                  ),
                { disabled: ekCertificate.trim() === "" },
              )}
            </div>
          </div>
          <div className="grid gap-2 max-w-sm">
            <Label htmlFor="tpm-certify-handle">Key handle to certify</Label>
            <Input id="tpm-certify-handle" value={certifyHandle} onChange={(e) => setCertifyHandle(e.target.value)} />
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
          <CardDescription>Create, read and delete the AK; quote PCRs and verify the quote</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-2 md:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="tpm-ak-handle">AK handle</Label>
              <Input id="tpm-ak-handle" value={akHandle} onChange={(e) => setAkHandle(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="tpm-quote-pcrs">PCRs to quote</Label>
              <Input id="tpm-quote-pcrs" value={pcrList} onChange={(e) => setPcrList(e.target.value)} />
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {opButton("createAK", "Create AK", () => void execute("createAK", (c) => c.createAK({ persistent: true }), true))}
            {opButton("getAK", "Get AK", () => void execute("getAK", (c) => c.getAK()))}
            {opButton("deleteAK", "Delete AK", () => askDelete("deleteAK", "Attestation Key", akHandle), { destructive: true })}
            {opButton("quote", "Quote", runQuote)}
            {opButton("verifyQuote", "Verify Quote", runVerify, { disabled: !lastQuote?.quote })}
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
