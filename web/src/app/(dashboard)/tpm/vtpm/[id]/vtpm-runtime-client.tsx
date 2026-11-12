"use client";

import * as React from "react";
import { use } from "react";
import { usePathname } from "next/navigation";
import { resolveDynamicId } from "@/utils/dynamic-route";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
} from "@/components/ui";
import { Textarea } from "@/components/ui/textarea";
import { Loader2, Play, Square } from "lucide-react";
import {
  useVTPMRuntime,
  useToast,
  textToBase64,
  base64ToText,
  hexToBase64,
  base64ToHex,
} from "@/hooks";

type PendingAction = "stop" | "extend" | null;

/** Parses "0, 7,16" into PCR indexes; empty input gives undefined. */
function parsePCRList(text: string): number[] | undefined {
  const parts = text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (parts.length === 0) return undefined;
  return parts.map((p) => {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 23) {
      throw new Error(`Invalid PCR index: ${p}`);
    }
    return n;
  });
}

/**
 * vTPM Runtime Page (#1726)
 *
 * Start and stop a bundle's vTPM, quote it, seal and unseal data, and read
 * and extend its PCRs. Stop and PCR extend sit behind a confirm dialog.
 */
export default function VTPMRuntimeClient({ params }: { params: Promise<{ id: string }> }) {
  const resolved = use(params);
  const pathname = usePathname();
  const routeId = resolveDynamicId(resolved, pathname, "vtpm");
  const [bundleId, setBundleId] = React.useState(routeId);
  const { toast } = useToast();
  const rt = useVTPMRuntime(bundleId);

  const [pending, setPending] = React.useState<PendingAction>(null);
  const [quoteNonce, setQuoteNonce] = React.useState("");
  const [quotePCRs, setQuotePCRs] = React.useState("0,7");
  const [sealText, setSealText] = React.useState("");
  const [sealPCRs, setSealPCRs] = React.useState("7");
  const [sealedBlob, setSealedBlob] = React.useState("");
  const [unsealBlob, setUnsealBlob] = React.useState("");
  const [extendIndex, setExtendIndex] = React.useState("16");
  const [extendDigest, setExtendDigest] = React.useState("");
  const [readIndex, setReadIndex] = React.useState("0");

  const fail = (title: string) => (error: Error) =>
    toast({ title, description: error.message, variant: "destructive" });

  const run = async (title: string, fn: () => Promise<unknown>) => {
    try {
      await fn();
    } catch (err) {
      fail(title)(err as Error);
    }
  };

  const handleStart = () =>
    run("Error starting vTPM", async () => {
      await rt.start.mutateAsync(undefined);
    });

  const handleQuote = () =>
    run("Error quoting vTPM", async () => {
      const nonce = quoteNonce || crypto.randomUUID();
      await rt.quote.mutateAsync({ nonce: textToBase64(nonce), pcrs: parsePCRList(quotePCRs) });
    });

  const handleSeal = () =>
    run("Error sealing data", async () => {
      const r = await rt.seal.mutateAsync({ data: textToBase64(sealText), pcrs: parsePCRList(sealPCRs) });
      setSealedBlob(r.sealed_data);
      setUnsealBlob(r.sealed_data);
    });

  const handleUnseal = () =>
    run("Error unsealing data", async () => {
      await rt.unseal.mutateAsync({ sealed_data: unsealBlob.trim() });
    });

  const handleRead = () =>
    run("Error reading PCR", async () => {
      const idx = parsePCRList(readIndex)?.[0] ?? 0;
      await rt.readPCR.mutateAsync(idx);
    });

  const confirmPending = () => {
    const action = pending;
    setPending(null);
    if (action === "stop") {
      void run("Error stopping vTPM", async () => {
        await rt.stop.mutateAsync(undefined);
      });
    } else if (action === "extend") {
      void run("Error extending PCR", async () => {
        const idx = parsePCRList(extendIndex)?.[0] ?? 0;
        await rt.extendPCR.mutateAsync({ pcr_index: idx, data: hexToBase64(extendDigest) });
      });
    }
  };

  const quoteData = rt.quote.data;
  const unsealData = rt.unseal.data;
  const extendData = rt.extendPCR.data;
  const readData = rt.readPCR.data;
  const noBundle = bundleId.trim() === "";

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">vTPM Runtime</h1>
          <p className="text-muted-foreground">
            Start, stop, quote, seal and measure a vTPM bundle
          </p>
        </div>
        <Badge
          data-testid="vtpm-run-state"
          variant={rt.runState === "running" ? "default" : "secondary"}
        >
          {rt.runState === "running" ? "Running" : rt.runState === "stopped" ? "Stopped" : "Unknown"}
        </Badge>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Bundle</CardTitle>
          <CardDescription>
            The running state comes from the last start or stop result.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="vtpm-bundle-id">Bundle ID</Label>
            <Input
              id="vtpm-bundle-id"
              value={bundleId}
              onChange={(e) => setBundleId(e.target.value)}
              placeholder="Bundle identifier"
            />
          </div>
          <div className="flex gap-2">
            <Button onClick={handleStart} disabled={noBundle || rt.start.isLoading}>
              {rt.start.isLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Play className="mr-2 h-4 w-4" />}
              Start vTPM
            </Button>
            <Button
              variant="destructive"
              onClick={() => setPending("stop")}
              disabled={noBundle || rt.stop.isLoading}
            >
              <Square className="mr-2 h-4 w-4" />
              Stop vTPM
            </Button>
          </div>
          {rt.start.data?.socket_path && (
            <p className="text-sm text-muted-foreground">
              Socket: <code data-testid="vtpm-socket">{rt.start.data.socket_path}</code>
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Quote</CardTitle>
          <CardDescription>Signed PCR quote over a nonce</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="vtpm-quote-nonce">Nonce</Label>
              <Input id="vtpm-quote-nonce" value={quoteNonce} onChange={(e) => setQuoteNonce(e.target.value)} placeholder="Random when empty" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="vtpm-quote-pcrs">Quote PCRs</Label>
              <Input id="vtpm-quote-pcrs" value={quotePCRs} onChange={(e) => setQuotePCRs(e.target.value)} />
            </div>
          </div>
          <Button onClick={handleQuote} disabled={noBundle || rt.quote.isLoading}>Quote</Button>
          {quoteData && (
            <div className="space-y-2" data-testid="vtpm-quote-result">
              <p className="text-sm">Hash algorithm: {quoteData.hash_algorithm}</p>
              <Label>Quote (base64)</Label>
              <Textarea readOnly className="font-mono text-xs" value={quoteData.quote} />
              <Label>Signature (base64)</Label>
              <Textarea readOnly className="font-mono text-xs" value={quoteData.signature} />
              {Object.entries(quoteData.pcr_values ?? {}).map(([idx, v]) => (
                <p key={idx} className="font-mono text-xs">PCR {idx}: {base64ToHex(v)}</p>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Seal / Unseal</CardTitle>
          <CardDescription>Bind data to the bundle&apos;s PCR state</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="vtpm-seal-data">Data to seal</Label>
              <Textarea id="vtpm-seal-data" value={sealText} onChange={(e) => setSealText(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="vtpm-seal-pcrs">Seal PCRs</Label>
              <Input id="vtpm-seal-pcrs" value={sealPCRs} onChange={(e) => setSealPCRs(e.target.value)} />
            </div>
          </div>
          <Button onClick={handleSeal} disabled={noBundle || !sealText || rt.seal.isLoading}>Seal</Button>
          {sealedBlob && (
            <div className="space-y-2">
              <Label>Sealed blob (base64)</Label>
              <Textarea data-testid="vtpm-sealed-blob" readOnly className="font-mono text-xs" value={sealedBlob} />
            </div>
          )}
          <div className="space-y-2">
            <Label htmlFor="vtpm-unseal-blob">Sealed blob to unseal</Label>
            <Textarea id="vtpm-unseal-blob" className="font-mono text-xs" value={unsealBlob} onChange={(e) => setUnsealBlob(e.target.value)} />
          </div>
          <Button onClick={handleUnseal} disabled={noBundle || !unsealBlob || rt.unseal.isLoading}>Unseal</Button>
          {unsealData && (
            <p className="text-sm" data-testid="vtpm-unsealed-data">
              Unsealed: <code>{base64ToText(unsealData.data)}</code>
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>PCRs</CardTitle>
          <CardDescription>Read and extend the bundle&apos;s PCRs</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-end gap-2">
            <div className="space-y-2">
              <Label htmlFor="vtpm-read-index">Read PCR index</Label>
              <Input id="vtpm-read-index" value={readIndex} onChange={(e) => setReadIndex(e.target.value)} />
            </div>
            <Button onClick={handleRead} disabled={noBundle || rt.readPCR.isLoading}>Read PCR</Button>
          </div>
          {readData && (
            <p className="font-mono text-xs" data-testid="vtpm-pcr-value">
              PCR {readData.pcr_index}: {base64ToHex(readData.value)}
            </p>
          )}
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="vtpm-extend-index">Extend PCR index</Label>
              <Input id="vtpm-extend-index" value={extendIndex} onChange={(e) => setExtendIndex(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="vtpm-extend-digest">Digest (hex)</Label>
              <Input id="vtpm-extend-digest" value={extendDigest} onChange={(e) => setExtendDigest(e.target.value)} />
            </div>
          </div>
          <Button
            variant="destructive"
            onClick={() => setPending("extend")}
            disabled={noBundle || !extendDigest || rt.extendPCR.isLoading}
          >
            Extend PCR
          </Button>
          {extendData?.extended && (
            <p className="text-sm" data-testid="vtpm-extend-result">
              PCR {extendData.pcr_index} extended
            </p>
          )}
        </CardContent>
      </Card>

      <Dialog open={pending !== null} onOpenChange={(open) => !open && setPending(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{pending === "stop" ? "Stop this vTPM?" : "Extend this PCR?"}</DialogTitle>
            <DialogDescription>
              {pending === "stop"
                ? "The guest loses its TPM until the vTPM starts again."
                : "A PCR extend cannot be undone until the vTPM restarts."}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPending(null)}>Cancel</Button>
            <Button variant="destructive" onClick={confirmPending}>Confirm</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
