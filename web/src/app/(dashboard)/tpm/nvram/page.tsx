"use client";

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
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  RefreshCw,
  HardDrive,
  AlertCircle,
  Database,
  Loader2,
  Eye,
  Plus,
  Trash2,
  PenLine,
  ShieldAlert,
  Copy,
} from "lucide-react";
import { useApi, useTPM, useToast } from "@/hooks";
import type { NVIndex, TPMCapability } from "trusted-platform-sdk";
import { errorMessage } from "@/utils/errors";


const formatHandle = (h: number): string =>
  "0x" + h.toString(16).toUpperCase().padStart(8, "0");

const formatBytes = (bytes: number): string => {
  if (!bytes) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const parseHandle = (raw: string): number | null => {
  const clean = raw.trim().toLowerCase();
  if (!clean) return null;
  const base = clean.startsWith("0x") ? 16 : 10;
  const n = parseInt(clean.startsWith("0x") ? clean.slice(2) : clean, base);
  return Number.isNaN(n) ? null : n;
};

const hexBytes = (b64: string): string => {
  if (!b64) return "";
  try {
    const bin = atob(b64);
    let out = "";
    for (let i = 0; i < bin.length; i++) {
      out += bin.charCodeAt(i).toString(16).padStart(2, "0");
      if ((i + 1) % 16 === 0) out += "\n";
      else if ((i + 1) % 2 === 0) out += " ";
    }
    return out.trim();
  } catch {
    return b64;
  }
};

const asciiOf = (b64: string): string => {
  if (!b64) return "";
  try {
    const bin = atob(b64);
    let s = "";
    for (let i = 0; i < bin.length; i++) {
      const c = bin.charCodeAt(i);
      s += c >= 32 && c <= 126 ? String.fromCharCode(c) : ".";
    }
    return s;
  } catch {
    return "";
  }
};

// The SDK resolves a failed call with `{ error }` rather than rejecting;
// raise it so each operation reports the failure instead of a success (#1824).
const raiseError = <T extends { error?: { message?: string } }>(resp: T): T => {
  if (resp?.error) throw new Error(resp.error.message || "Request failed");
  return resp;
};

// The write payload is the UTF-8 bytes of the text; btoa alone throws on
// any character above U+00FF (#1824).
const utf8Bytes = (text: string): Uint8Array => new TextEncoder().encode(text);

const bytesToBase64 = (bytes: Uint8Array): string => {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
};

/**
 * TPM NVRAM Management Page
 *
 * Surfaces the TPM's NV index inventory directly from
 * /api/v1/tpm/info (TPM2_GetCapability(TPM_CAP_HANDLES @
 * 0x01000000), populated by xkms's FixedProperties() and the
 * server-side TPMService.Info handler) and exposes the four core
 * NV operations through the TPM SDK:
 *
 *   - Read   → tpm.readNVRAM({index, size})
 *   - Define → tpm.defineNVRAM({index, size, attributes})
 *   - Write  → tpm.writeNVRAM({index, data})
 *   - Undefine → tpm.undefineNVRAM({index})
 *
 * No raw fetch() calls — every operation goes through the SDK so
 * the transport remains swappable from app config.
 */
export default function TPMNVRAMPage() {
  const { toast } = useToast();
  const tpm = useTPM();

  const {
    data: tpmInfo,
    isLoading: loading,
    error,
    refetch,
  } = useApi(
    () => tpm.getInfo(),
    [],
    {
      onError: (err) => {
        toast({
          title: "Error loading TPM info",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  const findCapability = (caps: TPMCapability[] | undefined, name: string) =>
    caps?.find((c) => c.name === name);

  const indexes: NVIndex[] = React.useMemo(() => tpmInfo?.nvIndexes ?? [], [tpmInfo]);

  const stats = React.useMemo(() => {
    const caps = tpmInfo?.capabilities;
    return {
      defined: parseInt(findCapability(caps, "nvIndexesDefined")?.value || "0", 10),
      max: parseInt(findCapability(caps, "nvIndexesMax")?.value || "0", 10),
      bufferMax: parseInt(findCapability(caps, "nvBufferMax")?.value || "0", 10),
    };
  }, [tpmInfo]);

  // -----------------------------------------------------------
  // Read dialog
  // -----------------------------------------------------------
  const [readState, setReadState] = React.useState<{
    open: boolean;
    handle: number;
    size: number;
    password: string;
    data: string | null;
    loading: boolean;
    err: string | null;
  }>({ open: false, handle: 0, size: 0, password: "", data: null, loading: false, err: null });

  const openRead = (ix: NVIndex) => {
    setReadState({
      open: true,
      handle: ix.handle,
      size: ix.size,
      password: "",
      data: null,
      loading: false,
      err: null,
    });
  };

  const doRead = async () => {
    setReadState((s) => ({ ...s, loading: true, err: null, data: null }));
    try {
      const resp = raiseError(
        await tpm.readNVRAM({
          index: readState.handle,
          size: readState.size,
          ...(readState.password ? { password: readState.password } : {}),
        })
      );
      setReadState((s) => ({ ...s, loading: false, data: resp.data?.data ?? "" }));
    } catch (e) {
      setReadState((s) => ({ ...s, loading: false, err: errorMessage(e, "Read failed") }));
    }
  };

  // -----------------------------------------------------------
  // Define dialog
  // -----------------------------------------------------------
  const [defineState, setDefineState] = React.useState({
    open: false,
    handleStr: "0x1500001",
    size: 32,
    password: "",
    parentPassword: "",
    attrs: ["AUTHREAD", "AUTHWRITE"] as string[],
    loading: false,
    err: null as string | null,
  });

  const doDefine = async () => {
    const handle = parseHandle(defineState.handleStr);
    if (handle === null) {
      setDefineState((s) => ({ ...s, err: "invalid handle (use 0x… or decimal)" }));
      return;
    }
    setDefineState((s) => ({ ...s, loading: true, err: null }));
    try {
      raiseError(
        await tpm.defineNVRAM({
          index: handle,
          size: defineState.size,
          attributes: defineState.attrs,
          ...(defineState.password ? { password: defineState.password } : {}),
          ...(defineState.parentPassword ? { parentPassword: defineState.parentPassword } : {}),
        })
      );
      toast({ title: "NV index defined", description: formatHandle(handle), variant: "success" });
      setDefineState((s) => ({ ...s, open: false, loading: false }));
      refetch();
    } catch (e) {
      setDefineState((s) => ({ ...s, loading: false, err: errorMessage(e, "Define failed") }));
    }
  };

  // -----------------------------------------------------------
  // Write dialog
  // -----------------------------------------------------------
  const [writeState, setWriteState] = React.useState<{
    open: boolean;
    handle: number;
    size: number;
    text: string;
    password: string;
    loading: boolean;
    err: string | null;
  }>({ open: false, handle: 0, size: 0, text: "", password: "", loading: false, err: null });

  const openWrite = (ix: NVIndex) => {
    setWriteState({
      open: true,
      handle: ix.handle,
      size: ix.size,
      text: "",
      password: "",
      loading: false,
      err: null,
    });
  };

  const doWrite = async () => {
    setWriteState((s) => ({ ...s, loading: true, err: null }));
    try {
      // Encode as base64 — proto bytes field; protojson decodes it
      // server-side. Truncate to the index size if the operator
      // pasted more bytes than the index can hold.
      const bin = utf8Bytes(writeState.text).slice(0, writeState.size);
      const b64 = bytesToBase64(bin);
      raiseError(
        await tpm.writeNVRAM({
          index: writeState.handle,
          data: b64,
          ...(writeState.password ? { password: writeState.password } : {}),
        })
      );
      toast({
        title: "NV index written",
        description: `${bin.length} bytes → ${formatHandle(writeState.handle)}`,
        variant: "success",
      });
      setWriteState((s) => ({ ...s, open: false, loading: false }));
    } catch (e) {
      setWriteState((s) => ({ ...s, loading: false, err: errorMessage(e, "Write failed") }));
    }
  };

  // -----------------------------------------------------------
  // Undefine
  // -----------------------------------------------------------
  const [undefineBusy, setUndefineBusy] = React.useState<number | null>(null);

  const doUndefine = async (ix: NVIndex) => {
    if (!window.confirm(`Permanently delete NV index ${formatHandle(ix.handle)}? This cannot be undone.`)) {
      return;
    }
    setUndefineBusy(ix.handle);
    try {
      raiseError(await tpm.undefineNVRAM({ index: ix.handle }));
      toast({ title: "NV index undefined", description: formatHandle(ix.handle), variant: "success" });
      refetch();
    } catch (e) {
      toast({ title: "Undefine failed", description: errorMessage(e, "Unknown error"), variant: "destructive" });
    } finally {
      setUndefineBusy(null);
    }
  };

  const copyToClipboard = (s: string) => {
    navigator.clipboard.writeText(s);
    toast({ title: "Copied", variant: "success" });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">NVRAM Management</h1>
          <p className="text-muted-foreground">
            Define, read, write, and undefine TPM NV indices
          </p>
        </div>
        <div className="flex gap-2">
          <Button onClick={() => setDefineState((s) => ({ ...s, open: true, err: null }))}>
            <Plus className="mr-2 h-4 w-4" /> Define Index
          </Button>
          <Button variant="outline" onClick={() => refetch()} disabled={loading}>
            <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-4 bg-destructive/10 border border-destructive rounded-lg">
          <AlertCircle className="h-4 w-4 text-destructive" />
          <div>
            <p className="font-medium text-destructive">Error</p>
            <p className="text-sm text-destructive">{error.message}</p>
          </div>
        </div>
      )}

      {loading && !tpmInfo && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          <span className="ml-2 text-muted-foreground">Loading NVRAM info…</span>
        </div>
      )}

      {tpmInfo && (
        <>
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Indexes Defined</CardTitle>
                <Database className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {stats.defined}
                  <span className="text-base font-normal text-muted-foreground"> / {stats.max}</span>
                </div>
                <p className="text-xs text-muted-foreground">Active NV indices</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">NV Buffer Max</CardTitle>
                <HardDrive className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{formatBytes(stats.bufferMax)}</div>
                <p className="text-xs text-muted-foreground">Largest NV write per call</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Size</CardTitle>
                <HardDrive className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {formatBytes(indexes.reduce((sum, i) => sum + (i.size || 0), 0))}
                </div>
                <p className="text-xs text-muted-foreground">Sum of all NV index payload sizes</p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Defined NV Indices</CardTitle>
              <CardDescription>
                Persistent NV handles enumerated via TPM2_GetCapability(TPM_CAP_HANDLES @ 0x01000000)
              </CardDescription>
            </CardHeader>
            <CardContent>
              {indexes.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Database className="h-10 w-10 mx-auto mb-2 opacity-50" />
                  <p>No NV indices defined.</p>
                  <p className="text-xs mt-1">Click <strong>Define Index</strong> above to create one.</p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Handle</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Size</TableHead>
                      <TableHead>Auth</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {indexes.map((ix) => (
                      <TableRow key={ix.handle}>
                        <TableCell>
                          <code className="font-mono text-xs">{formatHandle(ix.handle)}</code>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{ix.type}</Badge>
                        </TableCell>
                        <TableCell>{formatBytes(ix.size)}</TableCell>
                        <TableCell>
                          <div className="flex gap-1 flex-wrap">
                            {ix.authRead && <Badge variant="secondary" className="text-xs">R</Badge>}
                            {ix.authWrite && <Badge variant="secondary" className="text-xs">W</Badge>}
                            {!ix.authRead && !ix.authWrite && (
                              <span className="text-xs text-muted-foreground">policy</span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-1">
                            <Button
                              variant="ghost"
                              size="icon"
                              title="Read"
                              onClick={() => openRead(ix)}
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              title="Write"
                              onClick={() => openWrite(ix)}
                            >
                              <PenLine className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              title="Undefine"
                              disabled={undefineBusy === ix.handle}
                              onClick={() => doUndefine(ix)}
                            >
                              {undefineBusy === ix.handle ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                <Trash2 className="h-4 w-4 text-destructive" />
                              )}
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </>
      )}

      {/* Read dialog */}
      <Dialog open={readState.open} onOpenChange={(o) => setReadState((s) => ({ ...s, open: o }))}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Eye className="h-4 w-4" />
              Read NV Index {formatHandle(readState.handle)}
            </DialogTitle>
            <DialogDescription>
              Reads up to {readState.size} bytes from the index. Auth password is optional unless the index requires one.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label>Auth password (optional)</Label>
              <Input
                type="password"
                value={readState.password}
                onChange={(e) => setReadState((s) => ({ ...s, password: e.target.value }))}
                placeholder="leave blank if not required"
              />
            </div>
            {readState.err && (
              <div className="flex items-center gap-2 p-2 bg-destructive/10 border border-destructive rounded text-xs">
                <ShieldAlert className="h-4 w-4 text-destructive" />
                <span className="text-destructive">{readState.err}</span>
              </div>
            )}
            {readState.data !== null && (
              <div className="space-y-2">
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <Label className="text-xs">Hex</Label>
                    <Button variant="ghost" size="sm" onClick={() => copyToClipboard(hexBytes(readState.data || ""))}>
                      <Copy className="h-3 w-3 mr-1" /> Copy
                    </Button>
                  </div>
                  <pre className="bg-muted p-2 rounded text-xs font-mono whitespace-pre-wrap break-all max-h-32 overflow-y-auto">
                    {hexBytes(readState.data || "") || "(empty)"}
                  </pre>
                </div>
                <div>
                  <Label className="text-xs">ASCII</Label>
                  <pre className="bg-muted p-2 rounded text-xs font-mono whitespace-pre-wrap break-all max-h-20 overflow-y-auto">
                    {asciiOf(readState.data || "") || "(no printable bytes)"}
                  </pre>
                </div>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setReadState((s) => ({ ...s, open: false }))}>
              Close
            </Button>
            <Button onClick={doRead} disabled={readState.loading}>
              {readState.loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Eye className="h-4 w-4 mr-2" />}
              Read
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Define dialog */}
      <Dialog open={defineState.open} onOpenChange={(o) => setDefineState((s) => ({ ...s, open: o }))}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Plus className="h-4 w-4" /> Define New NV Index
            </DialogTitle>
            <DialogDescription>
              Allocates a persistent NV index. Handles must be in the
              0x01000000–0x01FFFFFF range. Common ranges:{" "}
              <code>0x1400000+</code> (TCG-reserved owner) and <code>0x1500000+</code> (vendor/tenant).
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label>Handle (hex 0x… or decimal)</Label>
              <Input
                value={defineState.handleStr}
                onChange={(e) => setDefineState((s) => ({ ...s, handleStr: e.target.value }))}
                placeholder="0x1500001"
                className="font-mono"
              />
            </div>
            <div>
              <Label>Size (bytes)</Label>
              <Input
                type="number"
                min={1}
                max={2048}
                value={defineState.size}
                onChange={(e) => setDefineState((s) => ({ ...s, size: parseInt(e.target.value, 10) || 0 }))}
              />
            </div>
            <div>
              <Label>Index auth password (optional)</Label>
              <Input
                type="password"
                value={defineState.password}
                onChange={(e) => setDefineState((s) => ({ ...s, password: e.target.value }))}
                placeholder="UserAuth value for the new index"
              />
            </div>
            <div>
              <Label>Owner-hierarchy password (if locked)</Label>
              <Input
                type="password"
                value={defineState.parentPassword}
                onChange={(e) => setDefineState((s) => ({ ...s, parentPassword: e.target.value }))}
                placeholder="leave blank for unlocked TPMs"
              />
              <p className="text-xs text-muted-foreground mt-1">
                NV Define routes through TPM_RH_OWNER. Required when the
                platform&apos;s owner hierarchy was provisioned with auth set.
              </p>
            </div>
            <div>
              <Label>Attributes</Label>
              <div className="flex flex-wrap gap-1 mt-1">
                {["AUTHREAD", "AUTHWRITE", "OWNERREAD", "OWNERWRITE", "PPREAD", "PPWRITE", "WRITELOCK", "READLOCK", "NO_DA"].map((a) => {
                  const on = defineState.attrs.includes(a);
                  return (
                    <Badge
                      key={a}
                      variant={on ? "default" : "outline"}
                      className="cursor-pointer"
                      onClick={() =>
                        setDefineState((s) => ({
                          ...s,
                          attrs: on ? s.attrs.filter((x) => x !== a) : [...s.attrs, a],
                        }))
                      }
                    >
                      {a}
                    </Badge>
                  );
                })}
              </div>
            </div>
            {defineState.err && (
              <div className="flex items-center gap-2 p-2 bg-destructive/10 border border-destructive rounded text-xs">
                <ShieldAlert className="h-4 w-4 text-destructive" />
                <span className="text-destructive">{defineState.err}</span>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDefineState((s) => ({ ...s, open: false }))}>
              Cancel
            </Button>
            <Button onClick={doDefine} disabled={defineState.loading}>
              {defineState.loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Plus className="h-4 w-4 mr-2" />}
              Define
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Write dialog */}
      <Dialog open={writeState.open} onOpenChange={(o) => setWriteState((s) => ({ ...s, open: o }))}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <PenLine className="h-4 w-4" />
              Write NV Index {formatHandle(writeState.handle)}
            </DialogTitle>
            <DialogDescription>
              Up to {writeState.size} bytes will be written. Excess input is truncated.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label>Data (UTF-8 text)</Label>
              <Textarea
                rows={5}
                value={writeState.text}
                onChange={(e) => setWriteState((s) => ({ ...s, text: e.target.value }))}
                className="font-mono text-xs"
                placeholder="payload bytes…"
              />
              <p className="text-xs text-muted-foreground mt-1">
                {utf8Bytes(writeState.text).length} / {writeState.size} bytes
              </p>
            </div>
            <div>
              <Label>Auth password (optional)</Label>
              <Input
                type="password"
                value={writeState.password}
                onChange={(e) => setWriteState((s) => ({ ...s, password: e.target.value }))}
              />
            </div>
            {writeState.err && (
              <div className="flex items-center gap-2 p-2 bg-destructive/10 border border-destructive rounded text-xs">
                <ShieldAlert className="h-4 w-4 text-destructive" />
                <span className="text-destructive">{writeState.err}</span>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setWriteState((s) => ({ ...s, open: false }))}>
              Cancel
            </Button>
            <Button onClick={doWrite} disabled={writeState.loading || !writeState.text}>
              {writeState.loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <PenLine className="h-4 w-4 mr-2" />}
              Write
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Card>
        <CardHeader>
          <CardTitle>NVRAM Reference</CardTitle>
          <CardDescription>Common index ranges and access controls</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2 text-sm text-muted-foreground">
            <div>
              <h4 className="font-medium text-foreground mb-2">Reserved Ranges</h4>
              <ul className="list-disc list-inside space-y-1">
                <li><code>0x1c00000–0x1c0FFFF</code> &mdash; EK Cert / EK templates (TCG-reserved)</li>
                <li><code>0x1400000+</code> &mdash; Owner-policy reserved</li>
                <li><code>0x1500000+</code> &mdash; Vendor / tenant indices</li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium text-foreground mb-2">Index Types</h4>
              <ul className="list-disc list-inside space-y-1">
                <li><strong>ordinary</strong>: general-purpose payload</li>
                <li><strong>counter</strong>: monotonic, write increments</li>
                <li><strong>extend</strong>: PCR-style hash extension</li>
                <li><strong>bits</strong>: SET-only bit field</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
