"use client";

import * as React from "react";
import { Download, RefreshCw, Loader2, Camera, RotateCcw, Trash2 } from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";

interface ConfigSource {
  path: string;
  format: string;
}

interface ConfigTree {
  sources: ConfigSource[];
  tree: Record<string, unknown>;
  generated_at: string;
  redacted_keys?: string[];
  secrets_hidden: boolean;
}

interface SnapshotSummary {
  id: string;
  created_at: string;
  reason?: string;
  actor?: string;
  source_path?: string;
  size_bytes: number;
}

/**
 * Platform Configuration page.
 *
 * Reads /api/v1/platform/config — the live merged Viper config tree
 * (defaults + overrides + env), with secret values replaced by ••••.
 * Sources lists every config file that contributed, with format,
 * so operators can see at a glance what the daemon actually loaded.
 *
 * A "Reload" button calls POST /api/v1/platform/config/reload which
 * tells platformd to re-read the file without restart; the page then
 * refreshes the tree.
 *
 * This replaces the static "Coming Soon" stub that lied about the
 * config service being in development — the underlying viper config
 * has always been queryable; the surface just wasn't wired up.
 */
export default function ConfigPage() {
  const { toast } = useToast();
  const [config, setConfig] = React.useState<ConfigTree | null>(null);
  const [isLoading, setIsLoading] = React.useState(true);
  const [isReloading, setIsReloading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [filter, setFilter] = React.useState("");
  const [snapshots, setSnapshots] = React.useState<SnapshotSummary[]>([]);
  const [isCapturing, setIsCapturing] = React.useState(false);

  // JWT auth runs through HTTP-only cookies set at WebAuthn login;
  // browsers attach them automatically when credentials: "include".
  const fetchOpts: RequestInit = React.useMemo(
    () => ({
      credentials: "include",
      headers: { Accept: "application/json" },
    }),
    [],
  );

  const fetchConfig = React.useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/v1/platform/config", fetchOpts);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      }
      const body = await res.json();
      const tree: ConfigTree =
        body.payload && typeof body.payload === "object"
          ? (body.payload as ConfigTree)
          : (body as ConfigTree);
      setConfig(tree);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  }, [fetchOpts]);

  const fetchSnapshots = React.useCallback(async () => {
    try {
      const res = await fetch("/api/v1/platform/config/snapshots", fetchOpts);
      if (!res.ok) return; // 503 when store isn't configured — non-fatal
      const body = await res.json();
      const list: SnapshotSummary[] =
        body.payload?.snapshots ?? body.snapshots ?? [];
      setSnapshots(list);
    } catch {
      // snapshot listing is best-effort; failure shouldn't block the page
    }
  }, [fetchOpts]);

  React.useEffect(() => {
    void fetchConfig();
    void fetchSnapshots();
  }, [fetchConfig, fetchSnapshots]);

  const handleCaptureSnapshot = async () => {
    setIsCapturing(true);
    try {
      const reason =
        window.prompt("Snapshot reason (optional)", "manual") ?? "manual";
      const res = await fetch("/api/v1/platform/config/snapshots", {
        ...fetchOpts,
        method: "POST",
        headers: { ...fetchOpts.headers, "Content-Type": "application/json" },
        body: JSON.stringify({ reason }),
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      }
      const body = await res.json();
      const id = body.payload?.id ?? body.id;
      toast({ title: "Snapshot captured", description: id });
      await fetchSnapshots();
    } catch (e: unknown) {
      toast({
        title: "Snapshot failed",
        description: e instanceof Error ? e.message : String(e),
        variant: "destructive",
      });
    } finally {
      setIsCapturing(false);
    }
  };

  const handleRollback = async (snap: SnapshotSummary) => {
    if (
      !window.confirm(
        `Roll back configuration to snapshot ${snap.id}? The current state will be captured as a new snapshot so this is reversible.`,
      )
    )
      return;
    try {
      const res = await fetch(
        `/api/v1/platform/config/snapshots/${encodeURIComponent(snap.id)}/rollback`,
        { ...fetchOpts, method: "POST" },
      );
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      }
      const body = await res.json();
      const pre = body.payload?.pre_rollback_snapshot ?? "";
      toast({
        title: "Rolled back",
        description: pre ? `Pre-rollback snapshot: ${pre}` : "OK",
      });
      await fetchConfig();
      await fetchSnapshots();
    } catch (e: unknown) {
      toast({
        title: "Rollback failed",
        description: e instanceof Error ? e.message : String(e),
        variant: "destructive",
      });
    }
  };

  const handleDeleteSnapshot = async (snap: SnapshotSummary) => {
    if (!window.confirm(`Delete snapshot ${snap.id}?`)) return;
    try {
      const res = await fetch(
        `/api/v1/platform/config/snapshots/${encodeURIComponent(snap.id)}`,
        { ...fetchOpts, method: "DELETE" },
      );
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      }
      toast({ title: "Snapshot deleted", description: snap.id });
      await fetchSnapshots();
    } catch (e: unknown) {
      toast({
        title: "Delete failed",
        description: e instanceof Error ? e.message : String(e),
        variant: "destructive",
      });
    }
  };

  const handleReload = async () => {
    setIsReloading(true);
    try {
      const res = await fetch("/api/v1/platform/config/reload", {
        ...fetchOpts,
        method: "POST",
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      }
      const body = await res.json();
      const sections =
        body.payload?.sections ?? body.sections ?? [];
      const snapID = body.payload?.pre_reload_snapshot ?? "";
      toast({
        title: "Configuration reloaded",
        description: snapID
          ? `Refreshed ${sections.length} sections. Pre-reload snapshot: ${snapID}`
          : `Refreshed ${sections.length} top-level sections`,
      });
      await fetchConfig();
      await fetchSnapshots();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      toast({
        title: "Reload failed",
        description: msg,
        variant: "destructive",
      });
    } finally {
      setIsReloading(false);
    }
  };

  const handleDownload = () => {
    if (!config) return;
    const blob = new Blob([JSON.stringify(config.tree, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "platform-config.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Configuration"
          description="Live merged platform configuration"
        />
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Configuration"
        description="Live merged platform configuration"
      >
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleCaptureSnapshot}
            disabled={isCapturing}
          >
            {isCapturing ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Camera className="h-4 w-4 mr-2" />
            )}
            Snapshot
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleReload}
            disabled={isReloading}
          >
            {isReloading ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4 mr-2" />
            )}
            Reload
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleDownload}
            disabled={!config}
          >
            <Download className="h-4 w-4 mr-2" />
            Download
          </Button>
        </div>
      </PageHeader>

      {error && (
        <Card className="border-destructive/50">
          <CardContent className="pt-6">
            <p className="text-sm text-destructive">
              Failed to load configuration: {error}
            </p>
          </CardContent>
        </Card>
      )}

      {config && (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Sources</CardTitle>
              <CardDescription>
                Files merged to produce the live configuration
              </CardDescription>
            </CardHeader>
            <CardContent>
              {config.sources.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No config file is currently loaded.
                </p>
              ) : (
                <ul className="space-y-1 text-sm font-mono">
                  {config.sources.map((src, i) => (
                    <li key={i} className="flex items-center justify-between">
                      <span>{src.path}</span>
                      <Badge variant="secondary">{src.format}</Badge>
                    </li>
                  ))}
                </ul>
              )}
              <div className="mt-4 flex items-center gap-2 text-xs text-muted-foreground">
                <span>
                  Generated{" "}
                  {new Date(config.generated_at).toLocaleString()}
                </span>
                {config.secrets_hidden && (
                  <Badge variant="outline">
                    {config.redacted_keys?.length ?? 0} secret
                    {(config.redacted_keys?.length ?? 0) === 1 ? "" : "s"}{" "}
                    redacted
                  </Badge>
                )}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Snapshots</CardTitle>
              <CardDescription>
                Pre-reload snapshots are captured automatically. Click
                Rollback to restore a previous configuration — the
                rollback itself is reversible.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {snapshots.length === 0 ? (
                <p className="text-sm text-muted-foreground py-4">
                  No snapshots yet. The next reload (or a manual
                  Snapshot click) will capture one.
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>ID</TableHead>
                      <TableHead>When</TableHead>
                      <TableHead>Reason</TableHead>
                      <TableHead>Actor</TableHead>
                      <TableHead className="text-right">Size</TableHead>
                      <TableHead className="w-32" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {snapshots.map((s) => (
                      <TableRow key={s.id}>
                        <TableCell className="font-mono text-xs">
                          {s.id}
                        </TableCell>
                        <TableCell className="text-xs">
                          {new Date(s.created_at).toLocaleString()}
                        </TableCell>
                        <TableCell className="text-xs">
                          {s.reason ?? "—"}
                        </TableCell>
                        <TableCell className="text-xs">
                          {s.actor ?? "—"}
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs">
                          {s.size_bytes}
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-1 justify-end">
                            <Button
                              variant="ghost"
                              size="icon"
                              title="Roll back to this snapshot"
                              onClick={() => handleRollback(s)}
                            >
                              <RotateCcw className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              title="Delete snapshot"
                              onClick={() => handleDeleteSnapshot(s)}
                            >
                              <Trash2 className="h-4 w-4" />
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

          <Card>
            <CardHeader>
              <CardTitle>Configuration Tree</CardTitle>
              <CardDescription>
                Merged values — secrets are shown as ••••
              </CardDescription>
              <Input
                placeholder="Filter by key (case-insensitive)…"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className="mt-2 max-w-md"
              />
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[480px] w-full rounded-md border">
                <pre className="p-4 text-xs font-mono leading-relaxed">
                  {filter
                    ? filterTree(config.tree, filter.toLowerCase())
                    : JSON.stringify(config.tree, null, 2)}
                </pre>
              </ScrollArea>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

// filterTree returns a JSON pretty-print of the subset of tree whose
// dotted-path keys contain the lowercase substring. Leaves are kept
// alongside their full ancestry so the result still parses as valid
// JSON-shaped output. Matches anywhere in the path so "tpm.device"
// matches when the user types "device".
function filterTree(tree: Record<string, unknown>, q: string): string {
  const matches: Record<string, unknown> = {};
  walk(tree, "", (key, val) => {
    if (key.toLowerCase().includes(q)) {
      assignAtPath(matches, key.split("."), val);
    }
  });
  return JSON.stringify(matches, null, 2);
}

function walk(
  obj: unknown,
  prefix: string,
  visit: (key: string, val: unknown) => void,
): void {
  if (obj !== null && typeof obj === "object" && !Array.isArray(obj)) {
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      const path = prefix ? `${prefix}.${k}` : k;
      walk(v, path, visit);
    }
  } else {
    visit(prefix, obj);
  }
}

function assignAtPath(
  target: Record<string, unknown>,
  parts: string[],
  val: unknown,
): void {
  let cur = target;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (!(part in cur) || typeof cur[part] !== "object" || cur[part] === null) {
      cur[part] = {};
    }
    cur = cur[part] as Record<string, unknown>;
  }
  cur[parts[parts.length - 1]] = val;
}
