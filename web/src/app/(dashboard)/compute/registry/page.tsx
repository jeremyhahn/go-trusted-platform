"use client";

import * as React from "react";
import { RefreshCw, Trash2, Loader2, Search } from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Gated } from "@/components/features/capabilities/gated";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useRegistry, useToast } from "@/hooks";
import type { RegistryHealthCode, UseRegistryResult } from "@/hooks";

type InspectDetail = Awaited<ReturnType<UseRegistryResult["inspect"]>>;

/** dash shows "-" for a missing field. */
function dash(v: string | number | undefined | null): string {
  return v === undefined || v === null || v === "" ? "-" : String(v);
}

const HEALTH_LABEL: Record<RegistryHealthCode, string> = {
  0: "Unknown",
  1: "Healthy",
  2: "Degraded",
  3: "Unhealthy",
};

function healthVariant(
  h: RegistryHealthCode,
): "default" | "secondary" | "destructive" {
  if (h === 1) return "default";
  if (h === 3) return "destructive";
  return "secondary";
}

/** InspectPanel shows one tag's image detail; missing fields show "-". */
function InspectPanel({
  name,
  tag,
  detail,
  onClose,
}: {
  name: string;
  tag: string;
  detail: InspectDetail;
  onClose: () => void;
}) {
  const artifact = detail.Artifact ?? null;
  const manifest = artifact?.Manifest ?? null;
  const scan = detail.ScanResult ?? null;
  const signatures = detail.Signatures ?? [];
  const platform =
    artifact?.OS || artifact?.Architecture
      ? `${artifact?.OS ?? "-"}/${artifact?.Architecture ?? "-"}`
      : "-";
  const size = artifact?.Size;
  return (
    <section
      data-testid="registry-inspect-panel"
      className="mt-4 rounded-md border p-4 space-y-2"
    >
      <div className="flex items-center justify-between">
        <h3 className="font-mono text-sm font-medium">
          {name}:{tag}
        </h3>
        <Button variant="outline" size="sm" onClick={onClose}>
          Close
        </Button>
      </div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-muted-foreground">Digest</dt>
        <dd data-testid="registry-inspect-digest" className="font-mono break-all">
          {dash(artifact?.Digest)}
        </dd>
        <dt className="text-muted-foreground">Media type</dt>
        <dd>{dash(manifest?.MediaType)}</dd>
        <dt className="text-muted-foreground">Size</dt>
        <dd>{size === undefined || size === null ? "-" : `${size} bytes`}</dd>
        <dt className="text-muted-foreground">Layers</dt>
        <dd data-testid="registry-inspect-layers">
          {manifest?.Layers?.length ?? 0}
        </dd>
        <dt className="text-muted-foreground">Platform</dt>
        <dd>{platform}</dd>
        <dt className="text-muted-foreground">Pushed</dt>
        <dd>{dash(artifact?.PushedAt)}</dd>
        <dt className="text-muted-foreground">Tags</dt>
        <dd>{detail.Tags?.length ? detail.Tags.join(", ") : "-"}</dd>
        <dt className="text-muted-foreground">Signatures</dt>
        <dd>
          {signatures.length}
          {signatures.length > 0
            ? ` (${signatures.map((s) => dash(s.Signer)).join(", ")})`
            : null}
        </dd>
        <dt className="text-muted-foreground">Vulnerabilities</dt>
        <dd>
          {scan
            ? `Critical ${scan.CriticalCount ?? 0}, High ${scan.HighCount ?? 0}, Medium ${scan.MediumCount ?? 0}, Low ${scan.LowCount ?? 0}`
            : "Not scanned"}
        </dd>
      </dl>
    </section>
  );
}

/**
 * Container registry page: registry status, the tags of a repository
 * (OCI tags/list), image inspection per tag (RegistryService.inspect) and
 * manifest deletion behind a confirm dialog.
 */
export default function RegistryPage() {
  const { toast } = useToast();
  const {
    status,
    statusError,
    isStatusLoading,
    refetchStatus,
    tags,
    tagsError,
    isTagsLoading,
    listTags,
    deleteManifest,
    inspect,
  } = useRegistry();
  const [repository, setRepository] = React.useState("");
  const [pending, setPending] = React.useState<string | null>(null);
  const [isDeleting, setDeleting] = React.useState(false);
  const [inspected, setInspected] = React.useState<{
    tag: string;
    detail: InspectDetail;
  } | null>(null);
  const [inspectError, setInspectError] = React.useState<{
    tag: string;
    message: string;
  } | null>(null);
  const [inspecting, setInspecting] = React.useState<string | null>(null);

  const onList = (e: React.FormEvent) => {
    e.preventDefault();
    const name = repository.trim();
    setInspected(null);
    setInspectError(null);
    if (name) void listTags(name);
  };

  const onInspect = async (name: string, tag: string) => {
    setInspecting(tag);
    try {
      const detail = await inspect(name, tag);
      setInspected({ tag, detail });
      setInspectError(null);
    } catch (e: unknown) {
      setInspected(null);
      setInspectError({
        tag,
        message: e instanceof Error ? e.message : String(e),
      });
    } finally {
      setInspecting(null);
    }
  };

  const onConfirmDelete = async () => {
    if (!tags || !pending) return;
    const ref = `${tags.name}:${pending}`;
    setDeleting(true);
    try {
      await deleteManifest(tags.name, pending);
      toast({ title: "Manifest deleted", description: ref });
    } catch (e: unknown) {
      toast({
        title: "Delete failed",
        description: e instanceof Error ? e.message : String(e),
        variant: "destructive",
      });
    } finally {
      setDeleting(false);
      setPending(null);
    }
  };

  return (
    <div className="container mx-auto py-6 space-y-6">
      <PageHeader
        title="Container Registry"
        description="Registry status, repository tags and manifests"
      >
        <Button
          variant="outline"
          size="sm"
          onClick={() => void refetchStatus()}
          disabled={isStatusLoading}
        >
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </PageHeader>

      <Card data-testid="registry-status">
        <CardHeader>
          <CardTitle>Status</CardTitle>
        </CardHeader>
        <CardContent>
          {isStatusLoading ? (
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          ) : statusError ? (
            <p className="text-sm text-destructive">
              Failed to load status: {statusError}
            </p>
          ) : status ? (
            <dl className="grid grid-cols-2 gap-2 text-sm max-w-md">
              <dt className="text-muted-foreground">Health</dt>
              <dd>
                <Badge variant={healthVariant(status.Health)}>
                  {HEALTH_LABEL[status.Health] ?? HEALTH_LABEL[0]}
                </Badge>
              </dd>
              <dt className="text-muted-foreground">Version</dt>
              <dd className="font-mono">{status.Version || "—"}</dd>
              <dt className="text-muted-foreground">Mode</dt>
              <dd>{status.ReadOnly ? "Read-only" : "Read-write"}</dd>
              <dt className="text-muted-foreground">Components</dt>
              <dd data-testid="registry-components">
                {status.Components && status.Components.length > 0 ? (
                  <ul className="space-y-1">
                    {status.Components.map((c, i) => {
                      const code = c.Status ?? 0;
                      return (
                        <li
                          key={c.Name ?? i}
                          className="flex flex-wrap items-center gap-2"
                        >
                          <span className="font-mono">{dash(c.Name)}</span>
                          <Badge variant={healthVariant(code)}>
                            {HEALTH_LABEL[code] ?? HEALTH_LABEL[0]}
                          </Badge>
                          <span className="text-muted-foreground">
                            {dash(c.Message)}
                          </span>
                        </li>
                      );
                    })}
                  </ul>
                ) : (
                  <span className="text-muted-foreground">
                    No components reported
                  </span>
                )}
              </dd>
              <dt className="text-muted-foreground">Last updated</dt>
              <dd className="font-mono">{dash(status.Timestamp)}</dd>
            </dl>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Tags</CardTitle>
          <CardDescription>
            List the tags of a repository, then delete a manifest by tag.
          </CardDescription>
          <form onSubmit={onList} className="flex gap-2 mt-2 max-w-md">
            <Input
              aria-label="Repository"
              placeholder="Repository, for example team/app"
              value={repository}
              onChange={(e) => setRepository(e.target.value)}
            />
            <Button type="submit" disabled={isTagsLoading || !repository.trim()}>
              <Search className="h-4 w-4 mr-2" />
              List tags
            </Button>
          </form>
        </CardHeader>
        <CardContent>
          {isTagsLoading ? (
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          ) : tagsError ? (
            <p className="text-sm text-destructive">
              Failed to list tags: {tagsError}
            </p>
          ) : tags === null ? null : tags.tags.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">
              {tags.name} has no tags.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Repository</TableHead>
                  <TableHead>Tag</TableHead>
                  <TableHead className="w-24" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {tags.tags.map((tag) => (
                  <TableRow key={tag}>
                    <TableCell className="font-mono">{tags.name}</TableCell>
                    <TableCell>
                      <Badge variant="secondary">{tag}</Badge>
                    </TableCell>
                    <TableCell>
                      <Gated op="GET /api/v1/compute/images/{repository:.+}">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => void onInspect(tags.name, tag)}
                          disabled={inspecting !== null}
                          aria-label={`Inspect ${tag}`}
                          title="Inspect image"
                        >
                          <Search className="h-4 w-4" />
                        </Button>
                      </Gated>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => setPending(tag)}
                        disabled={status?.ReadOnly === true}
                        aria-label={`Delete ${tag}`}
                        title={status?.ReadOnly ? "Registry is read-only" : "Delete manifest"}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          {tags && inspectError ? (
            <p
              data-testid="registry-inspect-error"
              className="text-sm text-destructive mt-4"
            >
              Failed to inspect {tags.name}:{inspectError.tag}:{" "}
              {inspectError.message}
            </p>
          ) : null}
          {tags && inspected ? (
            <InspectPanel
              name={tags.name}
              tag={inspected.tag}
              detail={inspected.detail}
              onClose={() => setInspected(null)}
            />
          ) : null}
        </CardContent>
      </Card>

      <Dialog
        open={pending !== null}
        onOpenChange={(open) => {
          if (!open && !isDeleting) setPending(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete manifest</DialogTitle>
            <DialogDescription>
              Delete {tags?.name}:{pending}? This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setPending(null)}
              disabled={isDeleting}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => void onConfirmDelete()}
              disabled={isDeleting}
            >
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
