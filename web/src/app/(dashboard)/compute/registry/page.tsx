"use client";

import * as React from "react";
import { Info, RefreshCw, Trash2, Loader2, Search } from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
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
import type { RegistryHealthCode, RegistryStatus } from "@/hooks";

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

/**
 * The capability gate on Delete (#2063): the reason a manifest cannot be
 * deleted now, or null when it can. A read-only registry refuses deletes,
 * and an unknown status gives no ground to offer one.
 */
export function registryDeleteBlock(status: RegistryStatus | null): string | null {
  if (status === null) return "Not available: the registry status is unknown";
  if (status.ReadOnly) return "Not available: the registry is read-only";
  return null;
}

/**
 * Container registry page: registry status, the tags of a repository
 * (OCI tags/list), artifact inspection and manifest deletion behind a
 * confirm dialog, all through the SDK's RegistryService.
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
    inspection,
    inspectError,
    isInspecting,
    inspect,
  } = useRegistry();
  const deleteBlock = registryDeleteBlock(status);
  const [repository, setRepository] = React.useState("");
  const [pending, setPending] = React.useState<string | null>(null);
  const [isDeleting, setDeleting] = React.useState(false);

  const onList = (e: React.FormEvent) => {
    e.preventDefault();
    const name = repository.trim();
    if (name) void listTags(name);
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
              <dd>{status.Components?.length ?? 0}</dd>
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
                  <TableHead className="w-12" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {tags.tags.map((tag) => (
                  <TableRow key={tag}>
                    <TableCell className="font-mono">{tags.name}</TableCell>
                    <TableCell>
                      <Badge variant="secondary">{tag}</Badge>
                    </TableCell>
                    <TableCell className="flex gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => void inspect(tags.name, tag)}
                        aria-label={`Inspect ${tag}`}
                        title="Inspect artifact"
                        disabled={isInspecting}
                      >
                        <Info className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => setPending(tag)}
                        aria-label={`Delete ${tag}`}
                        title={deleteBlock ?? "Delete manifest"}
                        disabled={deleteBlock !== null}
                        aria-describedby={deleteBlock ? "registry-delete-gate" : undefined}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          {tags !== null && tags.tags.length > 0 && deleteBlock && (
            <p id="registry-delete-gate" className="text-xs text-muted-foreground mt-2">
              Delete: {deleteBlock}
            </p>
          )}
        </CardContent>
      </Card>

      {(isInspecting || inspection !== null || inspectError !== null) && (
        <Card data-testid="registry-inspect">
          <CardHeader>
            <CardTitle>Artifact</CardTitle>
          </CardHeader>
          <CardContent>
            {isInspecting ? (
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            ) : inspectError !== null ? (
              <p className="text-sm text-destructive">
                Failed to inspect: {inspectError}
              </p>
            ) : inspection?.Artifact ? (
              <dl className="grid grid-cols-2 gap-2 text-sm max-w-xl">
                <dt className="text-muted-foreground">Reference</dt>
                <dd className="font-mono">
                  {inspection.Artifact.Repository}:{inspection.Artifact.Tag}
                </dd>
                <dt className="text-muted-foreground">Digest</dt>
                <dd className="font-mono break-all">{inspection.Artifact.Digest || "—"}</dd>
                <dt className="text-muted-foreground">Size</dt>
                <dd>{inspection.Artifact.Size ?? 0} bytes</dd>
                <dt className="text-muted-foreground">Platform</dt>
                <dd>
                  {[inspection.Artifact.OS, inspection.Artifact.Architecture]
                    .filter(Boolean)
                    .join("/") || "—"}
                </dd>
                <dt className="text-muted-foreground">Pushed</dt>
                <dd>{inspection.Artifact.PushedAt || "—"}</dd>
                <dt className="text-muted-foreground">Signatures</dt>
                <dd>{inspection.Signatures?.length ?? 0}</dd>
              </dl>
            ) : (
              <p className="text-sm text-muted-foreground">No artifact detail returned.</p>
            )}
          </CardContent>
        </Card>
      )}

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
