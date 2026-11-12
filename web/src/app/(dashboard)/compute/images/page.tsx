"use client";

import * as React from "react";
import { RefreshCw, Trash2, Loader2 } from "lucide-react";
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
import { useToast } from "@/hooks/use-toast";

interface ImageSummary {
  repository: string;
  tag: string;
  digest?: string;
  media_type?: string;
  size: number;
  layers: number;
  annotations?: Record<string, string>;
  created_at?: string;
  updated_at?: string;
}

interface ListResponse {
  images: ImageSummary[];
  total: number;
}

/**
 * Compute Images page.
 *
 * Reads /api/v1/compute/images — the platform's OCI artifact
 * registry. Phase 5 first-ship surfaces list + delete; push/pull
 * are reachable today via gRPC/MCP and will pick up a REST upload
 * surface alongside encryption/signing in the next round.
 *
 * Replaces the "API Not Implemented" stub that lied about the
 * surface being absent — the registry has always existed in
 * pkg/registry/, it just wasn't wired through the daemon until
 * Phase 5.
 */
export default function ImagesPage() {
  const { toast } = useToast();
  const [images, setImages] = React.useState<ImageSummary[]>([]);
  const [isLoading, setIsLoading] = React.useState(true);
  const [filter, setFilter] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);

  const fetchOpts: RequestInit = React.useMemo(
    () => ({
      credentials: "include",
      headers: { Accept: "application/json" },
    }),
    [],
  );

  // applyImages settles the list request into state from its promise
  // callbacks, so the mount effect can start it without a synchronous
  // setState (react-hooks/set-state-in-effect).
  const applyImages = React.useCallback(
    (request: Promise<ImageSummary[]>) =>
      request
        .then(
          (list) => {
            setImages(list);
            setError(null);
          },
          (e: unknown) => {
            setError(e instanceof Error ? e.message : String(e));
          }
        )
        .finally(() => setIsLoading(false)),
    []
  );

  const loadImages = React.useCallback(async (): Promise<ImageSummary[]> => {
    const res = await fetch("/api/v1/compute/images", fetchOpts);
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }
    const body = await res.json();
    const data: ListResponse =
      body.payload && typeof body.payload === "object"
        ? (body.payload as ListResponse)
        : (body as ListResponse);
    return data.images ?? [];
  }, [fetchOpts]);

  const fetchImages = React.useCallback(async () => {
    setIsLoading(true);
    setError(null);
    await applyImages(loadImages());
  }, [applyImages, loadImages]);

  React.useEffect(() => {
    void applyImages(loadImages());
  }, [applyImages, loadImages]);

  React.useEffect(() => {
    void loadImages();
  }, [loadImages]);

  const handleDelete = async (img: ImageSummary) => {
    const ref = img.tag ? `${img.repository}:${img.tag}` : img.repository;
    if (!confirm(`Delete ${ref}? This cannot be undone.`)) return;
    try {
      const res = await fetch(
        `/api/v1/compute/images/${encodeURIComponent(ref)}`,
        {
          ...fetchOpts,
          method: "DELETE",
        },
      );
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      }
      toast({ title: "Image deleted", description: ref });
      await fetchImages();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      toast({
        title: "Delete failed",
        description: msg,
        variant: "destructive",
      });
    }
  };

  const filtered = React.useMemo(() => {
    if (!filter) return images;
    const q = filter.toLowerCase();
    return images.filter(
      (i) =>
        i.repository.toLowerCase().includes(q) ||
        i.tag.toLowerCase().includes(q) ||
        (i.digest ?? "").toLowerCase().includes(q),
    );
  }, [images, filter]);

  if (isLoading) {
    return (
      <div className="container mx-auto py-6 space-y-6">
        <PageHeader
          title="Container Images"
          description="Trusted Platform OCI artifact registry"
        />
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-6 space-y-6">
      <PageHeader
        title="Container Images"
        description="Trusted Platform OCI artifact registry"
      >
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchImages}
            disabled={isLoading}
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </PageHeader>

      {error && (
        <Card className="border-destructive/50">
          <CardContent className="pt-6">
            <p className="text-sm text-destructive">
              Failed to load images: {error}
            </p>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Images</CardTitle>
          <CardDescription>
            {images.length === 0
              ? "No images have been pushed to the registry yet."
              : `${images.length} image${images.length === 1 ? "" : "s"} in the registry`}
          </CardDescription>
          <Input
            placeholder="Filter by repository, tag, or digest…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="mt-2 max-w-md"
          />
        </CardHeader>
        <CardContent>
          {filtered.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">
              {images.length === 0
                ? "Push images via `platformctl compute image push` or the gRPC RegistryService."
                : "No images match the current filter."}
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Repository</TableHead>
                  <TableHead>Tag</TableHead>
                  <TableHead>Digest</TableHead>
                  <TableHead>Layers</TableHead>
                  <TableHead className="text-right">Size</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="w-12" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((img) => (
                  <TableRow
                    key={`${img.repository}:${img.tag}:${img.digest ?? ""}`}
                  >
                    <TableCell className="font-mono">
                      {img.repository}
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">{img.tag || "—"}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {(img.digest ?? "").slice(0, 16) || "—"}
                    </TableCell>
                    <TableCell>{img.layers}</TableCell>
                    <TableCell className="text-right font-mono">
                      {formatSize(img.size)}
                    </TableCell>
                    <TableCell className="text-xs">
                      {img.created_at
                        ? new Date(img.created_at).toLocaleString()
                        : "—"}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => handleDelete(img)}
                        title="Delete image"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// formatSize renders a byte count as a short human-readable string.
// Binary units (KiB/MiB) match how OCI manifests typically express
// layer sizes — close enough for the WebUI; the API still returns
// the exact byte count.
function formatSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let n = bytes;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}
