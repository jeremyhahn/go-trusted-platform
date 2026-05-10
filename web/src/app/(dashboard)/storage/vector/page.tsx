"use client";

import * as React from "react";
import { ColumnDef } from "@tanstack/react-table";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { DataTable, createSelectColumn } from "@/components/ui/data-table";
import { DataTableColumnHeader } from "@/components/ui/data-table-column-header";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useQuicBaaSVector, useApi, useMutation, useToast } from "@/hooks";
import type {
  VectorNamespace,
  VectorSearchResult,
  DistanceMetric,
} from "trusted-platform-sdk";
import {
  Plus,
  RefreshCw,
  AlertCircle,
  Trash2,
  MoreHorizontal,
  Search,
  Boxes,
  Sparkles,
  Layers,
  CircleDot,
  Target,
} from "lucide-react";

/**
 * UI collection type that extends VectorNamespace with display properties
 */
interface VectorCollectionUI extends VectorNamespace {
  /** Index type for display (derived from namespace or default) */
  indexType: "flat" | "hnsw" | "ivf";
  /** Description placeholder */
  description?: string;
}

/**
 * Form data for creating collections (namespaces)
 */
interface VectorCollectionInput {
  name: string;
  description?: string;
  dimensions: number;
  distanceMetric: "cosine" | "euclidean" | "dot_product";
  indexType: "flat" | "hnsw" | "ivf";
}

/**
 * Form data for vector search
 */
interface VectorSearchInput {
  namespace: string;
  topK: number;
  vector: number[];
}

/**
 * Vector Database Page
 *
 * Features:
 * - Manage vector collections (namespaces) for embeddings
 * - Configure distance metrics (cosine, euclidean, dot product)
 * - Perform similarity searches
 * - Create and delete collections
 * - View collection statistics
 */
export default function VectorDatabasePage() {
  const { toast } = useToast();
  const vector = useQuicBaaSVector();
  const [isCreateDialogOpen, setIsCreateDialogOpen] = React.useState(false);
  const [isSearchDialogOpen, setIsSearchDialogOpen] = React.useState(false);
  const [searchResults, setSearchResults] = React.useState<VectorSearchResult[]>([]);
  const [formData, setFormData] = React.useState<VectorCollectionInput>({
    name: "",
    description: "",
    dimensions: 384,
    distanceMetric: "cosine",
    indexType: "hnsw",
  });
  const [searchData, setSearchData] = React.useState<VectorSearchInput>({
    namespace: "",
    topK: 10,
    vector: [],
  });
  const [vectorInput, setVectorInput] = React.useState("");

  // Fetch namespaces using SDK
  const {
    data: listResponse,
    isLoading: loading,
    error,
    refetch: loadData,
  } = useApi(
    () => vector.listNamespaces({ limit: 100 }),
    [],
    {
      onError: (err) => {
        toast({
          title: "Error loading collections",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Transform SDK VectorNamespace to UI format
  const collections: VectorCollectionUI[] = React.useMemo(() => {
    if (!listResponse?.namespaces) return [];
    return listResponse.namespaces.map((ns): VectorCollectionUI => ({
      ...ns,
      indexType: "hnsw", // Default since SDK doesn't expose this in namespace
      description: undefined,
    }));
  }, [listResponse]);

  // Create namespace mutation
  const createMutation = useMutation(
    async (data: VectorCollectionInput) => {
      // Map local metric names to SDK DistanceMetric type
      const metricMap: Record<string, DistanceMetric> = {
        cosine: "COSINE",
        euclidean: "EUCLIDEAN",
        dot_product: "DOT_PRODUCT",
      };
      return vector.createNamespace({
        name: data.name,
        dimension: data.dimensions,
        metric: metricMap[data.distanceMetric],
        indexConfig: {
          type: data.indexType,
        },
      });
    },
    {
      onSuccess: () => {
        toast({
          title: "Collection created",
          description: `Collection "${formData.name}" created successfully`,
          variant: "success",
        });
        setIsCreateDialogOpen(false);
        resetForm();
        loadData();
      },
      onError: (err) => {
        toast({
          title: "Error creating collection",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Delete namespace mutation
  const deleteMutation = useMutation(
    async (name: string) => {
      return vector.deleteNamespace({ name, force: true });
    },
    {
      onSuccess: (_, name) => {
        toast({
          title: "Collection deleted",
          description: `Collection "${name}" deleted successfully`,
          variant: "success",
        });
        loadData();
      },
      onError: (err) => {
        toast({
          title: "Error deleting collection",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Search mutation
  const searchMutation = useMutation(
    async (data: VectorSearchInput) => {
      return vector.search({
        namespace: data.namespace,
        vector: data.vector,
        topK: data.topK,
        includeMetadata: true,
      });
    },
    {
      onSuccess: (response) => {
        setSearchResults(response.results || []);
        toast({
          title: "Search completed",
          description: `Found ${response.results?.length || 0} results`,
          variant: "success",
        });
      },
      onError: (err) => {
        toast({
          title: "Search failed",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  const resetForm = () => {
    setFormData({
      name: "",
      description: "",
      dimensions: 384,
      distanceMetric: "cosine",
      indexType: "hnsw",
    });
  };

  const handleCreateCollection = async () => {
    if (!formData.name.trim()) {
      toast({
        title: "Validation error",
        description: "Collection name is required",
        variant: "destructive",
      });
      return;
    }
    await createMutation.mutateAsync(formData);
  };

  const handleDelete = async (collection: VectorCollectionUI) => {
    if (
      !confirm(
        `Delete collection "${collection.name}"? This will delete all vectors. This action cannot be undone.`
      )
    ) {
      return;
    }
    await deleteMutation.mutateAsync(collection.name);
  };

  const handleSearch = async () => {
    if (!searchData.namespace) {
      toast({
        title: "Validation error",
        description: "Please select a collection",
        variant: "destructive",
      });
      return;
    }

    // Parse vector input
    let parsedVector: number[];
    try {
      parsedVector = JSON.parse(vectorInput);
      if (!Array.isArray(parsedVector) || !parsedVector.every((v) => typeof v === "number")) {
        throw new Error("Invalid vector format");
      }
    } catch {
      toast({
        title: "Validation error",
        description: "Vector must be a valid JSON array of numbers",
        variant: "destructive",
      });
      return;
    }

    await searchMutation.mutateAsync({
      ...searchData,
      vector: parsedVector,
    });
  };

  const handleSearchDialogClose = (open: boolean) => {
    if (!open) {
      setSearchResults([]);
      setVectorInput("");
    }
    setIsSearchDialogOpen(open);
  };

  const getDistanceMetricBadge = (metric: DistanceMetric) => {
    const variants: Record<string, "default" | "secondary" | "outline"> = {
      COSINE: "default",
      EUCLIDEAN: "secondary",
      DOT_PRODUCT: "outline",
      MANHATTAN: "outline",
    };
    const labels: Record<string, string> = {
      COSINE: "Cosine",
      EUCLIDEAN: "Euclidean",
      DOT_PRODUCT: "Dot Product",
      MANHATTAN: "Manhattan",
    };
    return (
      <Badge variant={variants[metric] || "default"}>
        {labels[metric] || metric}
      </Badge>
    );
  };

  const getIndexTypeBadge = (indexType: string) => {
    const variants: Record<string, "default" | "secondary" | "outline"> = {
      flat: "outline",
      hnsw: "default",
      ivf: "secondary",
    };
    return (
      <Badge variant={variants[indexType] || "default"}>
        {indexType.toUpperCase()}
      </Badge>
    );
  };

  const columns: ColumnDef<VectorCollectionUI>[] = [
    createSelectColumn<VectorCollectionUI>(),
    {
      accessorKey: "name",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Collection Name" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Boxes className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{row.original.name}</span>
        </div>
      ),
    },
    {
      accessorKey: "description",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Description" />
      ),
      cell: ({ row }) => (
        <span className="text-muted-foreground">
          {row.original.description || "-"}
        </span>
      ),
    },
    {
      accessorKey: "dimension",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Dimensions" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-1">
          <Layers className="h-3 w-3 text-muted-foreground" />
          <span>{row.original.dimension}</span>
        </div>
      ),
    },
    {
      accessorKey: "metric",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Distance Metric" />
      ),
      cell: ({ row }) => getDistanceMetricBadge(row.original.metric),
    },
    {
      accessorKey: "indexType",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Index" />
      ),
      cell: ({ row }) => getIndexTypeBadge(row.original.indexType),
    },
    {
      accessorKey: "vectorCount",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Vectors" />
      ),
      cell: ({ row }) => (
        <span className="font-mono">{row.original.vectorCount.toLocaleString()}</span>
      ),
    },
    {
      accessorKey: "createdAt",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Created" />
      ),
      cell: ({ row }) => new Date(row.original.createdAt * 1000).toLocaleDateString(),
    },
    {
      id: "actions",
      cell: ({ row }) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem
              onClick={() => {
                setSearchData((prev) => ({ ...prev, namespace: row.original.name }));
                setIsSearchDialogOpen(true);
              }}
            >
              <Search className="mr-2 h-4 w-4" />
              Search Vectors
            </DropdownMenuItem>
            <DropdownMenuItem
              className="text-destructive"
              onClick={() => handleDelete(row.original)}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ];

  // Calculate statistics
  const totalCollections = collections.length;
  const totalVectors = collections.reduce((acc, c) => acc + c.vectorCount, 0);
  const avgDimensions = collections.length > 0
    ? Math.round(collections.reduce((acc, c) => acc + c.dimension, 0) / collections.length)
    : 0;

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Vector Database</h1>
          <p className="text-muted-foreground">
            Manage vector collections for embeddings and similarity search
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => loadData()} disabled={loading}>
            <RefreshCw
              className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
          <Dialog open={isSearchDialogOpen} onOpenChange={handleSearchDialogClose}>
            <DialogTrigger asChild>
              <Button variant="outline">
                <Search className="mr-2 h-4 w-4" />
                Search Vectors
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Similarity Search</DialogTitle>
                <DialogDescription>
                  Find similar vectors using the configured distance metric
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 pt-4">
                <div className="space-y-2">
                  <Label htmlFor="searchCollection">Collection</Label>
                  <Select
                    value={searchData.namespace}
                    onValueChange={(value) =>
                      setSearchData((prev) => ({ ...prev, namespace: value }))
                    }
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select collection" />
                    </SelectTrigger>
                    <SelectContent>
                      {collections
                        .filter((c) => c.name && c.name.length > 0)
                        .map((c) => (
                          <SelectItem key={c.name} value={c.name}>
                            {c.name} ({c.dimension}d)
                          </SelectItem>
                        ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="vector">Query Vector (JSON array)</Label>
                  <Textarea
                    id="vector"
                    placeholder="[0.1, 0.2, 0.3, ...]"
                    value={vectorInput}
                    onChange={(e) => setVectorInput(e.target.value)}
                    rows={4}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="topK">Top K Results</Label>
                  <Input
                    id="topK"
                    type="number"
                    value={searchData.topK}
                    onChange={(e) =>
                      setSearchData((prev) => ({
                        ...prev,
                        topK: parseInt(e.target.value, 10) || 10,
                      }))
                    }
                  />
                </div>
                <Button
                  onClick={handleSearch}
                  disabled={searchMutation.isLoading}
                  className="w-full"
                >
                  {searchMutation.isLoading ? "Searching..." : "Search"}
                </Button>
                {searchResults.length > 0 && (
                  <div className="mt-4 space-y-2">
                    <h4 className="font-medium">Results ({searchResults.length})</h4>
                    <div className="max-h-48 overflow-y-auto space-y-2">
                      {searchResults.map((result, idx) => (
                        <div
                          key={result.id}
                          className="flex items-center justify-between p-2 bg-muted rounded-lg"
                        >
                          <div className="flex items-center gap-2">
                            <Badge variant="outline">{idx + 1}</Badge>
                            <code className="text-sm">{result.id}</code>
                          </div>
                          <Badge variant="secondary">
                            Score: {result.score.toFixed(4)}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </DialogContent>
          </Dialog>
          <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" />
                Create Collection
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Create Vector Collection</DialogTitle>
                <DialogDescription>
                  Define a new collection for storing vector embeddings
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 pt-4">
                <div className="space-y-2">
                  <Label htmlFor="name">Collection Name</Label>
                  <Input
                    id="name"
                    placeholder="my-embeddings"
                    value={formData.name}
                    onChange={(e) =>
                      setFormData((prev) => ({ ...prev, name: e.target.value }))
                    }
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="description">Description</Label>
                  <Input
                    id="description"
                    placeholder="Document embeddings for semantic search"
                    value={formData.description}
                    onChange={(e) =>
                      setFormData((prev) => ({ ...prev, description: e.target.value }))
                    }
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="dimensions">Dimensions</Label>
                    <Select
                      value={formData.dimensions.toString()}
                      onValueChange={(value) =>
                        setFormData((prev) => ({
                          ...prev,
                          dimensions: parseInt(value, 10),
                        }))
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="128">128</SelectItem>
                        <SelectItem value="256">256</SelectItem>
                        <SelectItem value="384">384 (MiniLM)</SelectItem>
                        <SelectItem value="512">512</SelectItem>
                        <SelectItem value="768">768 (BERT)</SelectItem>
                        <SelectItem value="1024">1024</SelectItem>
                        <SelectItem value="1536">1536 (OpenAI)</SelectItem>
                        <SelectItem value="3072">3072</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="distanceMetric">Distance Metric</Label>
                    <Select
                      value={formData.distanceMetric}
                      onValueChange={(value) =>
                        setFormData((prev) => ({
                          ...prev,
                          distanceMetric: value as VectorCollectionInput["distanceMetric"],
                        }))
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="cosine">Cosine</SelectItem>
                        <SelectItem value="euclidean">Euclidean</SelectItem>
                        <SelectItem value="dot_product">Dot Product</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="indexType">Index Type</Label>
                  <Select
                    value={formData.indexType}
                    onValueChange={(value) =>
                      setFormData((prev) => ({
                        ...prev,
                        indexType: value as VectorCollectionInput["indexType"],
                      }))
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="flat">Flat (Exact)</SelectItem>
                      <SelectItem value="hnsw">HNSW (Approximate)</SelectItem>
                      <SelectItem value="ivf">IVF (Inverted File)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <Button
                  onClick={handleCreateCollection}
                  disabled={createMutation.isLoading}
                  className="w-full"
                >
                  {createMutation.isLoading ? "Creating..." : "Create Collection"}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="flex items-center gap-2 p-4 bg-destructive/10 border border-destructive rounded-lg">
          <AlertCircle className="h-4 w-4 text-destructive" />
          <div>
            <p className="font-medium text-destructive">Error</p>
            <p className="text-sm text-destructive">{error.message}</p>
          </div>
        </div>
      )}

      {/* Statistics Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Collections</CardTitle>
            <Boxes className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalCollections}</div>
            <p className="text-xs text-muted-foreground">
              Vector collections
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Vectors</CardTitle>
            <CircleDot className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
              {totalVectors.toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground">
              Stored embeddings
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Avg Dimensions</CardTitle>
            <Layers className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {avgDimensions}
            </div>
            <p className="text-xs text-muted-foreground">
              Vector size
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Search Ready</CardTitle>
            <Sparkles className="h-4 w-4 text-purple-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">
              {collections.filter((c) => c.vectorCount > 0).length}
            </div>
            <p className="text-xs text-muted-foreground">
              Collections with data
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Collections Table */}
      <Card>
        <CardHeader>
          <CardTitle>Collections</CardTitle>
          <CardDescription>
            Manage vector collections for embeddings and similarity search
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={collections}
            searchKey="name"
            searchPlaceholder="Filter collections..."
            loading={loading}
            emptyState={
              <div className="flex flex-col items-center gap-2 py-8">
                <Target className="h-12 w-12 text-muted-foreground" />
                <p className="text-muted-foreground">No collections found</p>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setIsCreateDialogOpen(true)}
                >
                  <Plus className="mr-2 h-4 w-4" />
                  Create your first collection
                </Button>
              </div>
            }
            bulkActions={[
              {
                label: "Delete selected",
                onClick: async (rows) => {
                  if (
                    confirm(
                      `Delete ${rows.length} selected collections? This will delete all vectors. This action cannot be undone.`
                    )
                  ) {
                    for (const row of rows) {
                      await deleteMutation.mutateAsync(row.name);
                    }
                  }
                },
                variant: "destructive",
              },
            ]}
          />
        </CardContent>
      </Card>
    </div>
  );
}
