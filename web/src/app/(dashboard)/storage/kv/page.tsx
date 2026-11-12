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
import { useQuicBaaSKV, useApi, useMutation, useToast } from "@/hooks";
import type { KeyValue } from "trusted-platform-sdk";
import {
  Plus,
  RefreshCw,
  AlertCircle,
  Key,
  Database,
  Edit,
  Trash2,
  MoreHorizontal,
  Clock,
  Hash,
  FileJson,
  Binary,
} from "lucide-react";

/**
 * UI entry type that extends KeyValue with display properties
 */
interface KVEntryUI extends KeyValue {
  /** Computed namespace from key prefix */
  namespace: string;
  /** Detected value type for display */
  valueType: "string" | "json" | "binary";
  /** Decoded value for display */
  displayValue: string;
}

/**
 * Form data for creating/editing entries
 */
interface KVFormData {
  key: string;
  value: string;
  valueType: "string" | "json" | "binary";
  ttl?: number;
}

/**
 * Key-Value Store Browser Page
 *
 * Features:
 * - Browse key-value pairs using DragonDB KV service
 * - Create, update, and delete entries
 * - Support for string, JSON, and binary values
 * - TTL management for expiring keys
 * - Prefix-based filtering
 */
export default function KVStorePage() {
  const { toast } = useToast();
  const kv = useQuicBaaSKV();
  const [prefixFilter, setPrefixFilter] = React.useState<string>("");
  const [isCreateDialogOpen, setIsCreateDialogOpen] = React.useState(false);
  const [editingEntry, setEditingEntry] = React.useState<KVEntryUI | null>(null);
  const [formData, setFormData] = React.useState<KVFormData>({
    key: "",
    value: "",
    valueType: "string",
  });

  // Fetch entries using SDK
  const {
    data: listResponse,
    isLoading: loading,
    error,
    refetch: loadData,
  } = useApi(
    () => kv.list({
      prefix: prefixFilter || undefined,
      includeValues: true,
      limit: 100,
    }),
    [prefixFilter],
    {
      onError: (err) => {
        toast({
          title: "Error loading entries",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Transform SDK KeyValue to UI format
  const entries: KVEntryUI[] = React.useMemo(() => {
    if (!listResponse?.kvs) return [];
    return listResponse.kvs.map((kv): KVEntryUI => {
      // Extract namespace from key (first segment before /)
      const keyParts = kv.key.split("/");
      const namespace = keyParts.length > 1 ? keyParts[0] : "default";

      // Detect value type and decode
      let valueType: "string" | "json" | "binary" = "string";
      let displayValue = "";

      try {
        // Try to decode base64 value
        const decoded = atob(kv.value);
        try {
          // Check if it's valid JSON
          JSON.parse(decoded);
          valueType = "json";
          displayValue = decoded;
        } catch {
          // Check if it contains non-printable characters (binary)
          const isBinary = /[\x00-\x08\x0E-\x1F\x7F-\xFF]/.test(decoded);
          if (isBinary) {
            valueType = "binary";
            displayValue = `[binary: ${kv.value.length} bytes encoded]`;
          } else {
            displayValue = decoded;
          }
        }
      } catch {
        // Not valid base64, treat as raw string
        displayValue = kv.value;
      }

      return {
        ...kv,
        namespace,
        valueType,
        displayValue,
      };
    });
  }, [listResponse]);

  // Extract unique namespaces for filtering
  const namespaces = React.useMemo(() => {
    const nsSet = new Set(entries.map((e) => e.namespace));
    return Array.from(nsSet).sort();
  }, [entries]);

  // Put mutation for creating/updating entries
  const putMutation = useMutation(
    async (data: KVFormData) => {
      // Encode value to base64
      const encodedValue = btoa(data.value);
      return kv.put({
        key: data.key,
        value: encodedValue,
        ttl: data.ttl,
      });
    },
    {
      onSuccess: () => {
        toast({
          title: editingEntry ? "Entry updated" : "Entry created",
          description: `Key "${formData.key}" saved successfully`,
          variant: "success",
        });
        setIsCreateDialogOpen(false);
        setEditingEntry(null);
        resetForm();
        loadData();
      },
      onError: (err) => {
        toast({
          title: "Error saving entry",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Delete mutation
  const deleteMutation = useMutation(
    async (key: string) => {
      return kv.delete({ key });
    },
    {
      onSuccess: (_, key) => {
        toast({
          title: "Entry deleted",
          description: `Key "${key}" deleted successfully`,
          variant: "success",
        });
        loadData();
      },
      onError: (err) => {
        toast({
          title: "Error deleting entry",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  const resetForm = () => {
    setFormData({
      key: "",
      value: "",
      valueType: "string",
    });
  };

  const handleSaveEntry = async () => {
    if (!formData.key.trim()) {
      toast({
        title: "Validation error",
        description: "Key is required",
        variant: "destructive",
      });
      return;
    }

    // Validate JSON if type is JSON
    if (formData.valueType === "json") {
      try {
        JSON.parse(formData.value);
      } catch {
        toast({
          title: "Validation error",
          description: "Invalid JSON format",
          variant: "destructive",
        });
        return;
      }
    }

    // A refusal is reported by the mutation's onError toast; mutateAsync
    // still rethrows it, so catch it here rather than leak a rejection.
    await putMutation.mutateAsync(formData).catch(() => undefined);
  };

  const handleDelete = async (entry: KVEntryUI) => {
    if (!confirm(`Delete key "${entry.key}"? This action cannot be undone.`)) {
      return;
    }
    await deleteMutation.mutateAsync(entry.key).catch(() => undefined);
  };

  const handleEdit = (entry: KVEntryUI) => {
    setEditingEntry(entry);
    setFormData({
      key: entry.key,
      value: entry.displayValue,
      valueType: entry.valueType,
      ttl: entry.expiresAt ? Math.floor((entry.expiresAt - Date.now()) / 1000) : undefined,
    });
    setIsCreateDialogOpen(true);
  };

  const handleDialogClose = (open: boolean) => {
    if (!open) {
      setEditingEntry(null);
      resetForm();
    }
    setIsCreateDialogOpen(open);
  };

  const getValueTypeIcon = (valueType: string) => {
    switch (valueType) {
      case "json":
        return <FileJson className="h-4 w-4" />;
      case "binary":
        return <Binary className="h-4 w-4" />;
      default:
        return <Hash className="h-4 w-4" />;
    }
  };

  const getValueTypeBadge = (valueType: string) => {
    const variants: Record<string, "default" | "secondary" | "outline"> = {
      string: "default",
      json: "secondary",
      binary: "outline",
    };
    return (
      <Badge variant={variants[valueType] || "default"}>
        {valueType}
      </Badge>
    );
  };

  const formatValue = (value: string, valueType: string): string => {
    if (valueType === "binary") {
      return value;
    }
    if (value.length > 50) {
      return value.substring(0, 50) + "...";
    }
    return value;
  };

  const columns: ColumnDef<KVEntryUI>[] = [
    createSelectColumn<KVEntryUI>(),
    {
      accessorKey: "namespace",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Namespace" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Database className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{row.original.namespace}</span>
        </div>
      ),
    },
    {
      accessorKey: "key",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Key" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Key className="h-4 w-4 text-muted-foreground" />
          <code className="text-sm bg-muted px-1 rounded">
            {row.original.key}
          </code>
        </div>
      ),
    },
    {
      accessorKey: "displayValue",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Value" />
      ),
      cell: ({ row }) => (
        <code className="text-sm text-muted-foreground">
          {formatValue(row.original.displayValue, row.original.valueType)}
        </code>
      ),
    },
    {
      accessorKey: "valueType",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Type" />
      ),
      cell: ({ row }) => getValueTypeBadge(row.original.valueType),
    },
    {
      accessorKey: "version",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Version" />
      ),
      cell: ({ row }) => (
        <Badge variant="outline">v{row.original.version}</Badge>
      ),
    },
    {
      accessorKey: "expiresAt",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Expires" />
      ),
      cell: ({ row }) => {
        if (!row.original.expiresAt) {
          return <span className="text-muted-foreground">Never</span>;
        }
        const expires = new Date(row.original.expiresAt);
        const isExpired = expires < new Date();
        return (
          <div className="flex items-center gap-1">
            <Clock className={`h-3 w-3 ${isExpired ? "text-destructive" : "text-orange-500"}`} />
            <span className={isExpired ? "text-destructive" : ""}>
              {expires.toLocaleDateString()}
            </span>
          </div>
        );
      },
    },
    {
      accessorKey: "modifiedAt",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Updated" />
      ),
      cell: ({ row }) => new Date(row.original.modifiedAt).toLocaleDateString(),
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
            <DropdownMenuItem onClick={() => handleEdit(row.original)}>
              <Edit className="mr-2 h-4 w-4" />
              Edit
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
  const totalEntries = entries.length;
  const namespaceCount = namespaces.length;
  const expiringCount = entries.filter((e) => e.expiresAt).length;

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Key-Value Store</h1>
          <p className="text-muted-foreground">
            Manage distributed key-value pairs with TTL support
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => loadData()} disabled={loading}>
            <RefreshCw
              className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
          <Dialog open={isCreateDialogOpen} onOpenChange={handleDialogClose}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" />
                Add Entry
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>
                  {editingEntry ? "Edit Entry" : "Add New Entry"}
                </DialogTitle>
                <DialogDescription>
                  Store a key-value pair in the distributed store
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 pt-4">
                <div className="space-y-2">
                  <Label htmlFor="key">Key</Label>
                  <Input
                    id="key"
                    placeholder="namespace/my-key"
                    value={formData.key}
                    onChange={(e) =>
                      setFormData((prev) => ({ ...prev, key: e.target.value }))
                    }
                    disabled={!!editingEntry}
                  />
                  <p className="text-xs text-muted-foreground">
                    Use forward slashes to organize keys by namespace (e.g., config/app-settings)
                  </p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="valueType">Value Type</Label>
                  <Select
                    value={formData.valueType}
                    onValueChange={(value) =>
                      setFormData((prev) => ({
                        ...prev,
                        valueType: value as "string" | "json" | "binary",
                      }))
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="string">String</SelectItem>
                      <SelectItem value="json">JSON</SelectItem>
                      <SelectItem value="binary">Binary (Base64)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="value">Value</Label>
                  <Textarea
                    id="value"
                    placeholder={
                      formData.valueType === "json"
                        ? '{"key": "value"}'
                        : formData.valueType === "binary"
                        ? "Base64 encoded data..."
                        : "Enter value..."
                    }
                    value={formData.value}
                    onChange={(e) =>
                      setFormData((prev) => ({ ...prev, value: e.target.value }))
                    }
                    rows={4}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="ttl">TTL (seconds, optional)</Label>
                  <Input
                    id="ttl"
                    type="number"
                    placeholder="3600"
                    value={formData.ttl || ""}
                    onChange={(e) =>
                      setFormData((prev) => ({
                        ...prev,
                        ttl: e.target.value ? parseInt(e.target.value, 10) : undefined,
                      }))
                    }
                  />
                  <p className="text-xs text-muted-foreground">
                    Leave empty for no expiration
                  </p>
                </div>
                <Button
                  onClick={handleSaveEntry}
                  disabled={putMutation.isLoading}
                  className="w-full"
                >
                  {putMutation.isLoading ? "Saving..." : "Save Entry"}
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
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Namespaces</CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{namespaceCount}</div>
            <p className="text-xs text-muted-foreground">
              Logical groupings
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Entries</CardTitle>
            <Key className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalEntries}</div>
            <p className="text-xs text-muted-foreground">
              Key-value pairs stored
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">With TTL</CardTitle>
            <Clock className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
              {expiringCount}
            </div>
            <p className="text-xs text-muted-foreground">
              Keys with expiration
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Filters</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-4">
            <div className="flex-1">
              <Input
                placeholder="Filter by key prefix..."
                value={prefixFilter}
                onChange={(e) => setPrefixFilter(e.target.value)}
              />
            </div>
            <div className="w-48">
              <Select
                value={prefixFilter || "all"}
                onValueChange={(value) =>
                  setPrefixFilter(value === "all" ? "" : value)
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="All namespaces" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All namespaces</SelectItem>
                  {namespaces
                    .filter((ns) => ns && ns.length > 0)
                    .map((ns) => (
                      <SelectItem key={ns} value={`${ns}/`}>
                        {ns}
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
            </div>
            {prefixFilter && (
              <Button variant="ghost" onClick={() => setPrefixFilter("")}>
                Clear filters
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Entries Table */}
      <Card>
        <CardHeader>
          <CardTitle>Entries</CardTitle>
          <CardDescription>
            Browse and manage key-value pairs across namespaces
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={entries}
            searchKey="key"
            searchPlaceholder="Filter entries..."
            loading={loading}
            emptyState={
              <div className="flex flex-col items-center gap-2 py-8">
                <Key className="h-12 w-12 text-muted-foreground" />
                <p className="text-muted-foreground">No entries found</p>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setIsCreateDialogOpen(true)}
                >
                  <Plus className="mr-2 h-4 w-4" />
                  Add your first entry
                </Button>
              </div>
            }
            bulkActions={[
              {
                label: "Delete selected",
                onClick: async (rows) => {
                  if (
                    confirm(
                      `Delete ${rows.length} selected entries? This action cannot be undone.`
                    )
                  ) {
                    for (const row of rows) {
                      await deleteMutation.mutateAsync(row.key).catch(() => undefined);
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
