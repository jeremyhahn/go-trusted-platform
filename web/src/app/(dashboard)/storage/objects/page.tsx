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
import { DataTable, createSelectColumn } from "@/components/ui/data-table";
import { DataTableColumnHeader } from "@/components/ui/data-table-column-header";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { usePlatformClient, useApi, useMutation, useToast } from "@/hooks";
import type {
  StoredObject,
  StorageBucket,
  StorageClass,
} from "trusted-platform-sdk";
import {
  Plus,
  RefreshCw,
  AlertCircle,
  FolderOpen,
  File,
  Download,
  Trash2,
  MoreHorizontal,
  HardDrive,
  Archive,
  Upload,
} from "lucide-react";

/**
 * UI object type that extends SDK StoredObject with display properties
 */
interface ObjectUI extends StoredObject {
  /** Unique ID for table selection (composed from bucket + key) */
  id: string;
}

/**
 * UI bucket type that maps SDK StorageBucket
 */
interface BucketUI {
  id: string;
  name: string;
  region: string;
  objectCount: number;
  totalSize: number;
  versioning: boolean;
  encryption: boolean;
  createdAt: string;
}

/**
 * Form data for creating a new bucket
 */
interface CreateBucketFormData {
  name: string;
  region?: string;
  versioning?: boolean;
  encryption?: boolean;
}

/**
 * Form data for uploading an object
 */
interface UploadFormData {
  bucket: string;
  key: string;
  file: File | null;
  storageClass: StorageClass;
}

/**
 * Object Storage Browser Page
 *
 * Features:
 * - Browse buckets and objects (S3-like interface)
 * - Upload and download objects
 * - Create and manage buckets
 * - Filter by bucket and prefix
 * - View object metadata
 */
export default function ObjectStoragePage() {
  const { toast } = useToast();
  const client = usePlatformClient();
  const [selectedBucket, setSelectedBucket] = React.useState<string>("");
  const [prefixFilter, setPrefixFilter] = React.useState<string>("");
  const [isCreateBucketOpen, setIsCreateBucketOpen] = React.useState(false);
  const [isUploadOpen, setIsUploadOpen] = React.useState(false);
  const [bucketFormData, setBucketFormData] = React.useState<CreateBucketFormData>({
    name: "",
    region: "",
    versioning: false,
    encryption: true,
  });
  const [uploadFormData, setUploadFormData] = React.useState<UploadFormData>({
    bucket: "",
    key: "",
    file: null,
    storageClass: "standard",
  });
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  // Fetch buckets using SDK
  const {
    data: bucketsResponse,
    isLoading: bucketsLoading,
    error: bucketsError,
    refetch: refetchBuckets,
  } = useApi(
    () => client.quicBaaSObjectStorageAdmin.listBuckets({}),
    [],
    {
      onError: (err) => {
        toast({
          title: "Error loading buckets",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Transform SDK buckets to UI format
  const buckets: BucketUI[] = React.useMemo(() => {
    if (!bucketsResponse?.buckets) return [];
    return bucketsResponse.buckets.map((bucket: StorageBucket): BucketUI => ({
      id: bucket.name,
      name: bucket.name,
      region: bucket.region || "default",
      objectCount: bucket.objectCount,
      totalSize: bucket.totalSizeBytes,
      versioning: bucket.config?.versioning === "enabled",
      encryption: bucket.config?.encryptionEnabled || false,
      createdAt: bucket.createdAt,
    }));
  }, [bucketsResponse]);

  // Auto-select first bucket when buckets are loaded
  React.useEffect(() => {
    if (buckets.length > 0 && !selectedBucket) {
      setSelectedBucket(buckets[0].name);
    }
  }, [buckets, selectedBucket]);

  // Update upload form bucket when selected bucket changes
  React.useEffect(() => {
    if (selectedBucket) {
      setUploadFormData((prev) => ({ ...prev, bucket: selectedBucket }));
    }
  }, [selectedBucket]);

  // Fetch objects for selected bucket
  const {
    data: objectsResponse,
    isLoading: objectsLoading,
    error: objectsError,
    refetch: refetchObjects,
  } = useApi(
    () =>
      client.quicBaaSObjectStorage.listObjects({
        bucket: selectedBucket || "default",
        prefix: prefixFilter || undefined,
        maxKeys: 100,
      }),
    [selectedBucket, prefixFilter],
    {
      enabled: !!selectedBucket,
      onError: (err) => {
        toast({
          title: "Error loading objects",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Transform SDK objects to UI format
  const objects: ObjectUI[] = React.useMemo(() => {
    if (!objectsResponse?.objects) return [];
    return objectsResponse.objects.map((obj: StoredObject): ObjectUI => ({
      ...obj,
      id: `${obj.bucket}/${obj.key}`,
    }));
  }, [objectsResponse]);

  // Create bucket mutation
  const createBucketMutation = useMutation(
    async (data: CreateBucketFormData) => {
      return client.quicBaaSObjectStorageAdmin.createBucket({
        name: data.name,
        region: data.region || undefined,
        config: {
          versioning: data.versioning ? "enabled" : "disabled",
          encryptionEnabled: data.encryption,
          defaultStorageClass: "standard",
        },
      });
    },
    {
      onSuccess: (_, variables) => {
        toast({
          title: "Bucket created",
          description: `Bucket "${variables.name}" created successfully`,
          variant: "success",
        });
        setIsCreateBucketOpen(false);
        resetBucketForm();
        refetchBuckets();
        // Select the newly created bucket
        setSelectedBucket(variables.name);
      },
      onError: (err) => {
        toast({
          title: "Error creating bucket",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Delete bucket mutation
  const deleteBucketMutation = useMutation(
    async (bucketName: string) => {
      return client.quicBaaSObjectStorageAdmin.deleteBucket({ name: bucketName });
    },
    {
      onSuccess: (_, bucketName) => {
        toast({
          title: "Bucket deleted",
          description: `Bucket "${bucketName}" deleted successfully`,
          variant: "success",
        });
        refetchBuckets();
        // Clear selection if deleted bucket was selected
        if (selectedBucket === bucketName) {
          setSelectedBucket("");
        }
      },
      onError: (err) => {
        toast({
          title: "Error deleting bucket",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Upload object mutation
  const uploadMutation = useMutation(
    async (data: UploadFormData) => {
      if (!data.file) {
        throw new Error("No file selected");
      }
      // Read file as base64
      const content = await fileToBase64(data.file);
      return client.quicBaaSObjectStorage.putObject({
        bucket: data.bucket,
        key: data.key,
        content,
        contentType: data.file.type || "application/octet-stream",
        storageClass: data.storageClass,
      });
    },
    {
      onSuccess: (_, variables) => {
        toast({
          title: "Object uploaded",
          description: `Object "${variables.key}" uploaded successfully`,
          variant: "success",
        });
        setIsUploadOpen(false);
        resetUploadForm();
        refetchObjects();
      },
      onError: (err) => {
        toast({
          title: "Error uploading object",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Delete object mutation
  const deleteObjectMutation = useMutation(
    async (obj: ObjectUI) => {
      return client.quicBaaSObjectStorage.deleteObject({
        bucket: obj.bucket,
        key: obj.key,
      });
    },
    {
      onSuccess: (_, obj) => {
        toast({
          title: "Object deleted",
          description: `Object "${obj.key}" deleted successfully`,
          variant: "success",
        });
        refetchObjects();
      },
      onError: (err) => {
        toast({
          title: "Error deleting object",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Helper to convert file to base64
  const fileToBase64 = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const result = reader.result as string;
        // Remove data URL prefix (e.g., "data:image/png;base64,")
        const base64 = result.split(",")[1] || result;
        resolve(base64);
      };
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  };

  // Reset form helpers
  const resetBucketForm = () => {
    setBucketFormData({
      name: "",
      region: "",
      versioning: false,
      encryption: true,
    });
  };

  const resetUploadForm = () => {
    setUploadFormData({
      bucket: selectedBucket,
      key: "",
      file: null,
      storageClass: "standard",
    });
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  // Handler functions
  const handleCreateBucket = async () => {
    if (!bucketFormData.name.trim()) {
      toast({
        title: "Validation error",
        description: "Bucket name is required",
        variant: "destructive",
      });
      return;
    }
    await createBucketMutation.mutateAsync(bucketFormData);
  };

  const handleDeleteBucket = async (bucket: BucketUI) => {
    if (!confirm(`Delete bucket "${bucket.name}"? This action cannot be undone.`)) {
      return;
    }
    await deleteBucketMutation.mutateAsync(bucket.name);
  };

  const handleUpload = async () => {
    if (!uploadFormData.file) {
      toast({
        title: "Validation error",
        description: "Please select a file to upload",
        variant: "destructive",
      });
      return;
    }
    if (!uploadFormData.key.trim()) {
      toast({
        title: "Validation error",
        description: "Object key is required",
        variant: "destructive",
      });
      return;
    }
    await uploadMutation.mutateAsync(uploadFormData);
  };

  const handleDeleteObject = async (obj: ObjectUI) => {
    if (!confirm(`Delete object "${obj.key}"? This action cannot be undone.`)) {
      return;
    }
    await deleteObjectMutation.mutateAsync(obj);
  };

  const handleDownload = async (obj: ObjectUI) => {
    try {
      const response = await client.quicBaaSObjectStorage.getObject({
        bucket: obj.bucket,
        key: obj.key,
      });
      if (response.error || !response.data) {
        toast({
          title: "Error downloading object",
          description: response.error?.message || "Failed to download object",
          variant: "destructive",
        });
        return;
      }
      // Decode base64 content and trigger download
      const content = response.data.content;
      const blob = base64ToBlob(content, obj.contentType || "application/octet-stream");
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = obj.key.split("/").pop() || obj.key;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      toast({
        title: "Download started",
        description: `Downloading "${obj.key}"`,
        variant: "success",
      });
    } catch (err) {
      toast({
        title: "Error downloading object",
        description: err instanceof Error ? err.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  // Helper to convert base64 to blob
  const base64ToBlob = (base64: string, contentType: string): Blob => {
    const byteCharacters = atob(base64);
    const byteNumbers = new Array(byteCharacters.length);
    for (let i = 0; i < byteCharacters.length; i++) {
      byteNumbers[i] = byteCharacters.charCodeAt(i);
    }
    const byteArray = new Uint8Array(byteNumbers);
    return new Blob([byteArray], { type: contentType });
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setUploadFormData((prev) => ({
        ...prev,
        file,
        key: prev.key || file.name,
      }));
    }
  };

  const handleRefresh = () => {
    refetchBuckets();
    if (selectedBucket) {
      refetchObjects();
    }
  };

  const formatSize = (bytes: number): string => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };

  const getStorageClassBadge = (storageClass: StorageClass) => {
    const variants: Record<string, "default" | "secondary" | "outline"> = {
      standard: "default",
      infrequent_access: "secondary",
      archive: "outline",
      deep_archive: "outline",
    };
    const labels: Record<string, string> = {
      standard: "Standard",
      infrequent_access: "Infrequent",
      archive: "Archive",
      deep_archive: "Deep Archive",
    };
    return (
      <Badge variant={variants[storageClass] || "default"}>
        {labels[storageClass] || storageClass}
      </Badge>
    );
  };

  const columns: ColumnDef<ObjectUI>[] = [
    createSelectColumn<ObjectUI>(),
    {
      accessorKey: "key",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Object Key" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <File className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{row.original.key}</span>
        </div>
      ),
    },
    {
      accessorKey: "bucket",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Bucket" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <FolderOpen className="h-4 w-4 text-muted-foreground" />
          <span>{row.original.bucket}</span>
        </div>
      ),
    },
    {
      accessorKey: "size",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Size" />
      ),
      cell: ({ row }) => formatSize(row.original.size),
    },
    {
      accessorKey: "contentType",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Content Type" />
      ),
      cell: ({ row }) => row.original.contentType || "application/octet-stream",
    },
    {
      accessorKey: "storageClass",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Storage Class" />
      ),
      cell: ({ row }) => getStorageClassBadge(row.original.storageClass),
    },
    {
      accessorKey: "lastModified",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Last Modified" />
      ),
      cell: ({ row }) =>
        new Date(row.original.lastModified).toLocaleDateString(),
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
            <DropdownMenuItem onClick={() => handleDownload(row.original)}>
              <Download className="mr-2 h-4 w-4" />
              Download
            </DropdownMenuItem>
            <DropdownMenuItem
              className="text-destructive"
              onClick={() => handleDeleteObject(row.original)}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ];

  // Calculate storage statistics
  const totalSize = objects.reduce((acc, obj) => acc + obj.size, 0);
  const objectCount = objects.length;
  const bucketCount = buckets.length;
  const loading = bucketsLoading || objectsLoading;
  const error = bucketsError || objectsError;

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Object Storage</h1>
          <p className="text-muted-foreground">
            Browse and manage S3-compatible object storage
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={handleRefresh} disabled={loading}>
            <RefreshCw
              className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
          <Dialog open={isCreateBucketOpen} onOpenChange={setIsCreateBucketOpen}>
            <DialogTrigger asChild>
              <Button variant="outline">
                <FolderOpen className="mr-2 h-4 w-4" />
                Create Bucket
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create New Bucket</DialogTitle>
                <DialogDescription>
                  Create a new storage bucket to organize your objects
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 pt-4">
                <div className="space-y-2">
                  <Label htmlFor="bucketName">Bucket Name</Label>
                  <Input
                    id="bucketName"
                    placeholder="my-bucket"
                    value={bucketFormData.name}
                    onChange={(e) =>
                      setBucketFormData((prev) => ({ ...prev, name: e.target.value }))
                    }
                  />
                  <p className="text-xs text-muted-foreground">
                    Use lowercase letters, numbers, and hyphens only
                  </p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="region">Region (optional)</Label>
                  <Input
                    id="region"
                    placeholder="us-east-1"
                    value={bucketFormData.region}
                    onChange={(e) =>
                      setBucketFormData((prev) => ({ ...prev, region: e.target.value }))
                    }
                  />
                </div>
                <div className="flex items-center gap-4">
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={bucketFormData.versioning}
                      onChange={(e) =>
                        setBucketFormData((prev) => ({ ...prev, versioning: e.target.checked }))
                      }
                      className="rounded border-input"
                    />
                    <span className="text-sm">Enable versioning</span>
                  </label>
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={bucketFormData.encryption}
                      onChange={(e) =>
                        setBucketFormData((prev) => ({ ...prev, encryption: e.target.checked }))
                      }
                      className="rounded border-input"
                    />
                    <span className="text-sm">Enable encryption</span>
                  </label>
                </div>
                <Button
                  onClick={handleCreateBucket}
                  disabled={createBucketMutation.isLoading}
                  className="w-full"
                >
                  {createBucketMutation.isLoading ? "Creating..." : "Create Bucket"}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
          <Dialog open={isUploadOpen} onOpenChange={setIsUploadOpen}>
            <DialogTrigger asChild>
              <Button disabled={!selectedBucket}>
                <Plus className="mr-2 h-4 w-4" />
                Upload Object
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Upload Object</DialogTitle>
                <DialogDescription>
                  Upload a file to the selected bucket
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 pt-4">
                <div className="space-y-2">
                  <Label htmlFor="uploadBucket">Bucket</Label>
                  <Select
                    value={uploadFormData.bucket}
                    onValueChange={(value) =>
                      setUploadFormData((prev) => ({ ...prev, bucket: value }))
                    }
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select bucket" />
                    </SelectTrigger>
                    <SelectContent>
                      {buckets.map((bucket) => (
                        <SelectItem key={bucket.id} value={bucket.name}>
                          {bucket.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="objectKey">Object Key</Label>
                  <Input
                    id="objectKey"
                    placeholder="path/to/file.txt"
                    value={uploadFormData.key}
                    onChange={(e) =>
                      setUploadFormData((prev) => ({ ...prev, key: e.target.value }))
                    }
                  />
                  <p className="text-xs text-muted-foreground">
                    Use forward slashes to organize objects into folders
                  </p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="file">File</Label>
                  <Input
                    id="file"
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileSelect}
                    className="cursor-pointer"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="storageClass">Storage Class</Label>
                  <Select
                    value={uploadFormData.storageClass}
                    onValueChange={(value) =>
                      setUploadFormData((prev) => ({
                        ...prev,
                        storageClass: value as StorageClass,
                      }))
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="standard">Standard</SelectItem>
                      <SelectItem value="infrequent_access">Infrequent Access</SelectItem>
                      <SelectItem value="archive">Archive</SelectItem>
                      <SelectItem value="deep_archive">Deep Archive</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <Button
                  onClick={handleUpload}
                  disabled={uploadMutation.isLoading || !uploadFormData.file}
                  className="w-full"
                >
                  {uploadMutation.isLoading ? (
                    <>
                      <Upload className="mr-2 h-4 w-4 animate-spin" />
                      Uploading...
                    </>
                  ) : (
                    <>
                      <Upload className="mr-2 h-4 w-4" />
                      Upload
                    </>
                  )}
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
            <CardTitle className="text-sm font-medium">Total Buckets</CardTitle>
            <FolderOpen className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{bucketCount}</div>
            <p className="text-xs text-muted-foreground">
              Storage containers
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Objects</CardTitle>
            <File className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{objectCount}</div>
            <p className="text-xs text-muted-foreground">
              {selectedBucket ? `In "${selectedBucket}"` : "Select a bucket"}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Size</CardTitle>
            <HardDrive className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{formatSize(totalSize)}</div>
            <p className="text-xs text-muted-foreground">
              Storage used
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
            <div className="w-48">
              <Select
                value={selectedBucket || "none"}
                onValueChange={(value) => {
                  setSelectedBucket(value === "none" ? "" : value);
                  setPrefixFilter("");
                }}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select bucket" />
                </SelectTrigger>
                <SelectContent>
                  {buckets.length === 0 ? (
                    <SelectItem value="none" disabled>
                      No buckets available
                    </SelectItem>
                  ) : (
                    buckets.map((bucket) => (
                      <SelectItem key={bucket.id} value={bucket.name}>
                        {bucket.name}
                      </SelectItem>
                    ))
                  )}
                </SelectContent>
              </Select>
            </div>
            <div className="flex-1">
              <Input
                placeholder="Filter by prefix..."
                value={prefixFilter}
                onChange={(e) => setPrefixFilter(e.target.value)}
                disabled={!selectedBucket}
              />
            </div>
            {(selectedBucket || prefixFilter) && (
              <Button
                variant="ghost"
                onClick={() => {
                  setPrefixFilter("");
                }}
              >
                Clear prefix
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Buckets List (collapsible) */}
      {buckets.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Buckets</CardTitle>
            <CardDescription>
              Select a bucket to browse its objects
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {buckets.map((bucket) => (
                <div
                  key={bucket.id}
                  className={`flex items-center gap-2 p-2 rounded-lg border cursor-pointer transition-colors ${
                    selectedBucket === bucket.name
                      ? "bg-primary/10 border-primary"
                      : "hover:bg-muted"
                  }`}
                  onClick={() => setSelectedBucket(bucket.name)}
                >
                  <FolderOpen className="h-4 w-4" />
                  <span className="font-medium">{bucket.name}</span>
                  <Badge variant="outline" className="ml-1">
                    {bucket.objectCount} objects
                  </Badge>
                  {bucket.versioning && (
                    <Badge variant="secondary" className="text-xs">V</Badge>
                  )}
                  {bucket.encryption && (
                    <Badge variant="secondary" className="text-xs">E</Badge>
                  )}
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6 ml-1"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleDeleteBucket(bucket);
                    }}
                  >
                    <Trash2 className="h-3 w-3 text-destructive" />
                  </Button>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Objects Table */}
      <Card>
        <CardHeader>
          <CardTitle>Objects</CardTitle>
          <CardDescription>
            {selectedBucket
              ? `Browse objects in "${selectedBucket}"`
              : "Select a bucket to view objects"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={objects}
            searchKey="key"
            searchPlaceholder="Filter objects..."
            loading={loading}
            emptyState={
              <div className="flex flex-col items-center gap-2 py-8">
                <Archive className="h-12 w-12 text-muted-foreground" />
                <p className="text-muted-foreground">
                  {selectedBucket
                    ? "No objects found in this bucket"
                    : "Select a bucket to view objects"}
                </p>
                {selectedBucket && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setIsUploadOpen(true)}
                  >
                    <Plus className="mr-2 h-4 w-4" />
                    Upload your first object
                  </Button>
                )}
                {!selectedBucket && buckets.length === 0 && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setIsCreateBucketOpen(true)}
                  >
                    <Plus className="mr-2 h-4 w-4" />
                    Create your first bucket
                  </Button>
                )}
              </div>
            }
            bulkActions={[
              {
                label: "Delete selected",
                onClick: async (rows) => {
                  if (
                    confirm(
                      `Delete ${rows.length} selected objects? This action cannot be undone.`
                    )
                  ) {
                    for (const row of rows) {
                      await deleteObjectMutation.mutateAsync(row);
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
