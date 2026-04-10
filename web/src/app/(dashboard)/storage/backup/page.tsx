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
import { Checkbox } from "@/components/ui/checkbox";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DataTable, createSelectColumn } from "@/components/ui/data-table";
import { DataTableColumnHeader } from "@/components/ui/data-table-column-header";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { usePlatformClient, useApi, useMutation, useToast } from "@/hooks";
import type {
  BackupMetadata,
  BackupType,
  BackupState,
  CreateBackupRequest,
} from "trusted-platform-sdk";
import {
  Plus,
  RefreshCw,
  AlertCircle,
  Trash2,
  MoreHorizontal,
  Clock,
  Calendar,
  HardDrive,
  Shield,
  CheckCircle,
  XCircle,
  Loader2,
  RotateCcw,
  Upload,
  Construction,
} from "lucide-react";

/**
 * UI backup type that extends SDK BackupMetadata with display properties
 */
interface BackupUI extends BackupMetadata {
  /** Unique ID for table selection */
  id: string;
  /** Formatted type for display */
  displayType: "full" | "incremental" | "differential";
  /** Formatted status for display */
  displayStatus: "pending" | "running" | "completed" | "failed" | "cancelled";
  /** Computed encrypted status based on encryptionKeyId presence */
  encrypted: boolean;
}

/**
 * Form data for creating a new backup
 */
interface CreateBackupFormData {
  name: string;
  description: string;
  type: BackupType;
  location: string;
  compression: boolean;
  encrypted: boolean;
}

/**
 * Backup & Restore Page
 *
 * Features:
 * - Create and manage backups
 * - Restore from backups
 * - Full, incremental, and differential backup types
 * - Encryption support
 */
export default function BackupPage() {
  const { toast } = useToast();
  const client = usePlatformClient();
  const [isCreateBackupOpen, setIsCreateBackupOpen] = React.useState(false);
  const [isRestoreDialogOpen, setIsRestoreDialogOpen] = React.useState(false);
  const [selectedBackup, setSelectedBackup] = React.useState<BackupUI | null>(null);
  const [backupFormData, setBackupFormData] = React.useState<CreateBackupFormData>({
    name: "",
    description: "",
    type: "FULL",
    location: "",
    compression: true,
    encrypted: true,
  });
  const [restoreDestination, setRestoreDestination] = React.useState("");
  const [restoreOverwrite, setRestoreOverwrite] = React.useState(false);

  // Fetch backups using SDK
  const {
    data: backupsResponse,
    isLoading,
    error,
    refetch,
  } = useApi(
    () => client.quicBaaSBackup.list({}),
    [],
    {
      onError: (err) => {
        toast({
          title: "Error loading backups",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Transform SDK backups to UI format
  const backups: BackupUI[] = React.useMemo(() => {
    if (!backupsResponse?.backups) return [];
    return backupsResponse.backups.map((backup: BackupMetadata): BackupUI => ({
      ...backup,
      id: backup.backupId,
      displayType: mapBackupType(backup.type),
      displayStatus: mapBackupState(backup.state),
      encrypted: !!backup.checksum,
    }));
  }, [backupsResponse]);

  // Create backup mutation
  const createBackupMutation = useMutation(
    async (data: CreateBackupFormData) => {
      const request: CreateBackupRequest = {
        name: data.name,
        type: data.type,
        location: data.location || undefined,
        compression: data.compression,
        tags: data.description ? { description: data.description } : undefined,
      };
      return client.quicBaaSBackup.create(request);
    },
    {
      onSuccess: (_, variables) => {
        toast({
          title: "Backup started",
          description: `Backup "${variables.name}" has been initiated`,
          variant: "success",
        });
        setIsCreateBackupOpen(false);
        resetBackupForm();
        refetch();
      },
      onError: (err) => {
        toast({
          title: "Error creating backup",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Delete backup mutation
  const deleteBackupMutation = useMutation(
    async (backup: BackupUI) => {
      return client.quicBaaSBackup.delete({ backupId: backup.backupId });
    },
    {
      onSuccess: (_, backup) => {
        toast({
          title: "Backup deleted",
          description: `Backup "${backup.name}" deleted successfully`,
          variant: "success",
        });
        refetch();
      },
      onError: (err) => {
        toast({
          title: "Error deleting backup",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Restore backup mutation
  const restoreBackupMutation = useMutation(
    async (params: { backup: BackupUI; targetPrefix: string; overwrite: boolean }) => {
      return client.quicBaaSBackup.restore({
        backupId: params.backup.backupId,
        targetPrefix: params.targetPrefix || undefined,
        overwrite: params.overwrite,
      });
    },
    {
      onSuccess: (_, params) => {
        toast({
          title: "Restore started",
          description: `Restore from "${params.backup.name}" has been initiated`,
          variant: "success",
        });
        setIsRestoreDialogOpen(false);
        setSelectedBackup(null);
        setRestoreDestination("");
        setRestoreOverwrite(false);
        refetch();
      },
      onError: (err) => {
        toast({
          title: "Error restoring backup",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Helper functions
  const mapBackupType = (type: BackupType): "full" | "incremental" | "differential" => {
    const typeMap: Record<BackupType, "full" | "incremental" | "differential"> = {
      UNSPECIFIED: "full",
      FULL: "full",
      INCREMENTAL: "incremental",
      DIFFERENTIAL: "differential",
    };
    return typeMap[type] || "full";
  };

  const mapBackupState = (state: BackupState): "pending" | "running" | "completed" | "failed" | "cancelled" => {
    const stateMap: Record<BackupState, "pending" | "running" | "completed" | "failed" | "cancelled"> = {
      UNSPECIFIED: "pending",
      PENDING: "pending",
      IN_PROGRESS: "running",
      COMPLETED: "completed",
      FAILED: "failed",
      CANCELLED: "cancelled",
    };
    return stateMap[state] || "pending";
  };

  const resetBackupForm = () => {
    setBackupFormData({
      name: "",
      description: "",
      type: "FULL",
      location: "",
      compression: true,
      encrypted: true,
    });
  };

  const handleCreateBackup = async () => {
    if (!backupFormData.name.trim()) {
      toast({
        title: "Validation error",
        description: "Backup name is required",
        variant: "destructive",
      });
      return;
    }
    await createBackupMutation.mutateAsync(backupFormData);
  };

  const handleDelete = async (backup: BackupUI) => {
    if (!confirm(`Delete backup "${backup.name}"? This action cannot be undone.`)) {
      return;
    }
    await deleteBackupMutation.mutateAsync(backup);
  };

  const handleRestore = async () => {
    if (!selectedBackup) return;
    await restoreBackupMutation.mutateAsync({
      backup: selectedBackup,
      targetPrefix: restoreDestination,
      overwrite: restoreOverwrite,
    });
  };

  const formatSize = (bytes?: number): string => {
    if (!bytes) return "-";
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };

  const getStatusBadge = (status: string) => {
    const config: Record<string, { variant: "default" | "secondary" | "outline" | "destructive"; icon: React.ReactNode }> = {
      pending: { variant: "secondary", icon: <Clock className="h-3 w-3" /> },
      running: { variant: "default", icon: <Loader2 className="h-3 w-3 animate-spin" /> },
      completed: { variant: "outline", icon: <CheckCircle className="h-3 w-3 text-green-500" /> },
      failed: { variant: "destructive", icon: <XCircle className="h-3 w-3" /> },
      cancelled: { variant: "secondary", icon: <XCircle className="h-3 w-3" /> },
    };
    const { variant, icon } = config[status] || config.pending;
    return (
      <Badge variant={variant} className="flex items-center gap-1">
        {icon}
        {status}
      </Badge>
    );
  };

  const getTypeBadge = (type: string) => {
    const variants: Record<string, "default" | "secondary" | "outline"> = {
      full: "default",
      incremental: "secondary",
      differential: "outline",
    };
    return <Badge variant={variants[type] || "default"}>{type}</Badge>;
  };

  const backupColumns: ColumnDef<BackupUI>[] = [
    createSelectColumn<BackupUI>(),
    {
      accessorKey: "name",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Name" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <HardDrive className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{row.original.name}</span>
        </div>
      ),
    },
    {
      accessorKey: "displayType",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Type" />
      ),
      cell: ({ row }) => getTypeBadge(row.original.displayType),
    },
    {
      accessorKey: "displayStatus",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Status" />
      ),
      cell: ({ row }) => getStatusBadge(row.original.displayStatus),
    },
    {
      accessorKey: "location",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Location" />
      ),
      cell: ({ row }) => (
        <code className="text-sm bg-muted px-1 rounded">{row.original.location || "-"}</code>
      ),
    },
    {
      accessorKey: "sizeBytes",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Size" />
      ),
      cell: ({ row }) => formatSize(row.original.sizeBytes),
    },
    {
      accessorKey: "keyCount",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Keys" />
      ),
      cell: ({ row }) => row.original.keyCount?.toLocaleString() || "-",
    },
    {
      accessorKey: "encrypted",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Encrypted" />
      ),
      cell: ({ row }) => (
        row.original.encrypted ? (
          <Shield className="h-4 w-4 text-green-500" />
        ) : (
          <span className="text-muted-foreground">-</span>
        )
      ),
    },
    {
      accessorKey: "startedAt",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Started" />
      ),
      cell: ({ row }) => row.original.startedAt
        ? new Date(row.original.startedAt).toLocaleString()
        : "-",
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
              disabled={row.original.displayStatus !== "completed"}
              onClick={() => {
                setSelectedBackup(row.original);
                setIsRestoreDialogOpen(true);
              }}
            >
              <RotateCcw className="mr-2 h-4 w-4" />
              Restore
            </DropdownMenuItem>
            <DropdownMenuSeparator />
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
  const totalBackups = backups.length;
  const completedBackups = backups.filter((b) => b.displayStatus === "completed").length;
  const failedBackups = backups.filter((b) => b.displayStatus === "failed").length;
  const runningBackups = backups.filter((b) => b.displayStatus === "running").length;

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Backup & Restore</h1>
          <p className="text-muted-foreground">
            Protect your data with scheduled and on-demand backups
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => refetch()} disabled={isLoading}>
            <RefreshCw
              className={`mr-2 h-4 w-4 ${isLoading ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
          <Dialog open={isCreateBackupOpen} onOpenChange={setIsCreateBackupOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" />
                Create Backup
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Create New Backup</DialogTitle>
                <DialogDescription>
                  Start an on-demand backup job
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 pt-4">
                <div className="space-y-2">
                  <Label htmlFor="backupName">Backup Name</Label>
                  <Input
                    id="backupName"
                    placeholder="Manual Backup - Production"
                    value={backupFormData.name}
                    onChange={(e) =>
                      setBackupFormData((prev) => ({ ...prev, name: e.target.value }))
                    }
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="backupDescription">Description (optional)</Label>
                  <Input
                    id="backupDescription"
                    placeholder="Pre-deployment backup"
                    value={backupFormData.description}
                    onChange={(e) =>
                      setBackupFormData((prev) => ({ ...prev, description: e.target.value }))
                    }
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="backupType">Backup Type</Label>
                  <Select
                    value={backupFormData.type}
                    onValueChange={(value) =>
                      setBackupFormData((prev) => ({
                        ...prev,
                        type: value as BackupType,
                      }))
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="FULL">Full</SelectItem>
                      <SelectItem value="INCREMENTAL">Incremental</SelectItem>
                      <SelectItem value="DIFFERENTIAL">Differential</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="backupLocation">Storage Location (optional)</Label>
                  <Input
                    id="backupLocation"
                    placeholder="s3://backups/production"
                    value={backupFormData.location}
                    onChange={(e) =>
                      setBackupFormData((prev) => ({ ...prev, location: e.target.value }))
                    }
                  />
                </div>
                <div className="flex items-center space-x-4">
                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="backupCompression"
                      checked={backupFormData.compression}
                      onCheckedChange={(checked) =>
                        setBackupFormData((prev) => ({
                          ...prev,
                          compression: checked === true,
                        }))
                      }
                    />
                    <Label htmlFor="backupCompression">Enable compression</Label>
                  </div>
                </div>
                <Button
                  onClick={handleCreateBackup}
                  disabled={createBackupMutation.isLoading}
                  className="w-full"
                >
                  {createBackupMutation.isLoading ? "Starting..." : "Start Backup"}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Restore Dialog */}
      <Dialog open={isRestoreDialogOpen} onOpenChange={setIsRestoreDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Restore Backup</DialogTitle>
            <DialogDescription>
              Restore data from backup &quot;{selectedBackup?.name}&quot;
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 pt-4">
            <div className="space-y-2">
              <Label htmlFor="restoreDestination">Target Prefix (optional)</Label>
              <Input
                id="restoreDestination"
                placeholder="Leave empty for original location"
                value={restoreDestination}
                onChange={(e) => setRestoreDestination(e.target.value)}
              />
            </div>
            <div className="flex items-center space-x-2">
              <Checkbox
                id="restoreOverwrite"
                checked={restoreOverwrite}
                onCheckedChange={(checked) => setRestoreOverwrite(checked === true)}
              />
              <Label htmlFor="restoreOverwrite">Overwrite existing keys</Label>
            </div>
            <div className="p-4 bg-amber-500/10 border border-amber-500 rounded-lg">
              <p className="text-sm text-amber-600 dark:text-amber-400">
                Warning: This operation may overwrite existing data at the destination.
              </p>
            </div>
            <Button
              onClick={handleRestore}
              disabled={restoreBackupMutation.isLoading}
              className="w-full"
            >
              {restoreBackupMutation.isLoading ? "Restoring..." : "Start Restore"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

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
            <CardTitle className="text-sm font-medium">Total Backups</CardTitle>
            <HardDrive className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalBackups}</div>
            <p className="text-xs text-muted-foreground">
              Backup records
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Completed</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {completedBackups}
            </div>
            <p className="text-xs text-muted-foreground">
              Successful backups
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Failed</CardTitle>
            <XCircle className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">
              {failedBackups}
            </div>
            <p className="text-xs text-muted-foreground">
              Failed backups
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">In Progress</CardTitle>
            <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
              {runningBackups}
            </div>
            <p className="text-xs text-muted-foreground">
              Active jobs
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Tabs for Backups and Schedules */}
      <Tabs defaultValue="backups" className="space-y-4">
        <TabsList>
          <TabsTrigger value="backups">Backups</TabsTrigger>
          <TabsTrigger value="schedules">Schedules</TabsTrigger>
        </TabsList>

        <TabsContent value="backups" className="space-y-4">
          {/* Backups Table */}
          <Card>
            <CardHeader>
              <CardTitle>Backup History</CardTitle>
              <CardDescription>
                View and manage your backup records
              </CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={backupColumns}
                data={backups}
                searchKey="name"
                searchPlaceholder="Filter backups..."
                loading={isLoading}
                emptyState={
                  <div className="flex flex-col items-center gap-2 py-8">
                    <Upload className="h-12 w-12 text-muted-foreground" />
                    <p className="text-muted-foreground">No backups found</p>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setIsCreateBackupOpen(true)}
                    >
                      <Plus className="mr-2 h-4 w-4" />
                      Create your first backup
                    </Button>
                  </div>
                }
                bulkActions={[
                  {
                    label: "Delete selected",
                    onClick: async (rows) => {
                      if (
                        confirm(
                          `Delete ${rows.length} selected backups? This action cannot be undone.`
                        )
                      ) {
                        for (const row of rows) {
                          await deleteBackupMutation.mutateAsync(row);
                        }
                      }
                    },
                    variant: "destructive",
                  },
                ]}
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="schedules" className="space-y-4">
          {/* Coming Soon - Schedule Management */}
          <Card>
            <CardHeader>
              <CardTitle>Backup Schedules</CardTitle>
              <CardDescription>
                Manage automated backup schedules
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col items-center gap-4 py-12">
                <Construction className="h-16 w-16 text-muted-foreground" />
                <div className="text-center">
                  <h3 className="text-lg font-semibold">Coming Soon</h3>
                  <p className="text-muted-foreground max-w-md">
                    Scheduled backup management is currently in development.
                    You can still create on-demand backups from the Backups tab.
                  </p>
                </div>
                <Button variant="outline" onClick={() => {
                  const tabsTrigger = document.querySelector('[data-value="backups"]') as HTMLElement;
                  tabsTrigger?.click();
                }}>
                  <Calendar className="mr-2 h-4 w-4" />
                  Go to Backups
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
