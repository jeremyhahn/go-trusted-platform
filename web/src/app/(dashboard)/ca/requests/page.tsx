"use client";

import * as React from "react";
import { ColumnDef } from "@tanstack/react-table";
import { DataTable, createSelectColumn } from "@/components/ui/data-table";
import { DataTableColumnHeader } from "@/components/ui/data-table-column-header";
import { DataTableRowActions } from "@/components/ui/data-table-row-actions";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { CSRViewer } from "@/components/features/ca/csr-viewer";
import { useCA, useApi, useMutation, useToast, type MutationError } from "@/hooks";
import type { CertificateRequest } from "@/types/security";
import type { TypedFilterColumn, TypedRowAction } from "@/components/ui/data-table.types";
import { AlertCircle, CheckCircle, XCircle, RefreshCw } from "lucide-react";

/**
 * Certificate Requests Page
 *
 * Features:
 * - View all certificate requests
 * - Approve/deny requests
 * - View CSR details
 * - Filter by status
 */
export default function CertificateRequestsPage() {
  const ca = useCA();
  const { toast } = useToast();
  const [selectedRequest, setSelectedRequest] = React.useState<CertificateRequest | null>(null);
  const [isCSRDialogOpen, setIsCSRDialogOpen] = React.useState(false);

  // TODO: CSR management methods (listCSRs, approveCSR, rejectCSR) are not yet
  // implemented in the SDK. Using placeholder data for now.
  // Track in issue: Add CSR management to CA service
  const [requests, setRequests] = React.useState<CertificateRequest[]>([]);
  const loading = false;
  const error = null as Error | null;
  const refetch = () => {
    // TODO: Implement when SDK supports CSR listing
    console.log("Refetch CSRs - not yet implemented");
  };

  // Placeholder mutation for approving CSRs
  const approveMutation = useMutation(
    async (id: string) => {
      // TODO: Replace with actual SDK method when available
      // For now, simulate approval by removing from pending requests
      setRequests(prev => prev.map(req =>
        req.id === id ? { ...req, status: "approved" as const } : req
      ));
      return { success: true };
    },
    {
      onSuccess: () => {
        toast({
          title: "Success",
          description: "Certificate request approved and certificate issued",
        });
        refetch();
      },
      onError: (err: MutationError) => {
        toast({
          title: "Error",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Placeholder mutation for rejecting CSRs
  const denyMutation = useMutation(
    async (id: string) => {
      // TODO: Replace with actual SDK method when available
      // For now, simulate denial by updating status
      setRequests(prev => prev.map(req =>
        req.id === id ? { ...req, status: "denied" as const } : req
      ));
      return { success: true };
    },
    {
      onSuccess: () => {
        toast({
          title: "Success",
          description: "Certificate request denied",
        });
        refetch();
      },
      onError: (err: MutationError) => {
        toast({
          title: "Error",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // The row-actions column closes over these; memoize them so the columns
  // memo below has a dependency list that matches what it reads.
  const handleViewCSR = React.useCallback((request: CertificateRequest) => {
    setSelectedRequest(request);
    setIsCSRDialogOpen(true);
  }, []);

  const handleApprove = React.useCallback(
    (request: CertificateRequest) => {
      if (!confirm(`Approve certificate request from ${request.requester}?`)) {
        return;
      }
      approveMutation.mutate(request.id);
    },
    [approveMutation]
  );

  const handleDeny = React.useCallback(
    (request: CertificateRequest) => {
      const reason = prompt("Enter denial reason:");
      if (!reason) return;
      denyMutation.mutate(request.id);
    },
    [denyMutation]
  );

  const columns: ColumnDef<CertificateRequest>[] = React.useMemo(
    () => [
      createSelectColumn<CertificateRequest>(),
      {
        accessorKey: "requester",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Requester" />
        ),
        cell: ({ row }) => (
          <div className="font-medium">{row.getValue("requester")}</div>
        ),
      },
      {
        accessorKey: "subject",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Subject" />
        ),
        cell: ({ row }) => (
          <div className="max-w-[300px] truncate font-mono text-sm">
            {row.getValue("subject")}
          </div>
        ),
      },
      {
        accessorKey: "type",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Type" />
        ),
        cell: ({ row }) => {
          const type = row.getValue("type") as string;
          return (
            <Badge variant="outline" className="capitalize">
              {type}
            </Badge>
          );
        },
      },
      {
        accessorKey: "requestedAt",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Requested At" />
        ),
        cell: ({ row }) => {
          const date = new Date(row.getValue("requestedAt"));
          return (
            <div className="text-sm">
              <div>{date.toLocaleDateString()}</div>
              <div className="text-xs text-muted-foreground">
                {date.toLocaleTimeString()}
              </div>
            </div>
          );
        },
      },
      {
        accessorKey: "status",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Status" />
        ),
        cell: ({ row }) => {
          const status = row.getValue("status") as string;
          return (
            <Badge
              variant={
                status === "approved"
                  ? "default"
                  : status === "denied"
                  ? "destructive"
                  : "secondary"
              }
            >
              {status}
            </Badge>
          );
        },
      },
      {
        id: "actions",
        cell: ({ row }) => {
          const request = row.original;
          const actions: TypedRowAction<CertificateRequest>[] = [
            {
              label: "View CSR",
              onClick: handleViewCSR,
            },
          ];

          if (request.status === "pending") {
            actions.push(
              {
                label: "Approve",
                onClick: handleApprove,
                icon: CheckCircle,
                separator: true,
              },
              {
                label: "Deny",
                onClick: handleDeny,
                variant: "destructive",
                icon: XCircle,
              }
            );
          }

          return <DataTableRowActions row={row.original} actions={actions} />;
        },
      },
    ],
    [handleViewCSR, handleApprove, handleDeny]
  );

  const filterableColumns: TypedFilterColumn<CertificateRequest>[] = [
    {
      id: "type",
      title: "Type",
      options: [
        { label: "Root", value: "root" },
        { label: "Intermediate", value: "intermediate" },
        { label: "Leaf", value: "leaf" },
      ],
    },
    {
      id: "status",
      title: "Status",
      options: [
        { label: "Pending", value: "pending" },
        { label: "Approved", value: "approved" },
        { label: "Denied", value: "denied" },
      ],
    },
  ];

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Certificate Requests</h1>
          <p className="text-muted-foreground">
            Review and manage certificate signing requests
          </p>
        </div>
        <Button variant="outline" onClick={() => refetch()} disabled={loading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
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

      {/* Requests Table */}
      <DataTable
        columns={columns}
        data={requests}
        searchKey="subject"
        searchPlaceholder="Search by subject..."
        filterableColumns={filterableColumns}
        pagination
        pageSize={10}
        loading={loading}
      />

      {/* CSR Viewer Dialog */}
      <Dialog open={isCSRDialogOpen} onOpenChange={setIsCSRDialogOpen}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>Certificate Signing Request</DialogTitle>
            <DialogDescription>
              Review the CSR details before approving or denying
            </DialogDescription>
          </DialogHeader>
          {selectedRequest && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4 p-4 bg-muted rounded-lg">
                <div>
                  <div className="text-sm font-medium text-muted-foreground">Requester</div>
                  <div className="mt-1 text-sm">{selectedRequest.requester}</div>
                </div>
                <div>
                  <div className="text-sm font-medium text-muted-foreground">Type</div>
                  <div className="mt-1 text-sm capitalize">{selectedRequest.type}</div>
                </div>
              </div>
              <CSRViewer csr={selectedRequest.csr} subject={selectedRequest.subject} />
              {selectedRequest.status === "pending" && (
                <div className="flex justify-end gap-2">
                  <Button
                    variant="outline"
                    onClick={() => {
                      setIsCSRDialogOpen(false);
                      handleDeny(selectedRequest);
                    }}
                  >
                    <XCircle className="mr-2 h-4 w-4" />
                    Deny
                  </Button>
                  <Button
                    onClick={() => {
                      setIsCSRDialogOpen(false);
                      handleApprove(selectedRequest);
                    }}
                  >
                    <CheckCircle className="mr-2 h-4 w-4" />
                    Approve
                  </Button>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
