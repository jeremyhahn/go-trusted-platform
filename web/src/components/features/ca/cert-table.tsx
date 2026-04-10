"use client";

import * as React from "react";
import { ColumnDef } from "@tanstack/react-table";
import { DataTable, createSelectColumn } from "@/components/ui/data-table";
import { DataTableColumnHeader } from "@/components/ui/data-table-column-header";
import { DataTableRowActions } from "@/components/ui/data-table-row-actions";
import { Badge } from "@/components/ui/badge";
import type { Certificate } from "@/types/security";
import type { TypedFilterColumn, TypedRowAction } from "@/components/ui/data-table.types";
import { RefreshCw, Download, Eye, XCircle } from "lucide-react";

interface CertTableProps {
  certificates: Certificate[];
  onView?: (cert: Certificate) => void;
  onDownload?: (cert: Certificate) => void;
  onRevoke?: (cert: Certificate) => void;
  onRenew?: (cert: Certificate) => void;
  loading?: boolean;
}

/**
 * Certificate table component with filtering and actions
 *
 * Features:
 * - Sortable columns
 * - Filter by type and status
 * - Row actions (view, download, revoke, renew)
 * - Status badges with semantic colors
 */
export function CertTable({
  certificates,
  onView,
  onDownload,
  onRevoke,
  onRenew,
  loading = false,
}: CertTableProps) {
  const columns: ColumnDef<Certificate>[] = React.useMemo(
    () => [
      createSelectColumn<Certificate>(),
      {
        accessorKey: "subject",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Subject" />
        ),
        cell: ({ row }) => (
          <div className="max-w-[300px] truncate font-medium">
            {row.getValue("subject")}
          </div>
        ),
      },
      {
        accessorKey: "issuer",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Issuer" />
        ),
        cell: ({ row }) => (
          <div className="max-w-[250px] truncate text-sm text-muted-foreground">
            {row.getValue("issuer")}
          </div>
        ),
      },
      {
        accessorKey: "serialNumber",
        header: "Serial Number",
        cell: ({ row }) => (
          <code className="text-xs bg-muted px-2 py-1 rounded">
            {row.getValue("serialNumber")}
          </code>
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
        accessorKey: "status",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Status" />
        ),
        cell: ({ row }) => {
          const status = row.getValue("status") as string;
          return (
            <Badge
              variant={
                status === "active"
                  ? "default"
                  : status === "revoked"
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
        accessorKey: "notAfter",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Expires" />
        ),
        cell: ({ row }) => {
          const date = new Date(row.getValue("notAfter"));
          const now = new Date();
          const isExpired = date < now;
          const isExpiringSoon = date.getTime() - now.getTime() < 30 * 24 * 60 * 60 * 1000; // 30 days

          return (
            <div className="flex flex-col">
              <span className={isExpired ? "text-destructive" : isExpiringSoon ? "text-orange-500" : ""}>
                {date.toLocaleDateString()}
              </span>
              {isExpiringSoon && !isExpired && (
                <span className="text-xs text-orange-500">Expiring soon</span>
              )}
            </div>
          );
        },
      },
      {
        id: "actions",
        cell: ({ row }) => {
          const cert = row.original;
          const actions: TypedRowAction<Certificate>[] = [];

          if (onView) {
            actions.push({
              label: "View Details",
              onClick: onView,
              icon: Eye,
            });
          }

          if (onDownload) {
            actions.push({
              label: "Download",
              onClick: onDownload,
              icon: Download,
            });
          }

          if (onRenew && cert.status === "active") {
            actions.push({
              label: "Renew",
              onClick: onRenew,
              icon: RefreshCw,
              separator: actions.length > 0,
            });
          }

          if (onRevoke && cert.status === "active") {
            actions.push({
              label: "Revoke",
              onClick: onRevoke,
              variant: "destructive",
              icon: XCircle,
              separator: true,
            });
          }

          return <DataTableRowActions row={row.original} actions={actions} />;
        },
      },
    ],
    [onView, onDownload, onRevoke, onRenew]
  );

  const filterableColumns: TypedFilterColumn<Certificate>[] = [
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
        { label: "Active", value: "active" },
        { label: "Revoked", value: "revoked" },
        { label: "Expired", value: "expired" },
      ],
    },
  ];

  return (
    <DataTable
      columns={columns}
      data={certificates}
      searchKey="subject"
      searchPlaceholder="Search certificates by subject..."
      filterableColumns={filterableColumns}
      pagination
      pageSize={10}
      loading={loading}
    />
  );
}
