"use client";

import * as React from "react";
import { ColumnDef } from "@tanstack/react-table";
import { DataTable, createSelectColumn } from "@/components/ui/data-table";
import { DataTableColumnHeader } from "@/components/ui/data-table-column-header";
import { DataTableRowActions } from "@/components/ui/data-table-row-actions";
import { Badge } from "@/components/ui/badge";
import type { Key } from "@/types/security";
import type { TypedFilterColumn, TypedRowAction } from "@/components/ui/data-table.types";
import { Eye, RefreshCw, Download, Trash2 } from "lucide-react";

interface KeyTableProps {
  keys: Key[];
  onView?: (key: Key) => void;
  onRotate?: (key: Key) => void;
  onExport?: (key: Key) => void;
  onDelete?: (key: Key) => void;
  loading?: boolean;
}

/**
 * KMS keys table component with filtering and actions
 *
 * Features:
 * - Sortable columns
 * - Filter by algorithm, type, and status
 * - Row actions (view, rotate, export, delete)
 * - Status badges with semantic colors
 * - Algorithm and type indicators
 */
export function KeyTable({
  keys,
  onView,
  onRotate,
  onExport,
  onDelete,
  loading = false,
}: KeyTableProps) {
  const columns: ColumnDef<Key>[] = React.useMemo(
    () => [
      createSelectColumn<Key>(),
      {
        accessorKey: "name",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Name" />
        ),
        cell: ({ row }) => (
          <div className="font-medium">{row.getValue("name")}</div>
        ),
      },
      {
        accessorKey: "algorithm",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Algorithm" />
        ),
        cell: ({ row }) => {
          const algorithm = row.getValue("algorithm") as string;
          return (
            <Badge variant="outline" className="font-mono text-xs">
              {algorithm}
            </Badge>
          );
        },
      },
      {
        accessorKey: "type",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Type" />
        ),
        cell: ({ row }) => {
          const type = row.getValue("type") as string;
          return (
            <Badge variant="secondary" className="capitalize">
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
                  : status === "disabled"
                  ? "secondary"
                  : "destructive"
              }
            >
              {status === "pending_deletion" ? "Pending Deletion" : status}
            </Badge>
          );
        },
      },
      {
        accessorKey: "rotationCount",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Rotations" />
        ),
        cell: ({ row }) => {
          const count = row.getValue("rotationCount") as number;
          return (
            <div className="text-center">
              <span className="text-sm">{count}</span>
            </div>
          );
        },
      },
      {
        accessorKey: "createdAt",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Created" />
        ),
        cell: ({ row }) => {
          const date = new Date(row.getValue("createdAt"));
          return (
            <div className="text-sm text-muted-foreground">
              {date.toLocaleDateString()}
            </div>
          );
        },
      },
      {
        id: "actions",
        cell: ({ row }) => {
          const key = row.original;
          const actions: TypedRowAction<Key>[] = [];

          if (onView) {
            actions.push({
              label: "View Details",
              onClick: onView,
              icon: Eye,
            });
          }

          if (onRotate && key.status === "active") {
            actions.push({
              label: "Rotate Key",
              onClick: onRotate,
              icon: RefreshCw,
            });
          }

          if (onExport && key.status === "active") {
            actions.push({
              label: "Export Key",
              onClick: onExport,
              icon: Download,
              separator: actions.length > 0,
            });
          }

          if (onDelete && key.status !== "pending_deletion") {
            actions.push({
              label: "Delete Key",
              onClick: onDelete,
              variant: "destructive",
              icon: Trash2,
              separator: true,
            });
          }

          return <DataTableRowActions row={row.original} actions={actions} />;
        },
      },
    ],
    [onView, onRotate, onExport, onDelete]
  );

  const filterableColumns: TypedFilterColumn<Key>[] = [
    {
      id: "algorithm",
      title: "Algorithm",
      options: [
        { label: "AES-256", value: "AES-256" },
        { label: "RSA-2048", value: "RSA-2048" },
        { label: "RSA-4096", value: "RSA-4096" },
        { label: "ECDSA-P256", value: "ECDSA-P256" },
        { label: "ECDSA-P384", value: "ECDSA-P384" },
      ],
    },
    {
      id: "type",
      title: "Type",
      options: [
        { label: "Symmetric", value: "symmetric" },
        { label: "Asymmetric", value: "asymmetric" },
      ],
    },
    {
      id: "status",
      title: "Status",
      options: [
        { label: "Active", value: "active" },
        { label: "Disabled", value: "disabled" },
        { label: "Pending Deletion", value: "pending_deletion" },
      ],
    },
  ];

  return (
    <DataTable
      columns={columns}
      data={keys}
      searchKey="name"
      searchPlaceholder="Search keys by name..."
      filterableColumns={filterableColumns}
      pagination
      pageSize={10}
      loading={loading}
    />
  );
}
