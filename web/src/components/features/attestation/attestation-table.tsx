"use client";

import * as React from "react";
import { ColumnDef } from "@tanstack/react-table";
import { DataTable, createSelectColumn } from "@/components/ui/data-table";
import { DataTableColumnHeader } from "@/components/ui/data-table-column-header";
import { DataTableRowActions } from "@/components/ui/data-table-row-actions";
import { Badge } from "@/components/ui/badge";
import type { Attestation } from "@/types/security";
import type { TypedFilterColumn, TypedRowAction } from "@/components/ui/data-table.types";
import { Eye, ShieldCheck, RefreshCw } from "lucide-react";

interface AttestationTableProps {
  attestations: Attestation[];
  onView?: (attestation: Attestation) => void;
  onVerify?: (attestation: Attestation) => void;
  onRequestAttestation?: (attestation: Attestation) => void;
  loading?: boolean;
}

/**
 * Attestation reports table component with filtering and actions
 *
 * Features:
 * - Sortable columns
 * - Filter by status
 * - Row actions (view, verify, request new attestation)
 * - Status badges with semantic colors
 * - Device information display
 */
export function AttestationTable({
  attestations,
  onView,
  onVerify,
  onRequestAttestation,
  loading = false,
}: AttestationTableProps) {
  const columns: ColumnDef<Attestation>[] = React.useMemo(
    () => [
      createSelectColumn<Attestation>(),
      {
        accessorKey: "deviceName",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Device" />
        ),
        cell: ({ row }) => (
          <div>
            <div className="font-medium">{row.getValue("deviceName")}</div>
            <div className="text-xs text-muted-foreground">
              ID: {row.original.deviceId}
            </div>
          </div>
        ),
      },
      {
        accessorKey: "tpmManufacturer",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="TPM" />
        ),
        cell: ({ row }) => (
          <Badge variant="outline" className="font-mono text-xs">
            {row.getValue("tpmManufacturer")}
          </Badge>
        ),
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
                status === "verified"
                  ? "default"
                  : status === "failed"
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
        accessorKey: "attestedAt",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Attested At" />
        ),
        cell: ({ row }) => {
          const date = new Date(row.getValue("attestedAt"));
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
        id: "actions",
        cell: ({ row }) => {
          const attestation = row.original;
          const actions: TypedRowAction<Attestation>[] = [];

          if (onView) {
            actions.push({
              label: "View Details",
              onClick: onView,
              icon: Eye,
            });
          }

          if (onVerify && attestation.status === "pending") {
            actions.push({
              label: "Verify",
              onClick: onVerify,
              icon: ShieldCheck,
            });
          }

          if (onRequestAttestation) {
            actions.push({
              label: "Request New Attestation",
              onClick: onRequestAttestation,
              icon: RefreshCw,
              separator: actions.length > 0,
            });
          }

          return <DataTableRowActions row={row.original} actions={actions} />;
        },
      },
    ],
    [onView, onVerify, onRequestAttestation]
  );

  const filterableColumns: TypedFilterColumn<Attestation>[] = [
    {
      id: "status",
      title: "Status",
      options: [
        { label: "Verified", value: "verified" },
        { label: "Failed", value: "failed" },
        { label: "Pending", value: "pending" },
      ],
    },
  ];

  return (
    <DataTable
      columns={columns}
      data={attestations}
      searchKey="deviceName"
      searchPlaceholder="Search by device name..."
      filterableColumns={filterableColumns}
      pagination
      pageSize={10}
      loading={loading}
    />
  );
}
