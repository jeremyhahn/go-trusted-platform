"use client";

import * as React from "react";
import { ColumnDef } from "@tanstack/react-table";
import { DataTable, createSelectColumn } from "@/components/ui/data-table";
import { DataTableColumnHeader } from "@/components/ui/data-table-column-header";
import { DataTableRowActions } from "@/components/ui/data-table-row-actions";
import { Badge } from "@/components/ui/badge";
import type { Attestation } from "@/types/security";
import type { TypedFilterColumn, TypedRowAction } from "@/components/ui/data-table.types";
import { Eye, RefreshCw } from "lucide-react";

interface AttestationTableProps {
  attestations: Attestation[];
  onView?: (attestation: Attestation) => void;
  onRequestAttestation?: (attestation: Attestation) => void;
  loading?: boolean;
}

/**
 * Host manifest table with filtering and actions
 *
 * Features:
 * - Sortable columns
 * - Filter by signature
 * - Row actions (view, request a new manifest)
 * - Signature badges: a manifest is evidence, never a verdict (#643); the
 *   verifier's verdict is the device report
 * - Device information display
 */
export function AttestationTable({
  attestations,
  onView,
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
          <DataTableColumnHeader column={column} title="Signature" />
        ),
        cell: ({ row }) => {
          const status = row.getValue("status") as Attestation["status"];
          return (
            <Badge variant={status === "signed" ? "outline" : "secondary"}>
              {status === "signed" ? "Signed" : "Unsigned"}
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
          const actions: TypedRowAction<Attestation>[] = [];

          if (onView) {
            actions.push({
              label: "View Details",
              onClick: onView,
              icon: Eye,
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
    [onView, onRequestAttestation]
  );

  const filterableColumns: TypedFilterColumn<Attestation>[] = [
    {
      id: "status",
      title: "Signature",
      options: [
        { label: "Signed", value: "signed" },
        { label: "Unsigned", value: "unsigned" },
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
