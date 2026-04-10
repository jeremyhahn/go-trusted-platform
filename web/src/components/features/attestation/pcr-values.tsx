"use client";

import * as React from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface PCRValuesProps {
  pcrValues: Record<number, string>;
  highlightIndices?: number[];
}

/**
 * PCR (Platform Configuration Register) values display component
 *
 * Features:
 * - Tabular display of PCR indices and values
 * - Highlight specific PCR indices
 * - Monospace formatting for hash values
 * - Descriptions for common PCR indices
 */
export function PCRValues({ pcrValues, highlightIndices = [] }: PCRValuesProps) {
  const getPCRDescription = (index: number): string => {
    const descriptions: Record<number, string> = {
      0: "BIOS/UEFI code",
      1: "BIOS/UEFI configuration",
      2: "Option ROM code",
      3: "Option ROM configuration",
      4: "Master Boot Record (MBR)",
      5: "MBR configuration",
      6: "State transitions and wake events",
      7: "Vendor-specific measurements",
      8: "GRUB bootloader",
      9: "Kernel and initrd",
      10: "IMA (Integrity Measurement Architecture)",
      11: "Unified Kernel",
      12: "Kernel command line",
      13: "Systemd boot",
      14: "MOK (Machine Owner Key)",
      15: "Debug",
      16: "Application support",
      17: "Dynamic Launch Control Policy",
      18: "Launch Control Policy Authorities",
      19: "Launch Control Policy Authorities",
      20: "Launch Control Policy Authorities",
      21: "Launch Control Policy Authorities",
      22: "Launch Control Policy Authorities",
      23: "Application support",
    };

    return descriptions[index] || "Reserved";
  };

  const sortedIndices = Object.keys(pcrValues)
    .map(Number)
    .sort((a, b) => a - b);

  if (sortedIndices.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-muted-foreground">
          No PCR values available
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>PCR Values</CardTitle>
        <CardDescription>
          Platform Configuration Register measurements
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-20">PCR</TableHead>
                <TableHead className="w-[200px]">Description</TableHead>
                <TableHead>Value</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sortedIndices.map((index) => {
                const isHighlighted = highlightIndices.includes(index);
                return (
                  <TableRow
                    key={index}
                    className={isHighlighted ? "bg-accent" : ""}
                  >
                    <TableCell className="font-medium">
                      <div className="flex items-center gap-2">
                        <span>{index}</span>
                        {isHighlighted && (
                          <Badge variant="default" className="text-xs">
                            Modified
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {getPCRDescription(index)}
                    </TableCell>
                    <TableCell>
                      <code className="text-xs bg-muted px-2 py-1 rounded break-all">
                        {pcrValues[index]}
                      </code>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>

        <div className="mt-4 text-xs text-muted-foreground">
          <p>
            PCR values are SHA-256 hashes that represent the state of system
            components. Changes to these values indicate modifications to the
            measured components.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
