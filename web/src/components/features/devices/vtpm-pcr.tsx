'use client';

/**
 * VTPMPCRDisplay Component
 * Display PCR values for a vTPM instance
 */

import { Lock } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import type { PCRValue } from '@/types/device';

interface VTPMPCRDisplayProps {
  pcrValues: PCRValue[];
}

export function VTPMPCRDisplay({ pcrValues }: VTPMPCRDisplayProps) {
  // Default PCR descriptions if not provided
  const defaultDescriptions: Record<number, string> = {
    0: 'BIOS/Firmware',
    1: 'BIOS Configuration',
    2: 'Option ROMs',
    3: 'Option ROM Configuration',
    4: 'Master Boot Record (MBR)',
    5: 'Master Boot Record Configuration',
    6: 'Resume from S4/S5',
    7: 'Secure Boot State',
    8: 'Kernel Command Line',
    9: 'initrd',
    10: 'IMA (Integrity Measurement Architecture)',
    11: 'Unified Kernel (EFI)',
    12: 'Kernel Data',
    13: 'Kernel Modules',
    14: 'MoK (Machine Owner Keys)',
    15: 'DRTM',
    16: 'Debug',
    23: 'Application Support',
  };

  const getDescription = (pcr: PCRValue): string => {
    return pcr.description || defaultDescriptions[pcr.index] || `PCR ${pcr.index}`;
  };

  const formatPCRValue = (value: string): string => {
    // Format as groups of 8 hex characters for readability
    return value.match(/.{1,8}/g)?.join(' ') || value;
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Lock className="h-5 w-5" />
          PCR Values
        </CardTitle>
        <CardDescription>
          Platform Configuration Register values for this vTPM
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="rounded-md border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-20">PCR</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Value</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pcrValues.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={3} className="text-center text-muted-foreground">
                    No PCR values available
                  </TableCell>
                </TableRow>
              ) : (
                pcrValues.map((pcr) => (
                  <TableRow key={pcr.index}>
                    <TableCell>
                      <Badge variant="outline" className="font-mono">
                        {pcr.index}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm">
                      {getDescription(pcr)}
                    </TableCell>
                    <TableCell>
                      <code className="text-xs font-mono text-muted-foreground break-all">
                        {formatPCRValue(pcr.value)}
                      </code>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>

        <div className="mt-4 rounded-lg border border-border bg-muted/50 p-4">
          <h4 className="text-sm font-medium mb-2">About PCR Values</h4>
          <p className="text-sm text-muted-foreground">
            Platform Configuration Registers (PCRs) are secure hash values that represent
            the system&apos;s boot state. Each PCR measures a specific aspect of the boot
            process, creating a chain of trust from firmware to operating system.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
