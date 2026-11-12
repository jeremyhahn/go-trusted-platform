"use client";

import * as React from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  RefreshCw,
  Database,
  Hash,
  AlertCircle,
  Copy,
  Info,
  Loader2,
} from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { textToBase64, useApi, useTPM, useTPMOps, useToast } from "@/hooks";
import type { PCRBank as SDKPCRBank } from "trusted-platform-sdk";

/**
 * PCR descriptions for common indices
 */
const pcrDescriptions: Record<number, string> = {
  0: "BIOS/UEFI code",
  1: "BIOS/UEFI configuration",
  2: "Option ROM code",
  3: "Option ROM configuration",
  4: "Master Boot Record (MBR)",
  5: "MBR configuration / GPT table",
  6: "State transitions and wake events",
  7: "Secure Boot policy",
  8: "GRUB bootloader / OS loader",
  9: "Kernel and initrd",
  10: "IMA (Integrity Measurement Architecture)",
  11: "Unified Kernel / systemd-boot",
  12: "Kernel command line",
  13: "Systemd boot measurements",
  14: "MOK (Machine Owner Key) certificates",
  15: "Debug PCR",
  16: "Application support (debug)",
  17: "DRTM - DCE/ACM",
  18: "DRTM - MLE",
  19: "DRTM - OS/MLE",
  20: "DRTM - platform specific",
  21: "DRTM - platform specific",
  22: "DRTM - platform specific",
  23: "Application support",
};

/**
 * TPM PCR Banks Viewer Page
 *
 * Features:
 * - View PCR values across different hash algorithms
 * - PCR descriptions and documentation
 * - Copy PCR values
 * - Highlight modified PCRs
 */
export default function TPMPCRsPage() {
  const { toast } = useToast();
  const tpm = useTPM();
  const [selectedAlgorithm, setSelectedAlgorithm] =
    React.useState<SDKPCRBank>("SHA256");

  const {
    data: pcrData,
    isLoading: loading,
    error,
    refetch,
  } = useApi(
    () => tpm.getPCRs({ indices: Array.from({ length: 24 }, (_, i) => i), bank: selectedAlgorithm }),
    [selectedAlgorithm],
    {
      onError: (err) => {
        toast({
          title: "Error loading PCRs",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  const { extendPCR } = useTPMOps();
  const [extendIndex, setExtendIndex] = React.useState("16");
  const [extendData, setExtendData] = React.useState("");
  const [extendConfirmOpen, setExtendConfirmOpen] = React.useState(false);

  const onExtend = async () => {
    setExtendConfirmOpen(false);
    try {
      await extendPCR.mutateAsync({
        index: Number(extendIndex),
        hashAlg: selectedAlgorithm,
        data: textToBase64(extendData),
      });
      toast({
        title: "PCR extended",
        description: `PCR ${extendIndex} (${selectedAlgorithm}) extended`,
        variant: "success",
      });
      refetch();
    } catch (err) {
      toast({
        title: "Extend PCR failed",
        description: err instanceof Error ? err.message : String(err),
        variant: "destructive",
      });
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied to clipboard",
      description: "PCR value has been copied to clipboard",
      variant: "success",
    });
  };

  const copyAllPCRs = () => {
    if (!pcrData?.pcrValues) return;
    const pcrText = pcrData.pcrValues
      .map((pcr) => `PCR[${pcr.index}]: ${pcr.value}`)
      .join("\n");
    copyToClipboard(pcrText);
  };

  const isZeroPCR = (value: string) => {
    const decoded = atob(value);
    return decoded.split('').every(c => c === '\0');
  };

  const pcrStats = React.useMemo(() => {
    if (!pcrData?.pcrValues) return { total: 0, measured: 0, zero: 0 };
    const measured = pcrData.pcrValues.filter((p) => !isZeroPCR(p.value)).length;
    return {
      total: pcrData.pcrValues.length,
      measured,
      zero: pcrData.pcrValues.length - measured,
    };
  }, [pcrData]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">PCR Banks</h1>
          <p className="text-muted-foreground">
            View Platform Configuration Register values
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Select
            value={selectedAlgorithm}
            onValueChange={(v) => setSelectedAlgorithm(v as SDKPCRBank)}
          >
            <SelectTrigger className="w-32">
              <SelectValue placeholder="Algorithm" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="SHA1">SHA-1</SelectItem>
              <SelectItem value="SHA256">SHA-256</SelectItem>
              <SelectItem value="SHA384">SHA-384</SelectItem>
              <SelectItem value="SHA512">SHA-512</SelectItem>
            </SelectContent>
          </Select>
          <Button variant="outline" onClick={() => refetch()} disabled={loading}>
            <RefreshCw
              className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
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

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total PCRs</CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{pcrStats.total}</div>
            <p className="text-xs text-muted-foreground">
              {selectedAlgorithm} bank
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Measured PCRs</CardTitle>
            <Hash className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {pcrStats.measured}
            </div>
            <p className="text-xs text-muted-foreground">
              Non-zero values
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Unused PCRs</CardTitle>
            <Hash className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-muted-foreground">
              {pcrStats.zero}
            </div>
            <p className="text-xs text-muted-foreground">
              Zero/uninitialized
            </p>
          </CardContent>
        </Card>
      </div>

      {/* PCR Values Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>PCR Values - {selectedAlgorithm}</CardTitle>
              <CardDescription>
                Platform Configuration Register measurements
              </CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={copyAllPCRs}>
              <Copy className="mr-2 h-4 w-4" />
              Copy All
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              <span className="ml-2 text-muted-foreground">Loading PCRs...</span>
            </div>
          ) : !pcrData?.pcrValues || pcrData.pcrValues.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No PCR bank data available for {selectedAlgorithm}
            </div>
          ) : (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-20">PCR</TableHead>
                    <TableHead className="w-[200px]">Description</TableHead>
                    <TableHead>Value</TableHead>
                    <TableHead className="w-12"></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <TooltipProvider>
                    {pcrData.pcrValues.map((pcr) => {
                      const isZero = isZeroPCR(pcr.value);
                      const hexValue = Array.from(atob(pcr.value), c =>
                        c.charCodeAt(0).toString(16).padStart(2, '0')
                      ).join('');

                      return (
                        <TableRow
                          key={pcr.index}
                          className={isZero ? "opacity-50" : ""}
                        >
                          <TableCell className="font-medium">
                            <div className="flex items-center gap-2">
                              <span>{pcr.index}</span>
                              {!isZero && (
                                <Badge variant="default" className="text-xs">
                                  Active
                                </Badge>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <span className="text-sm text-muted-foreground">
                                {pcrDescriptions[pcr.index] || "Reserved"}
                              </span>
                              <Tooltip>
                                <TooltipTrigger>
                                  <Info className="h-3 w-3 text-muted-foreground" />
                                </TooltipTrigger>
                                <TooltipContent>
                                  <p className="max-w-xs">
                                    PCR {pcr.index}: {pcrDescriptions[pcr.index] || "Reserved"}
                                  </p>
                                </TooltipContent>
                              </Tooltip>
                            </div>
                          </TableCell>
                          <TableCell>
                            <code
                              className={`text-xs px-2 py-1 rounded break-all ${
                                isZero
                                  ? "bg-muted text-muted-foreground"
                                  : "bg-muted"
                              }`}
                            >
                              {hexValue}
                            </code>
                          </TableCell>
                          <TableCell>
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => copyToClipboard(hexValue)}
                            >
                              <Copy className="h-4 w-4" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TooltipProvider>
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Extend PCR */}
      <Card>
        <CardHeader>
          <CardTitle>Extend PCR</CardTitle>
          <CardDescription>
            Extend a PCR in the {selectedAlgorithm} bank with data. A PCR
            cannot be rolled back until the next reset.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-end gap-4">
          <div className="space-y-2">
            <Label htmlFor="extend-index">PCR index</Label>
            <Input
              id="extend-index"
              type="number"
              min={0}
              max={23}
              className="w-24"
              value={extendIndex}
              onChange={(e) => setExtendIndex(e.target.value)}
            />
          </div>
          <div className="space-y-2 flex-1 min-w-[200px]">
            <Label htmlFor="extend-data">Data</Label>
            <Input
              id="extend-data"
              value={extendData}
              onChange={(e) => setExtendData(e.target.value)}
            />
          </div>
          <Button
            variant="destructive"
            onClick={() => setExtendConfirmOpen(true)}
            disabled={!extendData || extendIndex === "" || extendPCR.isLoading}
          >
            {extendPCR.isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Extend PCR
          </Button>
        </CardContent>
      </Card>

      <Dialog open={extendConfirmOpen} onOpenChange={setExtendConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Extend PCR {extendIndex}?</DialogTitle>
            <DialogDescription>
              The new value cannot be undone until the platform resets, and
              secrets sealed to this PCR stop unsealing.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setExtendConfirmOpen(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={onExtend}>
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* PCR Documentation */}
      <Card>
        <CardHeader>
          <CardTitle>PCR Reference</CardTitle>
          <CardDescription>
            Understanding Platform Configuration Registers
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4 text-sm text-muted-foreground">
            <p>
              Platform Configuration Registers (PCRs) are special TPM registers that
              store measurements of software and configuration. Each PCR accumulates
              hash values through an extend operation: PCR[n] = Hash(PCR[n] || new_value).
            </p>
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <h4 className="font-medium text-foreground mb-2">Boot PCRs (0-7)</h4>
                <p>
                  Measure BIOS/UEFI code and configuration, option ROMs, and secure
                  boot policy. These PCRs are typically extended during platform
                  initialization.
                </p>
              </div>
              <div>
                <h4 className="font-medium text-foreground mb-2">OS PCRs (8-15)</h4>
                <p>
                  Measure bootloader, kernel, initrd, and OS-specific configuration.
                  PCR 10 is commonly used by Linux IMA for runtime measurements.
                </p>
              </div>
              <div>
                <h4 className="font-medium text-foreground mb-2">DRTM PCRs (17-22)</h4>
                <p>
                  Reserved for Dynamic Root of Trust for Measurement (DRTM)
                  operations, used by technologies like Intel TXT or AMD SEV.
                </p>
              </div>
              <div>
                <h4 className="font-medium text-foreground mb-2">Application PCR (23)</h4>
                <p>
                  Available for application use. Can be used to measure
                  application-specific data or for development purposes.
                </p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
