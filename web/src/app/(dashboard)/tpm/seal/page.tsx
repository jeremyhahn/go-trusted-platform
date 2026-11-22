"use client";

import * as React from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Lock,
  Unlock,
  Loader2,
} from "lucide-react";
import { useTPM, useMutation, useToast } from "@/hooks";


/**
 * Available PCR indices for sealing
 */
const availablePCRs = [
  { index: 0, description: "BIOS/UEFI code" },
  { index: 1, description: "BIOS/UEFI configuration" },
  { index: 4, description: "Master Boot Record" },
  { index: 7, description: "Secure Boot policy" },
  { index: 8, description: "GRUB bootloader" },
  { index: 9, description: "Kernel and initrd" },
  { index: 10, description: "IMA measurements" },
  { index: 14, description: "MOK certificates" },
];

/**
 * TPM Seal/Unseal Operations Page
 *
 * Features:
 * - Seal data to PCR values
 * - Unseal data with current PCR state
 */
export default function TPMSealPage() {
  const { toast } = useToast();
  const tpm = useTPM();

  const [activeTab, setActiveTab] = React.useState<"seal" | "unseal">("seal");
  const [selectedPCRs, setSelectedPCRs] = React.useState<number[]>([7]);
  const [sealData, setSealData] = React.useState("");
  const [sealCn, setSealCn] = React.useState("");
  const [sealedResult, setSealedResult] = React.useState<string>("");
  const [unsealCn, setUnsealCn] = React.useState("");
  const [unsealedResult, setUnsealedResult] = React.useState<string>("");

  const handlePCRToggle = (index: number) => {
    setSelectedPCRs((prev) =>
      prev.includes(index)
        ? prev.filter((i) => i !== index)
        : [...prev, index].sort((a, b) => a - b)
    );
  };

  const sealMutation = useMutation(
    async () => {
      if (!sealData) {
        throw new Error("No data to seal");
      }
      if (!sealCn) {
        throw new Error("Common name is required");
      }
      // Every existing seal holds one Latin-1 byte per character and the server
      // stores no encoding marker. UTF-8 bytes are also valid Latin-1, so an
      // unseal decoder cannot tell the two apart: keep Latin-1 and refuse what
      // it cannot encode. A plain Error reaches onError; btoa's DOMException
      // carries a code and useMutation would drop it silently.
      if (Array.from(sealData).some((c) => c.charCodeAt(0) > 0xff)) {
        throw new Error("Data to seal must be Latin-1 text: characters above U+00FF cannot be sealed from this page");
      }
      return tpm.seal({
        data: btoa(sealData),
        cn: sealCn,
        pcrIndices: selectedPCRs,
      });
    },
    {
      onSuccess: (response) => {
        if (response.sealedData) {
          setSealedResult(response.sealedData);
          toast({
            title: "Data sealed successfully",
            description: `Data has been sealed with CN: ${sealCn}`,
            variant: "default",
          });
        }
      },
      onError: (error) => {
        toast({
          title: "Error sealing data",
          description: error.message,
          variant: "destructive",
        });
      },
    }
  );

  const unsealMutation = useMutation(
    async () => {
      if (!unsealCn) {
        throw new Error("Common name is required");
      }
      return tpm.unseal({
        cn: unsealCn,
        pcrIndices: selectedPCRs,
      });
    },
    {
      onSuccess: (response) => {
        if (response.data) {
          setUnsealedResult(atob(response.data));
          toast({
            title: "Data unsealed successfully",
            description: "Data has been successfully unsealed",
            variant: "default",
          });
        }
      },
      onError: (error) => {
        toast({
          title: "Error unsealing data",
          description: error.message,
          variant: "destructive",
        });
      },
    }
  );

  const handleSeal = () => {
    sealMutation.mutate(undefined);
  };

  const handleUnseal = () => {
    unsealMutation.mutate(undefined);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Seal/Unseal Operations</h1>
          <p className="text-muted-foreground">
            Protect secrets with TPM-based sealing
          </p>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Seal Data</CardTitle>
            <Lock className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Encrypt data that can only be decrypted when PCR values match
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Unseal Data</CardTitle>
            <Unlock className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Decrypt sealed data if current PCR state matches
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Seal/Unseal Operations */}
      <Card>
        <CardHeader>
          <CardTitle>Seal/Unseal Operations</CardTitle>
          <CardDescription>
            Perform TPM seal and unseal operations
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as "seal" | "unseal")}>
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="seal">
                <Lock className="mr-2 h-4 w-4" />
                Seal Data
              </TabsTrigger>
              <TabsTrigger value="unseal">
                <Unlock className="mr-2 h-4 w-4" />
                Unseal Data
              </TabsTrigger>
            </TabsList>
            <TabsContent value="seal" className="space-y-4">
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>PCR Policy</Label>
                  <p className="text-sm text-muted-foreground mb-2">
                    Select PCRs to bind the sealed data to. Data can only be unsealed
                    when these PCR values match the current system state.
                  </p>
                  <div className="grid grid-cols-2 gap-2">
                    {availablePCRs.map((pcr) => (
                      <div
                        key={pcr.index}
                        className="flex items-center space-x-2 rounded border p-2"
                      >
                        <Checkbox
                          id={`pcr-${pcr.index}`}
                          checked={selectedPCRs.includes(pcr.index)}
                          onCheckedChange={() => handlePCRToggle(pcr.index)}
                        />
                        <Label
                          htmlFor={`pcr-${pcr.index}`}
                          className="flex-1 cursor-pointer text-sm"
                        >
                          <span className="font-medium">PCR {pcr.index}</span>
                          <span className="text-muted-foreground ml-2">
                            {pcr.description}
                          </span>
                        </Label>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="seal-cn">Common Name</Label>
                  <Input
                    id="seal-cn"
                    placeholder="Enter a unique name for this sealed object"
                    value={sealCn}
                    onChange={(e) => setSealCn(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="seal-data">Data to Seal</Label>
                  <Textarea
                    id="seal-data"
                    placeholder="Enter data to seal (will be encrypted)"
                    className="min-h-[100px] font-mono"
                    value={sealData}
                    onChange={(e) => setSealData(e.target.value)}
                  />
                </div>
                <Button
                  onClick={handleSeal}
                  disabled={selectedPCRs.length === 0 || !sealData || !sealCn || sealMutation.isLoading}
                >
                  {sealMutation.isLoading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Sealing...
                    </>
                  ) : (
                    <>
                      <Lock className="mr-2 h-4 w-4" />
                      Seal Data
                    </>
                  )}
                </Button>
                {sealedResult && (
                  <div className="space-y-2">
                    <Label>Sealed Data (Base64)</Label>
                    <Textarea
                      readOnly
                      className="min-h-[100px] font-mono text-xs"
                      value={sealedResult}
                    />
                    <p className="text-sm text-muted-foreground">
                      Save this sealed blob. You will need it to unseal the data later.
                    </p>
                  </div>
                )}
              </div>
            </TabsContent>
            <TabsContent value="unseal" className="space-y-4">
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="unseal-cn">Common Name</Label>
                  <Input
                    id="unseal-cn"
                    placeholder="Enter the common name used when sealing"
                    value={unsealCn}
                    onChange={(e) => setUnsealCn(e.target.value)}
                  />
                </div>
                <Button
                  onClick={handleUnseal}
                  disabled={!unsealCn || unsealMutation.isLoading}
                >
                  {unsealMutation.isLoading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Unsealing...
                    </>
                  ) : (
                    <>
                      <Unlock className="mr-2 h-4 w-4" />
                      Unseal Data
                    </>
                  )}
                </Button>
                {unsealedResult && (
                  <div className="space-y-2">
                    <Label>Unsealed Data</Label>
                    <Textarea
                      readOnly
                      className="min-h-[100px] font-mono"
                      value={unsealedResult}
                    />
                  </div>
                )}
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Seal/Unseal Documentation */}
      <Card>
        <CardHeader>
          <CardTitle>Seal/Unseal Reference</CardTitle>
          <CardDescription>
            Understanding TPM-based data protection
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4 text-sm text-muted-foreground">
            <p>
              TPM sealing binds data to specific platform states measured in PCRs.
              Sealed data can only be decrypted (unsealed) when the current PCR
              values match those recorded at seal time.
            </p>
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <h4 className="font-medium text-foreground mb-2">Sealing</h4>
                <ul className="list-disc list-inside space-y-1">
                  <li>Encrypts data with TPM-protected key</li>
                  <li>Records current PCR values as policy</li>
                  <li>Creates sealed blob stored outside TPM</li>
                  <li>Optional: Add authorization policy</li>
                </ul>
              </div>
              <div>
                <h4 className="font-medium text-foreground mb-2">Unsealing</h4>
                <ul className="list-disc list-inside space-y-1">
                  <li>TPM verifies PCR values match policy</li>
                  <li>Decrypts data if policy satisfied</li>
                  <li>Fails if system state has changed</li>
                  <li>Protects against boot-time attacks</li>
                </ul>
              </div>
              <div>
                <h4 className="font-medium text-foreground mb-2">Common Use Cases</h4>
                <ul className="list-disc list-inside space-y-1">
                  <li>Full disk encryption keys (LUKS)</li>
                  <li>SSH/TLS private keys</li>
                  <li>Application credentials</li>
                  <li>Measured boot secrets</li>
                </ul>
              </div>
              <div>
                <h4 className="font-medium text-foreground mb-2">Best Practices</h4>
                <ul className="list-disc list-inside space-y-1">
                  <li>Include PCR 7 (Secure Boot policy)</li>
                  <li>Consider PCR 0 for firmware integrity</li>
                  <li>Use PCR 8-9 for bootloader/kernel</li>
                  <li>Re-seal after authorized updates</li>
                </ul>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
