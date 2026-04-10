"use client";

import * as React from "react";
import { Download, Upload, Loader2 } from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ConfigSection } from "@/components/features/platform";
// TODO: SDK doesn't have platform config service yet - legacy API removed
import { useToast } from "@/hooks/use-toast";
import type { PlatformConfig } from "@/types/platform";

/**
 * Configuration Page
 *
 * Features:
 * - General settings (platform name, timezone, locale)
 * - Security settings (session timeout, MFA, password policy)
 * - Network settings (API endpoint, TLS configuration)
 * - TPM settings (PCR policy, attestation interval)
 * - CA settings (validity period, key algorithm)
 * - Export/Import configuration
 */
export default function ConfigPage() {
  const { toast } = useToast();
  const [config, setConfig] = React.useState<PlatformConfig | null>(null);
  const [isLoading, setIsLoading] = React.useState(true);
  const [isExporting, setIsExporting] = React.useState(false);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    // TODO: SDK doesn't have platform config service yet
    // Using placeholder data until SDK implementation is available
    setIsLoading(false);
    setConfig(null);
  }, [toast]);

  const handleExport = async () => {
    // TODO: SDK doesn't have platform config service yet
    toast({
      title: "Export not available",
      description: "Platform configuration service is currently in development",
      variant: "destructive",
    });
    setIsExporting(false);
  };

  const handleImportClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    // TODO: SDK doesn't have platform config service yet
    toast({
      title: "Import not available",
      description: "Platform configuration service is currently in development",
      variant: "destructive",
    });
    // Reset file input
    event.target.value = "";
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Configuration"
          description="Manage platform configuration settings"
        />
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  if (!config) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Configuration"
          description="Manage platform configuration settings"
        />
        <div className="flex items-center justify-center h-64 border-2 border-dashed rounded-lg">
          <div className="text-center">
            <p className="text-lg font-medium text-muted-foreground mb-2">
              Platform Configuration Coming Soon
            </p>
            <p className="text-sm text-muted-foreground">
              SDK support for platform configuration is currently in development
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Configuration"
        description="Manage platform configuration settings"
      >
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={handleImportClick}>
            <Upload className="h-4 w-4 mr-2" />
            Import Config
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleExport}
            disabled={isExporting}
          >
            {isExporting ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Download className="h-4 w-4 mr-2" />
            )}
            Export Config
          </Button>
        </div>
      </PageHeader>

      <input
        ref={fileInputRef}
        type="file"
        accept=".json"
        className="hidden"
        onChange={handleFileChange}
      />

      <div className="space-y-6">
        {/* General Settings */}
        <ConfigSection
          title="General Settings"
          description="Configure general platform settings"
          onSave={async (data) => {
            // TODO: SDK doesn't have platform config service yet
            throw new Error("Platform configuration service is currently in development");
          }}
        >
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Platform Name</Label>
              <Input
                id="name"
                name="name"
                defaultValue={config.general.name}
                placeholder="Trusted Platform"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="timezone">Timezone</Label>
              <Select name="timezone" defaultValue={config.general.timezone}>
                <SelectTrigger id="timezone">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="UTC">UTC</SelectItem>
                  <SelectItem value="America/New_York">Eastern Time</SelectItem>
                  <SelectItem value="America/Chicago">Central Time</SelectItem>
                  <SelectItem value="America/Denver">Mountain Time</SelectItem>
                  <SelectItem value="America/Los_Angeles">Pacific Time</SelectItem>
                  <SelectItem value="Europe/London">London</SelectItem>
                  <SelectItem value="Europe/Paris">Paris</SelectItem>
                  <SelectItem value="Asia/Tokyo">Tokyo</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="locale">Locale</Label>
              <Select name="locale" defaultValue={config.general.locale}>
                <SelectTrigger id="locale">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="en-US">English (US)</SelectItem>
                  <SelectItem value="en-GB">English (UK)</SelectItem>
                  <SelectItem value="fr-FR">French</SelectItem>
                  <SelectItem value="de-DE">German</SelectItem>
                  <SelectItem value="ja-JP">Japanese</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </ConfigSection>

        {/* Security Settings */}
        <ConfigSection
          title="Security Settings"
          description="Configure security and authentication settings"
          onSave={async (data) => {
            // TODO: SDK doesn't have platform config service yet
            throw new Error("Platform configuration service is currently in development");
          }}
        >
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="sessionTimeout">Session Timeout (minutes)</Label>
              <Input
                id="sessionTimeout"
                name="sessionTimeoutMinutes"
                type="number"
                defaultValue={config.security.sessionTimeoutMinutes}
                min="5"
                max="1440"
              />
            </div>
            <div className="flex items-center space-x-2">
              <Checkbox
                id="mfaRequired"
                name="mfaRequired"
                defaultChecked={config.security.mfaRequired}
              />
              <Label htmlFor="mfaRequired" className="cursor-pointer">
                Require Multi-Factor Authentication
              </Label>
            </div>
            <div className="space-y-3">
              <Label>Password Policy</Label>
              <div className="space-y-2 pl-4">
                <div className="space-y-2">
                  <Label htmlFor="minLength" className="text-sm">
                    Minimum Length
                  </Label>
                  <Input
                    id="minLength"
                    name="passwordPolicy.minLength"
                    type="number"
                    defaultValue={config.security.passwordPolicy.minLength}
                    min="8"
                    max="128"
                  />
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="requireUppercase"
                    name="passwordPolicy.requireUppercase"
                    defaultChecked={config.security.passwordPolicy.requireUppercase}
                  />
                  <Label htmlFor="requireUppercase" className="cursor-pointer text-sm">
                    Require Uppercase Letters
                  </Label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="requireNumbers"
                    name="passwordPolicy.requireNumbers"
                    defaultChecked={config.security.passwordPolicy.requireNumbers}
                  />
                  <Label htmlFor="requireNumbers" className="cursor-pointer text-sm">
                    Require Numbers
                  </Label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="requireSymbols"
                    name="passwordPolicy.requireSymbols"
                    defaultChecked={config.security.passwordPolicy.requireSymbols}
                  />
                  <Label htmlFor="requireSymbols" className="cursor-pointer text-sm">
                    Require Symbols
                  </Label>
                </div>
              </div>
            </div>
          </div>
        </ConfigSection>

        {/* Network Settings */}
        <ConfigSection
          title="Network Settings"
          description="Configure network and TLS settings"
          onSave={async (data) => {
            // TODO: SDK doesn't have platform config service yet
            throw new Error("Platform configuration service is currently in development");
          }}
        >
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="apiEndpoint">API Endpoint</Label>
              <Input
                id="apiEndpoint"
                name="apiEndpoint"
                defaultValue={config.network.apiEndpoint}
                placeholder="https://api.example.com"
              />
            </div>
            <div className="flex items-center space-x-2">
              <Checkbox
                id="tlsEnabled"
                name="tlsEnabled"
                defaultChecked={config.network.tlsEnabled}
              />
              <Label htmlFor="tlsEnabled" className="cursor-pointer">
                Enable TLS
              </Label>
            </div>
            <div className="space-y-2">
              <Label htmlFor="tlsMinVersion">Minimum TLS Version</Label>
              <Select name="tlsMinVersion" defaultValue={config.network.tlsMinVersion}>
                <SelectTrigger id="tlsMinVersion">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1.2">TLS 1.2</SelectItem>
                  <SelectItem value="1.3">TLS 1.3</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </ConfigSection>

        {/* TPM Settings */}
        <ConfigSection
          title="TPM Settings"
          description="Configure Trusted Platform Module settings"
          onSave={async (data) => {
            // TODO: SDK doesn't have platform config service yet
            throw new Error("Platform configuration service is currently in development");
          }}
        >
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="defaultPcrPolicy">Default PCR Policy (comma-separated)</Label>
              <Input
                id="defaultPcrPolicy"
                name="defaultPcrPolicy"
                defaultValue={config.tpm.defaultPcrPolicy.join(",")}
                placeholder="0,1,2,3"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="attestationInterval">Attestation Interval (minutes)</Label>
              <Input
                id="attestationInterval"
                name="attestationIntervalMinutes"
                type="number"
                defaultValue={config.tpm.attestationIntervalMinutes}
                min="1"
                max="1440"
              />
            </div>
          </div>
        </ConfigSection>

        {/* CA Settings */}
        <ConfigSection
          title="Certificate Authority Settings"
          description="Configure CA and certificate settings"
          onSave={async (data) => {
            // TODO: SDK doesn't have platform config service yet
            throw new Error("Platform configuration service is currently in development");
          }}
        >
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="defaultValidityDays">Default Validity Period (days)</Label>
              <Input
                id="defaultValidityDays"
                name="defaultValidityDays"
                type="number"
                defaultValue={config.ca.defaultValidityDays}
                min="1"
                max="3650"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="defaultKeyAlgorithm">Default Key Algorithm</Label>
              <Select name="defaultKeyAlgorithm" defaultValue={config.ca.defaultKeyAlgorithm}>
                <SelectTrigger id="defaultKeyAlgorithm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="RSA2048">RSA 2048</SelectItem>
                  <SelectItem value="RSA4096">RSA 4096</SelectItem>
                  <SelectItem value="ECDSA256">ECDSA P-256</SelectItem>
                  <SelectItem value="ECDSA384">ECDSA P-384</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </ConfigSection>
      </div>
    </div>
  );
}
