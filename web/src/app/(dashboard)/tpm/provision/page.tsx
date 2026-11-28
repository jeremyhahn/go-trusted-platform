"use client";

/**
 * TPM Provisioning Page (#2068)
 *
 * - GetPlatformAttributes: the TPM device, its mode and its persistent keys
 * - GetCapabilities: the algorithms, commands and ECC curves it supports
 * - Provision: take ownership and create the EK, SRK and AK
 * - Clear: destroy every key in the TPM (behind a confirm dialog)
 */
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Loader2 } from "lucide-react";
import { useToast } from "@/hooks";
import { Gated } from "@/components/features/capabilities/gated";
import {
  provisionRequest,
  tpmKeyRefLabel,
  useTPMProvisioning,
  type TPMCapabilities,
  type TPMPlatformAttributes,
} from "@/hooks/use-tpm-provisioning";

interface OperationResult {
  success: boolean;
  error?: { message?: string };
  data?: { status?: { success?: boolean; message?: string } };
}

/** The server's message for a refused operation. */
function failureMessage(res: OperationResult): string {
  return res.error?.message ?? res.data?.status?.message ?? "the server refused the request";
}

function succeeded(res: OperationResult): boolean {
  return res.success && res.data?.status?.success !== false;
}

const yesNo = (v?: boolean) => (v ? "Yes" : "No");

export default function TPMProvisionPage() {
  const { toast } = useToast();
  const { getCapabilities, getPlatformAttributes, provision, clear } = useTPMProvisioning();

  const [platform, setPlatform] = React.useState<TPMPlatformAttributes | undefined>();
  const [platformError, setPlatformError] = React.useState<string | undefined>();
  const [capabilities, setCapabilities] = React.useState<TPMCapabilities | undefined>();
  const [capabilitiesError, setCapabilitiesError] = React.useState<string | undefined>();

  const [ownerPassword, setOwnerPassword] = React.useState("");
  const [provisioning, setProvisioning] = React.useState(false);
  const [provisionedKeys, setProvisionedKeys] = React.useState<string | undefined>();

  const [lockoutPassword, setLockoutPassword] = React.useState("");
  const [confirmOpen, setConfirmOpen] = React.useState(false);
  const [clearing, setClearing] = React.useState(false);

  const readPlatform = React.useCallback(async () => {
    const res = await getPlatformAttributes();
    if (res.success) {
      setPlatform(res.data ?? {});
      setPlatformError(undefined);
    } else {
      setPlatformError(res.error?.message ?? "the platform attributes could not be read");
    }
  }, [getPlatformAttributes]);

  React.useEffect(() => {
    void readPlatform();
    void (async () => {
      const res = await getCapabilities();
      if (res.success) {
        setCapabilities(res.data ?? {});
        setCapabilitiesError(undefined);
      } else {
        setCapabilitiesError(res.error?.message ?? "the capabilities could not be read");
      }
    })();
  }, [readPlatform, getCapabilities]);

  const onProvision = async () => {
    setProvisioning(true);
    try {
      const res = await provision(provisionRequest({ ownerPassword }));
      if (succeeded(res)) {
        const keys = [
          res.data?.ekPublic ? "EK" : undefined,
          res.data?.srkPublic ? "SRK" : undefined,
          res.data?.akPublic ? "AK" : undefined,
        ].filter(Boolean);
        setProvisionedKeys(keys.length ? keys.join(", ") : "none");
        toast({ title: "TPM provisioned", description: res.data?.status?.message, variant: "success" });
        await readPlatform();
      } else {
        toast({ title: "Provision failed", description: failureMessage(res), variant: "destructive" });
      }
    } finally {
      setProvisioning(false);
    }
  };

  const onClear = async () => {
    setConfirmOpen(false);
    setClearing(true);
    try {
      const res = await clear(lockoutPassword);
      if (succeeded(res)) {
        toast({ title: "TPM cleared", description: res.data?.status?.message, variant: "success" });
        await readPlatform();
      } else {
        toast({ title: "Clear failed", description: failureMessage(res), variant: "destructive" });
      }
    } finally {
      setClearing(false);
    }
  };

  const platformRows: { key: string; label: string; value: string }[] = platform
    ? [
        { key: "device", label: "Device", value: platform.device ?? "" },
        { key: "manufacturer", label: "Manufacturer", value: platform.manufacturer ?? "" },
        { key: "fips", label: "FIPS mode", value: yesNo(platform.isFips) },
        { key: "simulator", label: "Simulator", value: yesNo(platform.isSimulator) },
        { key: "seal", label: "Can seal", value: yesNo(platform.canSeal) },
        { key: "pcr", label: "PCRs extended", value: yesNo(platform.pcrExtended) },
        { key: "ek", label: "EK", value: tpmKeyRefLabel(platform.ek) },
        { key: "srk", label: "SRK", value: tpmKeyRefLabel(platform.srk) },
        { key: "iak", label: "IAK", value: tpmKeyRefLabel(platform.iak) },
      ]
    : [];

  const algorithms = capabilities?.algorithms ?? [];
  const commands = capabilities?.commands ?? [];
  const eccCurves = capabilities?.eccCurves ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">TPM Provisioning</h1>
        <p className="text-muted-foreground">
          Read the TPM&apos;s platform attributes and capabilities, provision it, or clear it
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Platform attributes</CardTitle>
          <CardDescription>The TPM device, its mode and its persistent keys</CardDescription>
        </CardHeader>
        <CardContent>
          {platformError && (
            <p data-testid="platform-error" className="text-sm text-destructive">
              {platformError}
            </p>
          )}
          {!platform && !platformError && <Loader2 className="h-4 w-4 animate-spin" />}
          {platform && (
            <dl className="grid grid-cols-2 gap-2 text-sm">
              {platformRows.map((row) => (
                <React.Fragment key={row.key}>
                  <dt className="text-muted-foreground">{row.label}</dt>
                  <dd data-testid={`platform-${row.key}`} className="font-mono">
                    {row.value}
                  </dd>
                </React.Fragment>
              ))}
            </dl>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Capabilities</CardTitle>
          <CardDescription>The algorithms, commands and ECC curves the TPM supports</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {capabilitiesError && (
            <p data-testid="capabilities-error" className="text-sm text-destructive">
              {capabilitiesError}
            </p>
          )}
          {!capabilities && !capabilitiesError && <Loader2 className="h-4 w-4 animate-spin" />}
          {capabilities && (
            <>
              <p data-testid="cap-counts" className="text-sm">
                {`${algorithms.length} algorithms, ${commands.length} commands, ${eccCurves.length} ECC curves`}
              </p>
              <p data-testid="cap-algorithms" className="text-xs font-mono break-all">
                {algorithms.join(", ")}
              </p>
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Provision</CardTitle>
          <CardDescription>Take ownership of the TPM; the daemon creates the EK and SRK and creates no AK</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="owner-password">Owner password</Label>
            <Input
              id="owner-password"
              type="password"
              value={ownerPassword}
              onChange={(e) => setOwnerPassword(e.target.value)}
            />
          </div>
          <Gated op="POST /api/v1/tpm/provision">
            <Button onClick={onProvision} disabled={provisioning}>
              {provisioning && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Provision TPM
            </Button>
          </Gated>
          {provisionedKeys !== undefined && (
            <p className="text-sm">
              Public keys returned: <span data-testid="provisioned-keys">{provisionedKeys}</span>
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Clear TPM</CardTitle>
          <CardDescription>
            Clear destroys every key in the TPM&apos;s storage and endorsement hierarchies.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="lockout-password">Lockout password</Label>
            <Input
              id="lockout-password"
              type="password"
              value={lockoutPassword}
              onChange={(e) => setLockoutPassword(e.target.value)}
            />
          </div>
          <Gated op="POST /api/v1/tpm/clear">
            <Button variant="destructive" onClick={() => setConfirmOpen(true)} disabled={clearing}>
              {clearing && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Clear TPM…
            </Button>
          </Gated>
        </CardContent>
      </Card>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Clear the TPM?</DialogTitle>
            <DialogDescription>
              Every key in the TPM&apos;s storage and endorsement hierarchies is destroyed. This
              cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={onClear}>
              Clear
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
