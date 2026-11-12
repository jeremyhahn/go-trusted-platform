"use client";

/**
 * TPM Credential and Random Page (#1725)
 *
 * - MakeCredential: wrap a secret to an attestation key name
 * - ActivateCredential: recover the secret (behind a confirm dialog, it
 *   uses the TPM's EK and AK)
 * - GetRandom: draw random bytes from the TPM
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
import { base64ToHex, textToBase64, useTPMOps, useToast } from "@/hooks";

export default function TPMCredentialPage() {
  const { toast } = useToast();
  const { makeCredential, activateCredential, getRandom } = useTPMOps();

  const [akName, setAkName] = React.useState("");
  const [secret, setSecret] = React.useState("");
  const [credentialBlob, setCredentialBlob] = React.useState("");
  const [encryptedSecret, setEncryptedSecret] = React.useState("");
  const [confirmOpen, setConfirmOpen] = React.useState(false);
  const [numBytes, setNumBytes] = React.useState("32");

  const fail = (title: string) => (err: unknown) => {
    toast({
      title,
      description: err instanceof Error ? err.message : String(err),
      variant: "destructive",
    });
  };

  const onMake = async () => {
    try {
      const resp = await makeCredential.mutateAsync({
        akName: akName.trim(),
        secret: secret ? textToBase64(secret) : undefined,
      });
      setCredentialBlob(resp.credentialBlob ?? "");
      setEncryptedSecret(resp.encryptedSecret ?? "");
      toast({ title: "Credential made", variant: "success" });
    } catch (err) {
      fail("MakeCredential failed")(err);
    }
  };

  const onActivate = async () => {
    setConfirmOpen(false);
    try {
      await activateCredential.mutateAsync({ credentialBlob, encryptedSecret });
      toast({ title: "Credential activated", variant: "success" });
    } catch (err) {
      fail("ActivateCredential failed")(err);
    }
  };

  const onRandom = async () => {
    try {
      await getRandom.mutateAsync({ numBytes: Number(numBytes) || 0 });
    } catch (err) {
      fail("GetRandom failed")(err);
    }
  };

  const randomBytes = getRandom.data?.randomBytes;
  const activatedSecret = activateCredential.data?.secret;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Credential and Random</h1>
        <p className="text-muted-foreground">
          Make and activate TPM credentials, and draw random bytes from the TPM
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Make Credential</CardTitle>
          <CardDescription>
            Wrap a secret to an attestation key name (TPM2_MakeCredential)
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="ak-name">AK name (base64)</Label>
            <Input id="ak-name" value={akName} onChange={(e) => setAkName(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="secret">Secret (optional)</Label>
            <Input id="secret" value={secret} onChange={(e) => setSecret(e.target.value)} />
          </div>
          <Button onClick={onMake} disabled={!akName.trim() || makeCredential.isLoading}>
            {makeCredential.isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Make Credential
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Activate Credential</CardTitle>
          <CardDescription>
            Recover the wrapped secret with the TPM&apos;s keys (TPM2_ActivateCredential)
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="credential-blob">Credential blob (base64)</Label>
            <Input
              id="credential-blob"
              value={credentialBlob}
              onChange={(e) => setCredentialBlob(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="encrypted-secret">Encrypted secret (base64)</Label>
            <Input
              id="encrypted-secret"
              value={encryptedSecret}
              onChange={(e) => setEncryptedSecret(e.target.value)}
            />
          </div>
          <Button
            variant="destructive"
            onClick={() => setConfirmOpen(true)}
            disabled={!credentialBlob || !encryptedSecret || activateCredential.isLoading}
          >
            Activate Credential
          </Button>
          {activatedSecret !== undefined && (
            <div className="space-y-1">
              <p className="text-sm font-medium">Recovered secret</p>
              <code data-testid="activated-secret" className="text-xs break-all">
                {base64ToHex(activatedSecret)}
              </code>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Random Bytes</CardTitle>
          <CardDescription>Draw random bytes from the TPM (TPM2_GetRandom)</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="num-bytes">Number of bytes</Label>
            <Input
              id="num-bytes"
              type="number"
              min={1}
              max={1024}
              value={numBytes}
              onChange={(e) => setNumBytes(e.target.value)}
            />
          </div>
          <Button onClick={onRandom} disabled={getRandom.isLoading}>
            {getRandom.isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Get Random
          </Button>
          {randomBytes !== undefined && (
            <code data-testid="random-bytes" className="block text-xs break-all">
              {base64ToHex(randomBytes)}
            </code>
          )}
        </CardContent>
      </Card>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Activate this credential?</DialogTitle>
            <DialogDescription>
              The TPM uses its endorsement and attestation keys to recover the
              secret. A credential activates once per session.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={onActivate}>
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
