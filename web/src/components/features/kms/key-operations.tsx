"use client";

import * as React from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loader2, Copy, Check } from "lucide-react";
import type { Key } from "@/types/security";

interface KeyOperationsProps {
  keyItem: Key;
  onEncrypt?: (plaintext: string) => Promise<string>;
  onDecrypt?: (ciphertext: string) => Promise<string>;
  onSign?: (data: string) => Promise<string>;
  onVerify?: (data: string, signature: string) => Promise<boolean>;
}

/**
 * Key operations test panel component
 *
 * Features:
 * - Test encryption/decryption (symmetric and asymmetric keys)
 * - Test signing/verification (asymmetric keys only)
 * - Non-destructive operations for testing
 * - Copy results to clipboard
 * - Clear operation type indicators
 */
export function KeyOperations({
  keyItem,
  onEncrypt,
  onDecrypt,
  onSign,
  onVerify,
}: KeyOperationsProps) {
  const [activeTab, setActiveTab] = React.useState("encrypt");
  const [loading, setLoading] = React.useState(false);
  const [copied, setCopied] = React.useState(false);

  // Encrypt/Decrypt state
  const [plaintext, setPlaintext] = React.useState("");
  const [ciphertext, setCiphertext] = React.useState("");
  const [decryptResult, setDecryptResult] = React.useState("");

  // Sign/Verify state
  const [signData, setSignData] = React.useState("");
  const [signature, setSignature] = React.useState("");
  const [verifyData, setVerifyData] = React.useState("");
  const [verifySignature, setVerifySignature] = React.useState("");
  const [verifyResult, setVerifyResult] = React.useState<boolean | null>(null);

  const isAsymmetric = keyItem.type === "asymmetric";
  const isActive = keyItem.status === "active";

  const handleEncrypt = async () => {
    if (!onEncrypt || !plaintext) return;
    setLoading(true);
    try {
      const result = await onEncrypt(plaintext);
      setCiphertext(result);
    } catch (error) {
      console.error("Encryption failed:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleDecrypt = async () => {
    if (!onDecrypt || !ciphertext) return;
    setLoading(true);
    try {
      const result = await onDecrypt(ciphertext);
      setDecryptResult(result);
    } catch (error) {
      console.error("Decryption failed:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleSign = async () => {
    if (!onSign || !signData) return;
    setLoading(true);
    try {
      const result = await onSign(signData);
      setSignature(result);
    } catch (error) {
      console.error("Signing failed:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    if (!onVerify || !verifyData || !verifySignature) return;
    setLoading(true);
    try {
      const result = await onVerify(verifyData, verifySignature);
      setVerifyResult(result);
    } catch (error) {
      console.error("Verification failed:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  if (!isActive) {
    return (
      <Card>
        <CardContent className="py-8 text-center">
          <Badge variant="secondary" className="mb-2">
            Key Inactive
          </Badge>
          <p className="text-sm text-muted-foreground">
            Key operations are only available for active keys
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Key Operations</CardTitle>
        <CardDescription>
          Test cryptographic operations with this key (non-destructive)
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="encrypt">Encrypt/Decrypt</TabsTrigger>
            <TabsTrigger value="sign" disabled={!isAsymmetric}>
              Sign/Verify {!isAsymmetric && "(Asymmetric only)"}
            </TabsTrigger>
          </TabsList>

          {/* Encrypt/Decrypt Tab */}
          <TabsContent value="encrypt" className="space-y-4">
            {/* Encrypt */}
            <div className="space-y-2">
              <Label htmlFor="plaintext">Plaintext to Encrypt</Label>
              <div className="flex gap-2">
                <Input
                  id="plaintext"
                  placeholder="Enter text to encrypt..."
                  value={plaintext}
                  onChange={(e) => setPlaintext(e.target.value)}
                  disabled={loading}
                />
                <Button
                  onClick={handleEncrypt}
                  disabled={loading || !plaintext || !onEncrypt}
                >
                  {loading ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    "Encrypt"
                  )}
                </Button>
              </div>
            </div>

            {ciphertext && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label>Encrypted Result</Label>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleCopy(ciphertext)}
                  >
                    {copied ? (
                      <Check className="h-4 w-4" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </Button>
                </div>
                <pre className="text-xs bg-muted p-3 rounded overflow-x-auto border">
                  {ciphertext}
                </pre>
              </div>
            )}

            {/* Decrypt */}
            {ciphertext && (
              <>
                <div className="space-y-2">
                  <Label htmlFor="ciphertext">Ciphertext to Decrypt</Label>
                  <div className="flex gap-2">
                    <Input
                      id="ciphertext"
                      placeholder="Enter ciphertext to decrypt..."
                      value={ciphertext}
                      onChange={(e) => setCiphertext(e.target.value)}
                      disabled={loading}
                    />
                    <Button
                      onClick={handleDecrypt}
                      disabled={loading || !ciphertext || !onDecrypt}
                    >
                      {loading ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        "Decrypt"
                      )}
                    </Button>
                  </div>
                </div>

                {decryptResult && (
                  <div className="space-y-2">
                    <Label>Decrypted Result</Label>
                    <div className="p-3 bg-muted rounded border">
                      <code className="text-sm">{decryptResult}</code>
                    </div>
                  </div>
                )}
              </>
            )}
          </TabsContent>

          {/* Sign/Verify Tab */}
          <TabsContent value="sign" className="space-y-4">
            {/* Sign */}
            <div className="space-y-2">
              <Label htmlFor="signData">Data to Sign</Label>
              <div className="flex gap-2">
                <Input
                  id="signData"
                  placeholder="Enter data to sign..."
                  value={signData}
                  onChange={(e) => setSignData(e.target.value)}
                  disabled={loading}
                />
                <Button
                  onClick={handleSign}
                  disabled={loading || !signData || !onSign}
                >
                  {loading ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    "Sign"
                  )}
                </Button>
              </div>
            </div>

            {signature && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label>Signature</Label>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleCopy(signature)}
                  >
                    {copied ? (
                      <Check className="h-4 w-4" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </Button>
                </div>
                <pre className="text-xs bg-muted p-3 rounded overflow-x-auto border">
                  {signature}
                </pre>
              </div>
            )}

            {/* Verify */}
            {signature && (
              <>
                <div className="space-y-2">
                  <Label htmlFor="verifyData">Data to Verify</Label>
                  <Input
                    id="verifyData"
                    placeholder="Enter data..."
                    value={verifyData}
                    onChange={(e) => setVerifyData(e.target.value)}
                    disabled={loading}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="verifySignature">Signature</Label>
                  <Input
                    id="verifySignature"
                    placeholder="Enter signature..."
                    value={verifySignature}
                    onChange={(e) => setVerifySignature(e.target.value)}
                    disabled={loading}
                  />
                </div>

                <Button
                  onClick={handleVerify}
                  disabled={
                    loading || !verifyData || !verifySignature || !onVerify
                  }
                  className="w-full"
                >
                  {loading ? (
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                  ) : null}
                  Verify Signature
                </Button>

                {verifyResult !== null && (
                  <div
                    className={`p-4 rounded border ${
                      verifyResult
                        ? "bg-green-50 border-green-200 dark:bg-green-950 dark:border-green-800"
                        : "bg-red-50 border-red-200 dark:bg-red-950 dark:border-red-800"
                    }`}
                  >
                    <p
                      className={`font-medium ${
                        verifyResult ? "text-green-900 dark:text-green-100" : "text-red-900 dark:text-red-100"
                      }`}
                    >
                      {verifyResult ? "Signature Valid" : "Signature Invalid"}
                    </p>
                  </div>
                )}
              </>
            )}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
