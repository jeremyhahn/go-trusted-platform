"use client";

import * as React from "react";
import Link from "next/link";
import { useParams, usePathname } from "next/navigation";
import { AlertCircle, ArrowLeft } from "lucide-react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui";
import { useApi, useEAB } from "@/hooks";
import { resolveDynamicId } from "@/utils/dynamic-route";
import { normalizeEABStatus } from "@/utils/eab-status";
import type {
  GetEABCredentialResponse,
  GetEABQRCodeResponse,
  GetEnrollmentURLResponse,
} from "trusted-platform-sdk";

function errorText(err: unknown, fallback: string): string {
  if (err instanceof Error && err.message) return err.message;
  if (typeof err === "object" && err !== null && "message" in err) {
    const message = (err as { message?: unknown }).message;
    if (typeof message === "string" && message) return message;
  }
  return fallback;
}

export default function EABCredentialDetailClient() {
  const params = useParams();
  const pathname = usePathname();
  const rawId = resolveDynamicId(params, pathname, "eab");
  const id = Number.parseInt(rawId, 10);
  const validId = Number.isFinite(id) && id > 0;

  const eab = useEAB();
  const credential = useApi<GetEABCredentialResponse>(
    () => eab.service.get(id),
    [id],
    { enabled: validId }
  );
  const cred = credential.data?.credential;
  const status = normalizeEABStatus(cred?.status);

  const [qrCode, setQrCode] = React.useState<GetEABQRCodeResponse | null>(null);
  const [enrollment, setEnrollment] = React.useState<GetEnrollmentURLResponse | null>(null);
  const [message, setMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  const run = async (action: () => Promise<string | null>, fallback: string) => {
    setActionError(null);
    setMessage(null);
    try {
      setMessage(await action());
    } catch (err) {
      setActionError(errorText(err, fallback));
    }
  };

  const handleQRCode = () => {
    void run(async () => {
      setQrCode(await eab.getQRCode.mutateAsync({ id, size: 256 }));
      return null;
    }, "Failed to get QR code");
  };

  const handleEnrollmentURL = () => {
    void run(async () => {
      setEnrollment(await eab.getEnrollmentURL.mutateAsync(id));
      return null;
    }, "Failed to get enrollment URL");
  };

  const handleMarkUsed = () => {
    void run(async () => {
      await eab.markUsed.mutateAsync(id);
      await credential.refetch();
      return "Credential marked as used";
    }, "Failed to mark credential used");
  };

  const qrSrc = qrCode
    ? qrCode.qrCode.startsWith("data:")
      ? qrCode.qrCode
      : `data:image/${qrCode.format || "png"};base64,${qrCode.qrCode}`
    : null;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="sm" asChild>
          <Link href="/ca/eab">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back
          </Link>
        </Button>
        <div>
          <h1 className="text-3xl font-bold tracking-tight">EAB Credential {validId ? id : ""}</h1>
          <p className="text-muted-foreground">Credential details and enrollment</p>
        </div>
      </div>

      {message && (
        <div role="status" data-testid="eab-message" className="p-4 rounded-lg border bg-muted">
          {message}
        </div>
      )}

      {(!validId || actionError || credential.error) && (
        <div
          role="alert"
          className="flex items-center gap-2 p-4 bg-destructive/10 border border-destructive rounded-lg"
        >
          <AlertCircle className="h-4 w-4 text-destructive" />
          <p className="text-sm text-destructive">
            {!validId
              ? "Invalid credential ID"
              : actionError ?? errorText(credential.error, "Failed to load credential")}
          </p>
        </div>
      )}

      {cred && (
        <Card>
          <CardHeader>
            <CardTitle className="font-mono">{cred.keyId}</CardTitle>
            <CardDescription>
              <Badge data-testid="eab-status">{status}</Badge>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-2 gap-2 text-sm">
              <dt className="text-muted-foreground">Tenant</dt>
              <dd>{cred.tenantId}</dd>
              <dt className="text-muted-foreground">Profile</dt>
              <dd>{cred.profileId}</dd>
              <dt className="text-muted-foreground">Expires</dt>
              <dd>{cred.expiresAt}</dd>
              <dt className="text-muted-foreground">Created</dt>
              <dd>{cred.createdAt}</dd>
            </dl>
            <div className="mt-4 flex gap-2">
              <Button variant="outline" onClick={handleQRCode}>
                Show QR Code
              </Button>
              <Button variant="outline" onClick={handleEnrollmentURL}>
                Get Enrollment URL
              </Button>
              <Button onClick={handleMarkUsed} disabled={status !== "ACTIVE"}>
                Mark Used
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {qrSrc && (
        <Card>
          <CardHeader>
            <CardTitle>QR Code</CardTitle>
          </CardHeader>
          <CardContent>
            {/* eslint-disable-next-line @next/next/no-img-element -- inline data URL */}
            <img
              src={qrSrc}
              alt="EAB enrollment QR code"
              width={qrCode?.size || 256}
              height={qrCode?.size || 256}
            />
          </CardContent>
        </Card>
      )}

      {enrollment && (
        <Card>
          <CardHeader>
            <CardTitle>Enrollment URL</CardTitle>
            {enrollment.expiresAt && (
              <CardDescription>Expires {enrollment.expiresAt}</CardDescription>
            )}
          </CardHeader>
          <CardContent>
            <code data-testid="eab-enrollment-url" className="break-all text-sm">
              {enrollment.url}
            </code>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
