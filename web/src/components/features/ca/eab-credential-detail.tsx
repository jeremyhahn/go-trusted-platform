"use client";

/**
 * <EABCredentialDetail id={7} />
 *
 * One EAB credential through the SDK client: GetCredential (client.eab.get),
 * GetCredentialQRCode (client.eab.getQRCode) and GetEnrollmentURL
 * (client.eab.getEnrollmentURL) (#2050).
 */

import * as React from "react";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { usePlatformClient } from "@/hooks";

// The REST wire shape: protojson sends the uint64 ids as strings and the
// status as the enum name, unlike the SDK's EABCredentialSummary type.
export interface EABCredentialWire {
  id: string;
  keyId: string;
  profileId?: string;
  tenantId?: string;
  status?: string;
  expiresAt?: string;
  createdAt?: string;
  usedAt?: string;
}

const STATUS_PREFIX = "EAB_CREDENTIAL_STATUS_";

export function eabStatusName(status?: string): string {
  const s = String(status || "").toUpperCase();
  return s.startsWith(STATUS_PREFIX) ? s.slice(STATUS_PREFIX.length) : s;
}

export function eabStatusLabel(status?: string): string {
  const name = eabStatusName(status);
  if (!name) return "Unknown";
  return name.charAt(0) + name.slice(1).toLowerCase();
}

interface Answer<T> {
  success?: boolean;
  data?: T;
  error?: { message?: string };
}

// unwrap returns the response data, or throws the server's refusal.
export function unwrapEAB<T>(res: Answer<T>, what: string): T {
  if (res.success === false || res.data === undefined) {
    throw new Error(res.error?.message || `Failed to ${what}`);
  }
  return res.data;
}

interface DetailState {
  credential?: EABCredentialWire;
  qr?: { qrCode: string; contentType: string };
  url?: { url: string; expiresAt?: string };
  error?: string;
  loading: boolean;
}

export interface EABCredentialDetailProps {
  /** The credential id as the server writes it: a uint64 decimal string. */
  id: string;
}

export function EABCredentialDetail({ id }: EABCredentialDetailProps) {
  const client = usePlatformClient();
  const [state, setState] = React.useState<DetailState>({ loading: true });

  React.useEffect(() => {
    let live = true;
    setState({ loading: true });
    (async () => {
      try {
        const [cred, qr, url] = await Promise.all([
          client.eab.get(id),
          client.eab.getQRCode(id),
          client.eab.getEnrollmentURL(id),
        ]);
        const credential = unwrapEAB(cred, "read the credential").credential as unknown as EABCredentialWire;
        const next: DetailState = { loading: false, credential };
        try {
          next.qr = unwrapEAB(qr, "read the QR code");
          next.url = unwrapEAB(url, "read the enrolment URL");
        } catch (err) {
          next.error = err instanceof Error ? err.message : String(err);
        }
        if (live) setState(next);
      } catch (err) {
        if (live) setState({ loading: false, error: err instanceof Error ? err.message : String(err) });
      }
    })();
    return () => {
      live = false;
    };
  }, [client, id]);

  if (state.loading) {
    return <Skeleton className="h-24 w-full" />;
  }

  const c = state.credential;
  return (
    <div data-testid="eab-credential-detail" className="space-y-3">
      {state.error && (
        <p role="alert" className="text-sm text-destructive">
          {state.error}
        </p>
      )}
      {c && (
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
          <dt className="text-muted-foreground">Key ID</dt>
          <dd className="font-mono">{c.keyId}</dd>
          <dt className="text-muted-foreground">Status</dt>
          <dd>
            <Badge variant={eabStatusName(c.status) === "ACTIVE" ? "default" : "secondary"}>
              {eabStatusLabel(c.status)}
            </Badge>
          </dd>
          <dt className="text-muted-foreground">Profile</dt>
          <dd>{c.profileId || "-"}</dd>
          <dt className="text-muted-foreground">Tenant</dt>
          <dd>{c.tenantId || "-"}</dd>
          <dt className="text-muted-foreground">Expires</dt>
          <dd>{c.expiresAt || "-"}</dd>
        </dl>
      )}
      {c && state.qr && (
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={`data:${state.qr.contentType || "image/png"};base64,${state.qr.qrCode}`}
          alt={`QR code for ${c.keyId}`}
          className="h-40 w-40"
        />
      )}
      {state.url && (
        <p className="text-sm">
          <span className="text-muted-foreground">Enrolment URL: </span>
          <span className="font-mono break-all">{state.url.url}</span>
        </p>
      )}
    </div>
  );
}
