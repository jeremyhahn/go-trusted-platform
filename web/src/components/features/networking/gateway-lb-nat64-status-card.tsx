'use client';

/**
 * GatewayLBNAT64StatusCard — the gateway's load-balancer summary
 * (GatewayService.GetLBStatus, GET /api/v1/gateway/lb/status) and NAT64
 * status (GatewayService.GetNAT64Status, GET /api/v1/gateway/nat64/status,
 * #2052), read through the SDK.
 *
 * Both are reads. Each section has its own Refresh behind the capability
 * gate on its route, and a refused read shows the server's message in that
 * section only.
 */

import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { Network, RefreshCw } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Gated } from '@/components/features/capabilities/gated';
import { useGateway } from '@/hooks';
import type { GatewayNAT64Status, LBStatus } from 'trusted-platform-sdk';

type Read<T> = () => Promise<{ data?: T | null; error?: { message?: string } | null }>;

interface Section<S> {
  loading: boolean;
  status: S | null;
  error: string | null;
}

const EMPTY = { loading: false, status: null, error: null };

/** useStatusRead keeps one status read's result, its error and its loading flag. */
function useStatusRead<S>(read: Read<{ status: S | null }>) {
  const [state, setState] = useState<Section<S>>(EMPTY);

  const load = useCallback(async () => {
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const res = await read();
      if (res.error) {
        setState({ loading: false, status: null, error: res.error.message || 'The gateway did not answer the read' });
      } else {
        setState({ loading: false, status: res.data?.status ?? null, error: null });
      }
    } catch (err) {
      setState({ loading: false, status: null, error: err instanceof Error ? err.message : String(err) });
    }
  }, [read]);

  return { ...state, load };
}

function Field({ children }: { children: ReactNode }) {
  return <span className="mr-3 inline-block">{children}</span>;
}

function ActiveBadge({ active }: { active: boolean }) {
  return <Field>{active ? 'Active' : 'Inactive'}</Field>;
}

export function GatewayLBNAT64StatusCard() {
  const gateway = useGateway();
  const readLB = useCallback(() => gateway.getLBStatus(), [gateway]);
  const readNAT64 = useCallback(() => gateway.getGatewayNAT64Status(), [gateway]);
  const lb = useStatusRead<LBStatus>(readLB);
  const nat64 = useStatusRead<GatewayNAT64Status>(readNAT64);
  const loadLB = lb.load;
  const loadNAT64 = nat64.load;

  useEffect(() => {
    void loadLB();
    void loadNAT64();
    // Read once on mount; each Refresh re-reads its own status.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <Card data-testid="lb-nat64-status-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Network className="h-5 w-5" />
          Load balancer and NAT64
        </CardTitle>
        <CardDescription>The gateway&apos;s load-balancer summary and its NAT64 translator status.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <section className="space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-medium">Load balancer</h3>
            <Gated op="GET /api/v1/gateway/lb/status">
              <Button
                variant="outline"
                size="sm"
                data-testid="lb-status-refresh"
                disabled={lb.loading}
                onClick={() => void loadLB()}
              >
                <RefreshCw className="mr-1 h-4 w-4" />
                Refresh
              </Button>
            </Gated>
          </div>
          {lb.error !== null && (
            <Alert variant="destructive">
              <AlertTitle>Read refused</AlertTitle>
              <AlertDescription data-testid="lb-status-error" className="whitespace-pre-wrap break-words">
                {lb.error}
              </AlertDescription>
            </Alert>
          )}
          <div className="text-sm" data-testid="lb-status">
            {lb.status && (
              <>
                <ActiveBadge active={lb.status.active} />
                <Field>{`${lb.status.vipCount} VIPs`}</Field>
                <Field>{`${lb.status.healthyBackends}/${lb.status.totalBackends} backends healthy`}</Field>
                <Field>{`Last reconcile ${lb.status.lastReconcile ?? 'never'}`}</Field>
              </>
            )}
          </div>
        </section>

        <section className="space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-medium">NAT64</h3>
            <Gated op="GET /api/v1/gateway/nat64/status">
              <Button
                variant="outline"
                size="sm"
                data-testid="nat64-status-refresh"
                disabled={nat64.loading}
                onClick={() => void loadNAT64()}
              >
                <RefreshCw className="mr-1 h-4 w-4" />
                Refresh
              </Button>
            </Gated>
          </div>
          {nat64.error !== null && (
            <Alert variant="destructive">
              <AlertTitle>Read refused</AlertTitle>
              <AlertDescription data-testid="nat64-status-error" className="whitespace-pre-wrap break-words">
                {nat64.error}
              </AlertDescription>
            </Alert>
          )}
          <div className="text-sm" data-testid="nat64-status">
            {nat64.status && (
              <>
                <ActiveBadge active={nat64.status.active} />
                <Field>{nat64.status.prefix}</Field>
                <Field>{nat64.status.instance}</Field>
                <Field>{`${nat64.status.sessions} sessions`}</Field>
                <Field>{`${nat64.status.pool4Used} pool4 used`}</Field>
                <Field>{`${nat64.status.flowCount} flows`}</Field>
                <Field>{nat64.status.moduleVersion}</Field>
                <Field>{`Last reconcile ${nat64.status.lastReconcile ?? 'never'}`}</Field>
                {nat64.status.lastError !== '' && (
                  <Field>
                    <span className="text-destructive">{nat64.status.lastError}</span>
                  </Field>
                )}
              </>
            )}
          </div>
        </section>
      </CardContent>
    </Card>
  );
}
