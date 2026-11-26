'use client';

/**
 * GatewayPerfCountersCard — the gateway's live datapath and conntrack counters
 * (GatewayService.GetPerfDatapath, GET /api/v1/gateway/perf/datapath, and
 * GatewayService.GetPerfConntrack, GET /api/v1/gateway/perf/conntrack, #2052).
 *
 * Both calls only read counters, so there is no confirm dialog. The server
 * serves them to the admin role only; a non-admin sees both reads disabled
 * with the reason. A refused read shows the server's message and can be
 * tried again. Each read is also gated on the server's capability for its
 * route (GET /api/v1/gateway/perf/datapath, GET /api/v1/gateway/perf/conntrack).
 */

import { useState } from 'react';
import { Activity } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useGateway, useOptionalAuth } from '@/hooks';
import type { GetPerfConntrackResponse, GetPerfDatapathResponse } from 'trusted-platform-sdk';
import { Gated } from '@/components/features/capabilities/gated';

/** The server's capability ops for the two reads. */
const DATAPATH_OP = 'GET /api/v1/gateway/perf/datapath';
const CONNTRACK_OP = 'GET /api/v1/gateway/perf/conntrack';

/** Largest conntrack zone (zones are 16-bit). */
const MAX_ZONE = 65535;

/**
 * Parse the zone filter: empty means every zone (undefined), a decimal
 * integer 0-65535 is that zone, anything else is invalid (null).
 */
export function parseZone(text: string): number | undefined | null {
  const t = text.trim();
  if (t === '') {
    return undefined;
  }
  if (!/^\d+$/.test(t)) {
    return null;
  }
  const n = Number(t);
  return n <= MAX_ZONE ? n : null;
}

function Counter({ label, value }: { label: string; value: string | undefined }) {
  return (
    <div>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="font-bold">{value || '0'}</dd>
    </div>
  );
}

export function GatewayPerfCountersCard() {
  const gateway = useGateway();
  const auth = useOptionalAuth();
  const isAdmin = auth?.user?.roles.includes('admin') ?? false;
  const [bridge, setBridge] = useState('');
  const [zone, setZone] = useState('');
  const [loading, setLoading] = useState(false);
  const [datapath, setDatapath] = useState<GetPerfDatapathResponse | null>(null);
  const [conntrack, setConntrack] = useState<GetPerfConntrackResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const zoneValue = parseZone(zone);

  const run = async <T,>(
    read: () => Promise<{ data?: T | null; error?: { message?: string } | null }>,
    done: (data: T) => void
  ) => {
    setLoading(true);
    setError(null);
    try {
      const res = await read();
      if (res.error) {
        setError(res.error.message || 'The gateway did not answer the read');
      } else if (res.data) {
        done(res.data);
      } else {
        setError('The gateway returned no result');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const readDatapath = () =>
    run(() => gateway.getPerfDatapath(bridge.trim() || undefined), setDatapath);

  const readConntrack = () => run(() => gateway.getPerfConntrack(zoneValue ?? undefined), setConntrack);

  const zones = Object.entries(conntrack?.perZone ?? {}).sort(([a], [b]) => Number(a) - Number(b));

  return (
    <Card data-testid="perf-counters-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className="h-5 w-5" />
          Datapath and conntrack counters
        </CardTitle>
        <CardDescription>Reads the switch datapath counters and the conntrack table size.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!isAdmin && (
          <p className="text-sm text-muted-foreground" data-testid="perf-counters-admin-only">
            Requires the admin role: the counters are an operator view.
          </p>
        )}
        {error !== null && (
          <Alert variant="destructive">
            <AlertTitle>Read refused</AlertTitle>
            <AlertDescription data-testid="perf-counters-error" className="whitespace-pre-wrap break-words">
              {error}
            </AlertDescription>
          </Alert>
        )}

        <div className="space-y-2">
          <div className="flex items-end gap-2">
            <div className="space-y-1">
              <Label htmlFor="perf-datapath-bridge">Bridge</Label>
              <Input
                id="perf-datapath-bridge"
                data-testid="perf-datapath-bridge"
                placeholder="default bridge"
                value={bridge}
                onChange={(e) => setBridge(e.target.value)}
              />
            </div>
            <Gated op={DATAPATH_OP}>
              <Button
                variant="outline"
                size="sm"
                data-testid="perf-datapath-load"
                disabled={!isAdmin || loading}
                onClick={readDatapath}
              >
                Read datapath
              </Button>
            </Gated>
          </div>
          {datapath && (
            <dl className="grid grid-cols-2 gap-2 text-sm md:grid-cols-4" data-testid="perf-datapath-result">
              <div>
                <dt className="text-muted-foreground">Bridge</dt>
                <dd className="font-mono">{datapath.bridge}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Datapath type</dt>
                <dd className="font-mono">{datapath.datapathType}</dd>
              </div>
              <Counter label="Hits" value={datapath.hits} />
              <Counter label="Misses" value={datapath.misses} />
              <Counter label="Lost" value={datapath.lost} />
              <Counter label="Offloaded flows" value={datapath.offloadedFlowCount} />
              <div>
                <dd>Hardware offload: {datapath.hwOffloadEnabled ? 'on' : 'off'}</dd>
              </div>
            </dl>
          )}
        </div>

        <div className="space-y-2">
          <div className="flex items-end gap-2">
            <div className="space-y-1">
              <Label htmlFor="perf-conntrack-zone">Zone</Label>
              <Input
                id="perf-conntrack-zone"
                data-testid="perf-conntrack-zone"
                placeholder="every zone"
                inputMode="numeric"
                value={zone}
                onChange={(e) => setZone(e.target.value)}
              />
            </div>
            <Gated op={CONNTRACK_OP}>
              <Button
                variant="outline"
                size="sm"
                data-testid="perf-conntrack-load"
                disabled={!isAdmin || loading || zoneValue === null}
                onClick={readConntrack}
              >
                Read conntrack
              </Button>
            </Gated>
          </div>
          {conntrack && (
            <div className="text-sm" data-testid="perf-conntrack-result">
              <p className="font-bold">Total entries {conntrack.totalEntries || '0'}</p>
              <ul>
                {zones.map(([k, v]) => (
                  <li key={k}>
                    Zone {k}: {v}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
