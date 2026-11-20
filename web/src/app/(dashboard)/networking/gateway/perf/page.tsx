'use client';
import * as React from 'react';
import { Loader2, Play, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { counterEntries, useGatewayPerf, type PerfCard } from '@/hooks/use-gateway-perf';

/** The scalar counters of one report, its raw payload, or why it has none. */
function PerfReport({ title, card }: { title: string; card: PerfCard }) {
  if (card.error) {
    return (
      <p className="text-sm text-muted-foreground">
        {title} unavailable: {card.error.message}
      </p>
    );
  }
  if (card.loading && !card.data) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" /> Loading…
      </div>
    );
  }
  const entries = counterEntries(card.data);
  return (
    <div className="space-y-2">
      {entries.length === 0 ? (
        <p className="text-sm text-muted-foreground">No counters reported.</p>
      ) : (
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
          {entries.map(([k, v]) => (
            <React.Fragment key={k}>
              <dt className="text-muted-foreground">{k}</dt>
              <dd className="font-mono">{String(v)}</dd>
            </React.Fragment>
          ))}
        </dl>
      )}
      <details>
        <summary className="cursor-pointer text-sm text-muted-foreground">Raw response</summary>
        <pre className="mt-2 max-h-80 overflow-auto rounded bg-muted p-2 text-xs">
          {JSON.stringify(card.data ?? {}, null, 2)}
        </pre>
      </details>
    </div>
  );
}

export default function GatewayPerfPage() {
  const { flows, datapath, conntrack, runFlows, loadDatapath, loadConntrack } = useGatewayPerf();
  const [bridge, setBridge] = React.useState('');
  const [zone, setZone] = React.useState('');
  const [zoneError, setZoneError] = React.useState<string | null>(null);

  const onDatapath = (e: React.FormEvent) => {
    e.preventDefault();
    void loadDatapath(bridge.trim() || undefined);
  };

  const onConntrack = (e: React.FormEvent) => {
    e.preventDefault();
    const raw = zone.trim();
    if (raw === '') {
      setZoneError(null);
      void loadConntrack();
      return;
    }
    const z = Number(raw);
    if (!/^\d+$/.test(raw) || z > 0xffffffff) {
      setZoneError('Zone must be a number from 0 to 4294967295');
      return;
    }
    setZoneError(null);
    void loadConntrack(z);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Gateway performance</h1>
        <p className="text-muted-foreground">
          Flow, datapath and conntrack counters reported by the gateway.
        </p>
      </div>

      <Card data-testid="gateway-perf-flows">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Flows</CardTitle>
          <Button variant="outline" size="sm" onClick={() => void runFlows()} disabled={flows.loading}>
            <Play className="mr-2 h-4 w-4" />
            Run flows report
          </Button>
        </CardHeader>
        <CardContent>
          <PerfReport title="Flows report" card={flows} />
        </CardContent>
      </Card>

      <Card data-testid="gateway-perf-datapath">
        <CardHeader>
          <CardTitle>Datapath</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <form className="flex flex-wrap items-end gap-3" onSubmit={onDatapath}>
            <div className="space-y-1">
              <Label htmlFor="perf-bridge">Bridge</Label>
              <Input
                id="perf-bridge"
                value={bridge}
                onChange={(e) => setBridge(e.target.value)}
                placeholder="all bridges"
              />
            </div>
            <Button type="submit" variant="outline" disabled={datapath.loading}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Load datapath
            </Button>
          </form>
          <PerfReport title="Datapath counters" card={datapath} />
        </CardContent>
      </Card>

      <Card data-testid="gateway-perf-conntrack">
        <CardHeader>
          <CardTitle>Conntrack</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <form className="flex flex-wrap items-end gap-3" onSubmit={onConntrack}>
            <div className="space-y-1">
              <Label htmlFor="perf-zone">Zone</Label>
              <Input
                id="perf-zone"
                inputMode="numeric"
                value={zone}
                onChange={(e) => setZone(e.target.value)}
                placeholder="all zones"
              />
            </div>
            <Button type="submit" variant="outline" disabled={conntrack.loading}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Load conntrack
            </Button>
          </form>
          {zoneError && (
            <p role="alert" className="text-sm text-destructive">
              {zoneError}
            </p>
          )}
          <PerfReport title="Conntrack counters" card={conntrack} />
        </CardContent>
      </Card>
    </div>
  );
}
