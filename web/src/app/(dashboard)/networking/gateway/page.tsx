'use client';

import { Plus, RefreshCw, Activity, Lock, AlertCircle, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { isServiceNotConfigured } from 'trusted-platform-sdk';
import { useGateway, useApi, useToast, useReportedGateways } from '@/hooks';

export default function APIGatewayPage() {
  const { toast } = useToast();
  const gateway = useGateway();

  // Reported gateways consume /api/v1/gateway/state — the platform
  // control-plane surface that gatewayd POSTs telemetry into. This
  // path is independent of the SDK GatewayService gRPC calls below;
  // the data flows regardless of whether the gRPC backend is
  // reachable, so the WebUI stays useful even when gatewayd hasn't
  // attached itself to the in-process service.
  const {
    gateways: reportedGateways,
    isLoading: reportedLoading,
    error: reportedError,
    refetch: fetchReportedGateways,
  } = useReportedGateways({ refreshMs: 30_000 });

  // Fetch gateway status
  const {
    data: statusData,
    isLoading: statusLoading,
    error: statusError,
    refetch: refetchStatus,
  } = useApi(
    () => gateway.getStatus(),
    [],
    {
      onError: (err) => {
        // A structured 503 means gatewayd is not wired on this node
        // (e.g. a control plane) — rendered as an informational state
        // below, not an error toast.
        if (isServiceNotConfigured(err)) {
          return;
        }
        toast({
          title: 'Error loading gateway status',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Fetch BGP status
  const {
    data: bgpStatusData,
    isLoading: bgpStatusLoading,
    error: bgpStatusError,
    refetch: refetchBGPStatus,
  } = useApi(
    () => gateway.getBGPStatus(),
    [],
    {
      onError: (err) => {
        // A structured 503 means gatewayd is not wired on this node
        // (e.g. a control plane) — rendered as an informational state
        // below, not an error toast.
        if (isServiceNotConfigured(err)) {
          return;
        }
        toast({
          title: 'Error loading BGP status',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Fetch announced prefixes
  const {
    data: prefixesData,
    isLoading: prefixesLoading,
    error: prefixesError,
    refetch: refetchPrefixes,
  } = useApi(
    () => gateway.listAnnouncedPrefixes(),
    [],
    {
      onError: (err) => {
        // A structured 503 means gatewayd is not wired on this node
        // (e.g. a control plane) — rendered as an informational state
        // below, not an error toast.
        if (isServiceNotConfigured(err)) {
          return;
        }
        toast({
          title: 'Error loading announced prefixes',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Fetch IPAM pools
  const {
    data: ipamPoolsData,
    isLoading: ipamPoolsLoading,
    error: ipamPoolsError,
    refetch: refetchIPAMPools,
  } = useApi(
    () => gateway.listIPAMPools(),
    [],
    {
      onError: (err) => {
        // A structured 503 means gatewayd is not wired on this node
        // (e.g. a control plane) — rendered as an informational state
        // below, not an error toast.
        if (isServiceNotConfigured(err)) {
          return;
        }
        toast({
          title: 'Error loading IPAM pools',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  const isLoading = statusLoading || bgpStatusLoading || prefixesLoading || ipamPoolsLoading;
  // The gateway service can be deployed without a backing controller
  // (gatewayd not running). When all four endpoints return the typed
  // 503 "gateway not configured" we want to render the empty page
  // shell, not block on it forever. Treat that specific error as an
  // empty state so the user sees the page and can navigate away.
  const allUnavailable = [statusError, bgpStatusError, prefixesError, ipamPoolsError]
    .every((e) => isServiceNotConfigured(e));
  const localError = allUnavailable ? undefined : (statusError || bgpStatusError || prefixesError || ipamPoolsError);

  const status = statusData?.status || null;
  const bgpStatus = bgpStatusData?.status || null;
  const announcedPrefixes = prefixesData?.prefixes || [];
  const ipamPools = ipamPoolsData?.pools || [];

  const fetchData = () => {
    void fetchReportedGateways();
    refetchStatus();
    refetchBGPStatus();
    refetchPrefixes();
    refetchIPAMPools();
  };

  // The legacy SDK-backed view (Status / BGP / IPAM cards below)
  // can hang or error when no in-process GatewayService gRPC
  // backend is reachable. Don't block the entire page on it — the
  // Reported Gateways card above still renders useful telemetry
  // from the control-plane endpoint. We log the error inline if
  // there is one and let the rest of the page render.

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Gateway</h1>
          <p className="text-muted-foreground mt-1">
            Manage gateway configuration, BGP routing, and IPAM
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="icon" onClick={fetchData} disabled={isLoading}>
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>
          <Button>
            <Plus className="mr-2 h-4 w-4" />
            Add Route
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Reported Gateways</CardTitle>
          <CardDescription>
            Live telemetry posted by each gatewayd via{' '}
            <code className="font-mono text-xs">POST /api/v1/gateway/telemetry</code>.
            Updates every 30 seconds.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {reportedLoading && reportedGateways.length === 0 ? (
            <p className="text-sm text-muted-foreground py-4">
              <Loader2 className="inline-block h-4 w-4 animate-spin mr-2" />
              Loading reported gateways…
            </p>
          ) : reportedError ? (
            <p className="text-sm text-destructive">
              Failed to load: {reportedError}
            </p>
          ) : reportedGateways.length === 0 ? (
            <p className="text-sm text-muted-foreground py-4">
              No gatewayd processes have reported yet. Start gatewayd
              with the platform CP base URL in its config to populate
              this view.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Gateway ID</TableHead>
                  <TableHead>Hostname</TableHead>
                  <TableHead>Mode</TableHead>
                  <TableHead>Health</TableHead>
                  <TableHead>BGP</TableHead>
                  <TableHead>Last Report</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reportedGateways.map((g) => (
                  <TableRow key={g.gateway_id}>
                    <TableCell className="font-mono text-xs">
                      {g.gateway_id}
                    </TableCell>
                    <TableCell>{g.hostname ?? '—'}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{g.mode ?? '—'}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge
                        className={
                          g.health?.status === 'healthy'
                            ? 'bg-green-500/10 text-green-600 border-green-500/20'
                            : 'bg-red-500/10 text-red-600 border-red-500/20'
                        }
                      >
                        {g.health?.status ?? 'unknown'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs">
                      {g.bgp?.established_peers ?? 0}/
                      {g.bgp?.peer_count ?? 0} peers
                    </TableCell>
                    <TableCell className="text-xs">
                      {new Date(g.reported_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {allUnavailable ? (
        <Card>
          <CardContent className="py-6">
            <p className="text-sm text-muted-foreground">
              This node does not run gatewayd, so there is no local
              gateway service to report on. The Reported Gateways table
              above is the fleet view; local status, BGP and IPAM cards
              appear on nodes running the gateway role.
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          {localError && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Error loading local gateway service</AlertTitle>
              <AlertDescription>{localError.message}</AlertDescription>
            </Alert>
          )}

          <div className="grid gap-4 md:grid-cols-4">
          <div className="rounded-lg border border-border bg-card p-6">
            <div className="flex items-center gap-2 text-muted-foreground mb-2">
              <Activity className="h-4 w-4" />
              <span className="text-sm font-medium">Status</span>
            </div>
            <div className="text-2xl font-bold">
              {status?.healthy ? (
                <Badge className="bg-green-500/10 text-green-500 border-green-500/20">
                  Healthy
                </Badge>
              ) : (
                <Badge className="bg-red-500/10 text-red-500 border-red-500/20">
                  Unhealthy
                </Badge>
              )}
            </div>
          </div>
          <div className="rounded-lg border border-border bg-card p-6">
            <div className="text-sm font-medium text-muted-foreground">Uptime</div>
            <div className="text-3xl font-bold mt-2">
              {status?.uptimeSeconds ? Math.floor(status.uptimeSeconds / 3600) : 0}h
            </div>
          </div>
          <div className="rounded-lg border border-border bg-card p-6">
            <div className="text-sm font-medium text-muted-foreground">BGP Peers</div>
            <div className="text-3xl font-bold mt-2">
              {bgpStatus?.establishedPeers || 0} / {bgpStatus?.peerCount || 0}
            </div>
          </div>
          <div className="rounded-lg border border-border bg-card p-6">
            <div className="text-sm font-medium text-muted-foreground">IPAM Pools</div>
            <div className="text-3xl font-bold mt-2">{ipamPools.length}</div>
          </div>
        </div>

        <div className="grid gap-6 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5" />
                BGP Announced Prefixes
              </CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="flex items-center justify-center h-32">
                  <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </div>
              ) : announcedPrefixes.length === 0 ? (
                <p className="text-center text-muted-foreground py-8">
                  No announced prefixes
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Prefix</TableHead>
                      <TableHead>Next Hop</TableHead>
                      <TableHead>Announced</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {announcedPrefixes.slice(0, 5).map((prefix, index) => (
                      <TableRow key={index}>
                        <TableCell className="font-mono text-sm">
                          {prefix.prefix}
                        </TableCell>
                        <TableCell className="font-mono text-sm">
                          {prefix.nextHop}
                        </TableCell>
                        <TableCell className="text-sm">
                          {prefix.announcedAt ? new Date(prefix.announcedAt).toLocaleString() : '-'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Lock className="h-5 w-5" />
                IPAM Pools
              </CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="flex items-center justify-center h-32">
                  <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </div>
              ) : ipamPools.length === 0 ? (
                <p className="text-center text-muted-foreground py-8">
                  No IPAM pools configured
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Pool ID</TableHead>
                      <TableHead>CIDR</TableHead>
                      <TableHead>Available</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {ipamPools.slice(0, 5).map((pool) => (
                      <TableRow key={pool.id}>
                        <TableCell className="font-medium">{pool.id}</TableCell>
                        <TableCell className="font-mono text-sm">
                          {pool.cidr}
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary">
                            {pool.available || 0}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>

        {bgpStatus && (
          <Card>
            <CardHeader>
              <CardTitle>BGP Status</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-3">
                <div className="space-y-2">
                  <div className="text-sm font-medium text-muted-foreground">Local ASN</div>
                  <div className="text-2xl font-bold">{bgpStatus.localAsn}</div>
                </div>
                <div className="space-y-2">
                  <div className="text-sm font-medium text-muted-foreground">Router ID</div>
                  <div className="text-xl font-mono">{bgpStatus.routerId}</div>
                </div>
                <div className="space-y-2">
                  <div className="text-sm font-medium text-muted-foreground">Prefixes Announced</div>
                  <div className="text-2xl font-bold">{bgpStatus.prefixesAnnounced}</div>
                </div>
              </div>
            </CardContent>
          </Card>
          )}
        </>
      )}
    </div>
  );
}
