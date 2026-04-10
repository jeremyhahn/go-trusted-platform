'use client';

import { Plus, RefreshCw, Activity, Lock, AlertCircle, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
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
import { useGateway, useApi, useToast } from '@/hooks';

export default function APIGatewayPage() {
  const { toast } = useToast();
  const gateway = useGateway();

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
        toast({
          title: 'Error loading IPAM pools',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  const isLoading = statusLoading || bgpStatusLoading || prefixesLoading || ipamPoolsLoading;
  const error = statusError || bgpStatusError || prefixesError || ipamPoolsError;

  const status = statusData?.status || null;
  const bgpStatus = bgpStatusData?.status || null;
  const announcedPrefixes = prefixesData?.prefixes || [];
  const ipamPools = ipamPoolsData?.pools || [];

  const fetchData = () => {
    refetchStatus();
    refetchBGPStatus();
    refetchPrefixes();
    refetchIPAMPools();
  };

  // Show error state
  if (error) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Gateway</AlertTitle>
          <AlertDescription>
            {error.message}
            <Button
              variant="outline"
              size="sm"
              className="ml-4"
              onClick={fetchData}
            >
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  // Show loading state
  if (isLoading && !status) {
    return (
      <div className="container mx-auto py-6">
        <Card>
          <CardContent className="py-6 flex items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin mr-2" />
            <span>Loading gateway...</span>
          </CardContent>
        </Card>
      </div>
    );
  }

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
    </div>
  );
}
