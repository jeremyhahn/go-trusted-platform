'use client';

import { useState } from 'react';
import { AlertCircle, FileCode, Loader2, Plus, RefreshCw, Shield, Users } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
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
import { ServiceUnavailableState } from '@/components/features/platform';
import { isServiceNotConfigured } from 'trusted-platform-sdk';
import { useApi, useToast, useVPN } from '@/hooks';
import type { ApiResponse, VPNPeer, VPNPosturePolicy } from 'trusted-platform-sdk';

/** A posture policy in the editor; `isNew` unlocks the tenant and name. */
interface PolicyDraft {
  tenantId: string;
  name: string;
  module: string;
  isNew: boolean;
}

/** Renders a protojson Unix-seconds string; zero means the field is unset. */
function formatUnix(seconds: string): string {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value <= 0) {
    return '—';
  }
  return new Date(value * 1000).toLocaleString();
}

/** The SDK reports a failed call in the response; mutations need it thrown. */
function throwOnError<T>(response: ApiResponse<T>): void {
  if (response.error !== undefined) {
    throw new Error(response.error.message);
  }
}

export default function VPNPage() {
  const { toast } = useToast();
  const vpn = useVPN();
  const [revoking, setRevoking] = useState<VPNPeer | null>(null);
  const [revokeSubmitting, setRevokeSubmitting] = useState(false);
  const [draft, setDraft] = useState<PolicyDraft | null>(null);
  const [draftSubmitting, setDraftSubmitting] = useState(false);

  const notConfiguredQuiet = (title: string) => ({
    onError: (err: Error) => {
      // A structured 503 means this node runs no VPN control plane; it is
      // rendered as an informational state, not an error toast.
      if (isServiceNotConfigured(err)) {
        return;
      }
      toast({ title, description: err.message, variant: 'destructive' });
    },
  });

  const {
    data: statusData,
    isLoading: statusLoading,
    error: statusError,
    refetch: refetchStatus,
  } = useApi(() => vpn.getStatus(), [], notConfiguredQuiet('Error loading VPN status'));

  const {
    data: peersData,
    isLoading: peersLoading,
    error: peersError,
    refetch: refetchPeers,
  } = useApi(() => vpn.listPeers(), [], notConfiguredQuiet('Error loading VPN peers'));

  const {
    data: policiesData,
    isLoading: policiesLoading,
    error: policiesError,
    refetch: refetchPolicies,
  } = useApi(
    () => vpn.listPosturePolicies(),
    [],
    notConfiguredQuiet('Error loading posture policies')
  );

  const gateways = statusData?.gateways ?? [];
  const peers = peersData?.peers ?? [];
  const policies = policiesData?.policies ?? [];
  const isLoading = statusLoading || peersLoading || policiesLoading;
  const vpnUnavailable =
    isServiceNotConfigured(statusError) ||
    isServiceNotConfigured(peersError) ||
    isServiceNotConfigured(policiesError);
  // Status alone fails on a daemon without gateway telemetry; peers and
  // policies are still worth showing then, so only their errors are fatal.
  const error = peersError ?? policiesError;

  const fetchData = () => {
    refetchStatus();
    refetchPeers();
    refetchPolicies();
  };

  const revokePeer = async (peer: VPNPeer) => {
    setRevokeSubmitting(true);
    try {
      throwOnError(await vpn.revokePeer(peer.tenantId, peer.deviceId));
      toast({ title: `Revoked ${peer.deviceId}`, variant: 'success' });
      setRevoking(null);
      refetchPeers();
      refetchStatus();
    } catch (err) {
      toast({
        title: 'Failed to revoke peer',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setRevokeSubmitting(false);
    }
  };

  const openPolicy = async (policy: VPNPosturePolicy) => {
    try {
      const response = await vpn.getPosturePolicy(policy.tenantId, policy.name);
      throwOnError(response);
      const stored = response.data?.policy ?? policy;
      setDraft({ tenantId: stored.tenantId, name: stored.name, module: stored.module, isNew: false });
    } catch (err) {
      toast({
        title: 'Failed to load posture policy',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  const savePolicy = async (policy: PolicyDraft) => {
    setDraftSubmitting(true);
    try {
      throwOnError(
        await vpn.setPosturePolicy({
          tenantId: policy.tenantId,
          name: policy.name,
          module: policy.module,
        })
      );
      toast({ title: `Saved posture policy ${policy.name}`, variant: 'success' });
      setDraft(null);
      refetchPolicies();
    } catch (err) {
      // A module that does not compile is refused here; the dialog stays
      // open so the operator can fix it.
      toast({
        title: 'Failed to save posture policy',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setDraftSubmitting(false);
    }
  };

  const header = (
    <div>
      <h1 className="text-3xl font-bold">VPN</h1>
      <p className="text-muted-foreground mt-1">
        Remote-access sessions, enrolled peers and tenant posture policies
      </p>
    </div>
  );

  if (vpnUnavailable) {
    return (
      <div className="container mx-auto py-6 space-y-6">
        {header}
        <ServiceUnavailableState
          service="VPN"
          description="This node runs no VPN control plane. Point the console at the control-plane node."
        />
      </div>
    );
  }

  if (error) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading VPN</AlertTitle>
          <AlertDescription>
            {error.message}
            <Button variant="outline" size="sm" className="ml-4" onClick={fetchData}>
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  if (isLoading && peers.length === 0 && policies.length === 0) {
    return (
      <div className="container mx-auto py-6">
        <Card>
          <CardContent className="py-6 flex items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin mr-2" />
            <span>Loading VPN data...</span>
          </CardContent>
        </Card>
      </div>
    );
  }

  const leases = gateways.flatMap((gateway) =>
    gateway.leases.map((lease) => ({ gatewayId: gateway.gatewayId, lease }))
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        {header}
        <Button variant="outline" size="icon" onClick={fetchData} disabled={isLoading} aria-label="Refresh">
          <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Gateways
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {statusError ? (
            <p className="text-sm text-muted-foreground">
              Session status is unavailable: {statusError.message}
            </p>
          ) : gateways.length === 0 ? (
            <p className="text-sm text-muted-foreground">No gateway has reported yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Gateway</TableHead>
                  <TableHead>VPN</TableHead>
                  <TableHead>Admissions</TableHead>
                  <TableHead>Refusals</TableHead>
                  <TableHead>Last Refusal</TableHead>
                  <TableHead>Last Report</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {gateways.map((gateway) => (
                  <TableRow key={gateway.gatewayId}>
                    <TableCell className="font-mono text-sm">{gateway.gatewayId}</TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {!gateway.reporting ? 'not configured' : gateway.running ? 'running' : 'stopped'}
                      </Badge>
                    </TableCell>
                    <TableCell>{gateway.admissions}</TableCell>
                    <TableCell>{gateway.refusals}</TableCell>
                    <TableCell className="text-sm">{gateway.lastRefusal || '—'}</TableCell>
                    <TableCell className="text-xs">{formatUnix(gateway.reportedAtUnix)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          {gateways.flatMap((gateway) =>
            gateway.rejectedPeers.map((rejected) => (
              <Alert key={`${gateway.gatewayId}/${rejected.tenantId}/${rejected.deviceId}`} variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>
                  {gateway.gatewayId} refused {rejected.tenantId}/{rejected.deviceId}
                </AlertTitle>
                <AlertDescription>{rejected.reason}</AlertDescription>
              </Alert>
            ))
          )}
          {gateways.flatMap((gateway) =>
            gateway.posturePolicyErrors.map((policyError) => (
              <Alert key={`${gateway.gatewayId}/${policyError}`} variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>{gateway.gatewayId} could not load a posture policy</AlertTitle>
                <AlertDescription>{policyError}</AlertDescription>
              </Alert>
            ))
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Sessions</CardTitle>
        </CardHeader>
        <CardContent>
          {leases.length === 0 ? (
            <p className="text-sm text-muted-foreground">No live sessions.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Gateway</TableHead>
                  <TableHead>Tenant</TableHead>
                  <TableHead>Device</TableHead>
                  <TableHead>Address</TableHead>
                  <TableHead>Data Plane</TableHead>
                  <TableHead>Zones</TableHead>
                  <TableHead>Expires</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {leases.map(({ gatewayId, lease }) => (
                  <TableRow key={`${gatewayId}/${lease.id}`}>
                    <TableCell className="font-mono text-sm">{gatewayId}</TableCell>
                    <TableCell>{lease.tenantId}</TableCell>
                    <TableCell className="font-mono text-sm">{lease.deviceId}</TableCell>
                    <TableCell className="font-mono text-sm">{lease.address}</TableCell>
                    <TableCell>{lease.dataPlane}</TableCell>
                    <TableCell>{lease.zones.length > 0 ? lease.zones.join(', ') : 'all allowed'}</TableCell>
                    <TableCell className="text-xs">{formatUnix(lease.expiresAtUnix)}</TableCell>
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
            <Users className="h-5 w-5" />
            Enrolled Peers
          </CardTitle>
        </CardHeader>
        <CardContent>
          {peers.length === 0 ? (
            <p className="text-sm text-muted-foreground">No peers are enrolled.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Tenant</TableHead>
                  <TableHead>Device</TableHead>
                  <TableHead>Zones</TableHead>
                  <TableHead>Enrolled</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {peers.map((peer) => (
                  <TableRow key={`${peer.tenantId}/${peer.deviceId}`}>
                    <TableCell>{peer.tenantId}</TableCell>
                    <TableCell className="font-mono text-sm">{peer.deviceId}</TableCell>
                    <TableCell>{peer.zones.length > 0 ? peer.zones.join(', ') : 'all allowed'}</TableCell>
                    <TableCell className="text-xs">{formatUnix(peer.enrolledAtUnix)}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => setRevoking(peer)}
                        aria-label={`Revoke ${peer.deviceId}`}
                      >
                        Revoke
                      </Button>
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
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <FileCode className="h-5 w-5" />
              Posture Policies
            </CardTitle>
            <Button
              size="sm"
              onClick={() => setDraft({ tenantId: '', name: '', module: 'package vpn.posture\n', isNew: true })}
            >
              <Plus className="mr-2 h-4 w-4" />
              New Policy
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {policies.length === 0 ? (
            <p className="text-sm text-muted-foreground">No posture policies are stored.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Tenant</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Updated</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {policies.map((policy) => (
                  <TableRow key={`${policy.tenantId}/${policy.name}`}>
                    <TableCell>{policy.tenantId}</TableCell>
                    <TableCell className="font-mono text-sm">{policy.name}</TableCell>
                    <TableCell className="text-xs">{formatUnix(policy.updatedAtUnix)}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openPolicy(policy)}
                        aria-label={`Edit ${policy.name}`}
                      >
                        View / Edit
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog open={revoking !== null} onOpenChange={(open) => !open && setRevoking(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke VPN Peer</DialogTitle>
            <DialogDescription>
              {revoking
                ? `Revoke ${revoking.deviceId} of tenant ${revoking.tenantId}? The gateways end its sessions when the change reaches them.`
                : ''}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRevoking(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={revokeSubmitting}
              onClick={() => revoking && revokePeer(revoking)}
            >
              {revokeSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Confirm Revoke
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={draft !== null} onOpenChange={(open) => !open && setDraft(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{draft?.isNew ? 'New Posture Policy' : `Posture Policy ${draft?.name ?? ''}`}</DialogTitle>
            <DialogDescription>
              A Rego module in package vpn.posture. A module that does not compile is refused.
            </DialogDescription>
          </DialogHeader>
          {draft && (
            <div className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="vpn-policy-tenant">Tenant *</Label>
                  <Input
                    id="vpn-policy-tenant"
                    value={draft.tenantId}
                    disabled={!draft.isNew}
                    onChange={(e) => setDraft({ ...draft, tenantId: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="vpn-policy-name">Name *</Label>
                  <Input
                    id="vpn-policy-name"
                    value={draft.name}
                    disabled={!draft.isNew}
                    onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="vpn-policy-module">Module *</Label>
                <Textarea
                  id="vpn-policy-module"
                  className="font-mono text-xs min-h-[240px]"
                  value={draft.module}
                  onChange={(e) => setDraft({ ...draft, module: e.target.value })}
                />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setDraft(null)}>
              Cancel
            </Button>
            <Button
              disabled={!draft || !draft.tenantId || !draft.name || !draft.module || draftSubmitting}
              onClick={() => draft && savePolicy(draft)}
            >
              {draftSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
