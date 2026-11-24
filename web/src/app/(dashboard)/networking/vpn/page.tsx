'use client';

import { useRef, useState } from 'react';
import { AlertCircle, FileCode, Loader2, Plus, RefreshCw, Shield, Trash2, Users } from 'lucide-react';
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
import { Gated } from '@/components/features/capabilities/gated';
import { isServiceNotConfigured } from 'trusted-platform-sdk';
import { useApi, useToast, useVPN } from '@/hooks';
import type { ApiResponse, VPNGatewayStatus, VPNPeer, VPNPosturePolicy } from 'trusted-platform-sdk';

/** A posture policy in the editor; `isNew` unlocks the tenant and name. */
interface PolicyDraft {
  tenantId: string;
  name: string;
  module: string;
  isNew: boolean;
}

/** A peer in the enrol dialog; `zones` is the comma-separated text the operator types. */
interface PeerDraft {
  tenantId: string;
  deviceId: string;
  zones: string;
}

/** Splits the comma-separated zone list; an empty list means every allowed zone. */
function parseZones(text: string): string[] {
  return text
    .split(',')
    .map((zone) => zone.trim())
    .filter((zone) => zone !== '');
}

/** Renders a protojson Unix-seconds string; zero means the field is unset. */
function formatUnix(seconds: string): string {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value <= 0) {
    return '—';
  }
  return new Date(value * 1000).toLocaleString();
}

/** Renders a protojson count map as `key: value` pairs; an empty map reads none. */
function formatCounts(counts: Record<string, string | number> | null | undefined): string {
  const entries = Object.entries(counts ?? {});
  if (entries.length === 0) {
    return 'none';
  }
  return entries.map(([key, value]) => `${key}: ${value}`).join(', ');
}

/** Renders a re-attestation histogram as its count and mean time. */
function formatReattest(reattest: VPNGatewayStatus['reattest']): string {
  const count = Number(reattest?.count ?? 0);
  if (!reattest || !Number.isFinite(count) || count <= 0) {
    return 'no re-attestations';
  }
  return `${count} re-attestations, mean ${Math.round((reattest.sumSeconds / count) * 1000)} ms`;
}

/** The SDK reports a failed call in the response; mutations need it thrown. */
function throwOnError<T>(response: ApiResponse<T>): void {
  if (response.error !== undefined) {
    throw new Error(response.error.message);
  }
}

/**
 * latest numbers each read on gen and answers with neither data nor error
 * when a newer read on the same counter started meanwhile: useApi then keeps
 * the newer answer, raises no error state and shows no toast.
 */
async function latest<T>(gen: { current: number }, read: () => Promise<ApiResponse<T>>): Promise<ApiResponse<T>> {
  const mine = ++gen.current;
  const response = await read();
  return mine === gen.current ? response : ({} as ApiResponse<T>);
}

export default function VPNPage() {
  const { toast } = useToast();
  const vpn = useVPN();
  const [revoking, setRevoking] = useState<VPNPeer | null>(null);
  const [revokeSubmitting, setRevokeSubmitting] = useState(false);
  const [draft, setDraft] = useState<PolicyDraft | null>(null);
  const [draftSubmitting, setDraftSubmitting] = useState(false);
  const [enrolling, setEnrolling] = useState<PeerDraft | null>(null);
  const [enrolSubmitting, setEnrolSubmitting] = useState(false);
  const [deleting, setDeleting] = useState<VPNPosturePolicy | null>(null);
  const [deleteSubmitting, setDeleteSubmitting] = useState(false);
  const [tenantInput, setTenantInput] = useState('');
  const [gatewayInput, setGatewayInput] = useState('');
  // Filter answers that arrive after a newer filter was applied are dropped (#2070).
  const [filters, setFilters] = useState({ tenant: '', gateway: '' });
  const statusGen = useRef(0);
  const tenantGen = useRef(0);
  const policiesGen = useRef(0);

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
  } = useApi(
    () =>
      latest(statusGen, async (): Promise<ApiResponse<{ gateways?: VPNGatewayStatus[]; gateway?: string }>> => {
        const gateway = filters.gateway;
        const response = await vpn.getStatus(gateway || undefined);
        return response.data !== undefined ? { ...response, data: { ...response.data, gateway } } : response;
      }),
    [filters.gateway],
    notConfiguredQuiet('Error loading VPN status')
  );

  const {
    data: peersData,
    isLoading: peersLoading,
    error: peersError,
    refetch: refetchPeers,
  } = useApi(
    () =>
      latest(tenantGen, async (): Promise<ApiResponse<{ peers?: VPNPeer[]; tenant?: string }>> => {
        const tenant = filters.tenant;
        const response = await vpn.listPeers(tenant || undefined);
        return response.data !== undefined ? { ...response, data: { ...response.data, tenant } } : response;
      }),
    [filters.tenant],
    notConfiguredQuiet('Error loading VPN peers')
  );

  const {
    data: policiesData,
    isLoading: policiesLoading,
    error: policiesError,
    refetch: refetchPolicies,
  } = useApi(
    () =>
      latest(policiesGen, async (): Promise<ApiResponse<{ policies?: VPNPosturePolicy[]; tenant?: string }>> => {
        const tenant = filters.tenant;
        const response = await vpn.listPosturePolicies(tenant || undefined);
        return response.data !== undefined ? { ...response, data: { ...response.data, tenant } } : response;
      }),
    [filters.tenant],
    notConfiguredQuiet('Error loading posture policies')
  );

  // Telemetry is shown only for the filter that answered (#2070). Peers and
  // posture policies, too, are shown only for the tenant filter that answered,
  // so a pending tenant read never leaves the previous tenant's rows actionable.
  const gateways = !statusError && statusData?.gateway === filters.gateway ? (statusData?.gateways ?? []) : [];
  const peers = peersData?.tenant === filters.tenant ? (peersData?.peers ?? []) : [];
  const policies = policiesData?.tenant === filters.tenant ? (policiesData?.policies ?? []) : [];
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

  const clearFilters = () => {
    setTenantInput('');
    setGatewayInput('');
    setFilters({ tenant: '', gateway: '' });
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

  const enrolPeer = async (peer: PeerDraft) => {
    setEnrolSubmitting(true);
    try {
      // Enrolling an enrolled device replaces its zones and keeps its first
      // enrolment time (docs/vpn/cli.md).
      throwOnError(
        await vpn.enrolPeer({
          tenantId: peer.tenantId.trim(),
          deviceId: peer.deviceId.trim(),
          zones: parseZones(peer.zones),
        })
      );
      toast({ title: `Enrolled ${peer.deviceId.trim()}`, variant: 'success' });
      setEnrolling(null);
      refetchPeers();
      refetchStatus();
    } catch (err) {
      toast({
        title: 'Failed to enrol peer',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setEnrolSubmitting(false);
    }
  };

  const deletePolicy = async (policy: VPNPosturePolicy) => {
    setDeleteSubmitting(true);
    try {
      throwOnError(await vpn.deletePosturePolicy(policy.tenantId, policy.name));
      toast({ title: `Deleted posture policy ${policy.name}`, variant: 'success' });
      setDeleting(null);
      refetchPolicies();
    } catch (err) {
      toast({
        title: 'Failed to delete posture policy',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setDeleteSubmitting(false);
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
      <div className="container mx-auto py-6 space-y-6" data-testid="vpn-unavailable">
        {header}
        <ServiceUnavailableState
          service="VPN"
          description="This node runs no VPN control plane. Point the console at the control-plane node."
        />
      </div>
    );
  }

  // The filter form stays on the error state too: a filtered read the server
  // refuses (a tenant the caller may not read) is fixed by changing or
  // clearing the filter, not by retrying the same read.
  const filterForm = (
    <form
      role="search"
      aria-label="VPN filters"
      data-testid="vpn-filters"
      className="flex flex-wrap items-end gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        setFilters({ tenant: tenantInput.trim(), gateway: gatewayInput.trim() });
      }}
    >
      <div className="space-y-1">
        <Label htmlFor="vpn-filter-tenant">Tenant</Label>
        <Input
          id="vpn-filter-tenant"
          placeholder="every tenant"
          value={tenantInput}
          onChange={(e) => setTenantInput(e.target.value)}
        />
      </div>
      <div className="space-y-1">
        <Label htmlFor="vpn-filter-gateway">Gateway</Label>
        <Input
          id="vpn-filter-gateway"
          placeholder="every gateway"
          value={gatewayInput}
          onChange={(e) => setGatewayInput(e.target.value)}
        />
      </div>
      <Button type="submit" size="sm" variant="outline">
        Apply filters
      </Button>
      <Button type="button" size="sm" variant="ghost" onClick={clearFilters}>
        Clear filters
      </Button>
    </form>
  );

  if (error) {
    return (
      <div className="container mx-auto py-6 space-y-6">
        {header}
        {filterForm}
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading VPN</AlertTitle>
          <AlertDescription>
            {error.message}
            <Button variant="outline" size="sm" className="ml-4" onClick={fetchData}>
              Retry
            </Button>
            {(filters.tenant || filters.gateway) && (
              <Button variant="outline" size="sm" className="ml-2" onClick={clearFilters}>
                Clear filters
              </Button>
            )}
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

      {filterForm}

      <Card data-testid="vpn-gateways-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Gateways
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {statusError ? (
            <p className="text-sm text-muted-foreground" data-testid="vpn-status-error">
              Session status is unavailable: {statusError.message}
            </p>
          ) : gateways.length === 0 ? (
            <p className="text-sm text-muted-foreground">No gateway has reported yet.</p>
          ) : (
            <Table data-testid="vpn-gateways-table">
              <TableHeader>
                <TableRow>
                  <TableHead>Gateway</TableHead>
                  <TableHead>VPN</TableHead>
                  <TableHead>Peers</TableHead>
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
                    <TableCell>{gateway.enrolledPeers}</TableCell>
                    <TableCell>{gateway.admissions}</TableCell>
                    <TableCell>{gateway.refusals}</TableCell>
                    <TableCell className="text-sm">{gateway.lastRefusal || '—'}</TableCell>
                    <TableCell className="text-xs">{formatUnix(gateway.reportedAtUnix)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          {gateways
            .filter((gateway) => gateway.reporting)
            .map((gateway) => (
              <div
                key={gateway.gatewayId}
                data-testid={`vpn-gateway-detail-${gateway.gatewayId}`}
                className="mt-4 space-y-1 rounded-md border p-3 text-sm"
              >
                <p className="font-mono font-medium">{gateway.gatewayId}</p>
                <p>
                  <span className="text-muted-foreground">Leases by data plane: </span>
                  <span>{formatCounts(gateway.leasesByDataPlane)}</span>
                </p>
                <p>
                  <span className="text-muted-foreground">Revocations: </span>
                  <span>{formatCounts(gateway.revocations)}</span>
                </p>
                <p>
                  <span className="text-muted-foreground">Posture violations: </span>
                  <span>{formatCounts(gateway.postureViolations)}</span>
                </p>
                <p>
                  <span className="text-muted-foreground">Re-attestation: </span>
                  <span>{formatReattest(gateway.reattest)}</span>
                </p>
              </div>
            ))}
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

      <Card data-testid="vpn-sessions-card">
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
                  <TableHead>Issued</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>Renewals</TableHead>
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
                    <TableCell className="text-xs">{formatUnix(lease.issuedAtUnix)}</TableCell>
                    <TableCell className="text-xs">{formatUnix(lease.expiresAtUnix)}</TableCell>
                    <TableCell>{lease.renewals}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card data-testid="vpn-peers-card">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5" />
              Enrolled Peers
            </CardTitle>
            <Gated op="POST /api/v1/vpn/peers">
              <Button size="sm" onClick={() => setEnrolling({ tenantId: '', deviceId: '', zones: '' })}>
                <Plus className="mr-2 h-4 w-4" />
                Enrol Peer
              </Button>
            </Gated>
          </div>
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
                      <Gated op="DELETE /api/v1/vpn/peers/{device_id}">
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => setRevoking(peer)}
                          aria-label={`Revoke ${peer.deviceId}`}
                        >
                          Revoke
                        </Button>
                      </Gated>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card data-testid="vpn-policies-card">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <FileCode className="h-5 w-5" />
              Posture Policies
            </CardTitle>
            <Gated op="PUT /api/v1/vpn/posture-policies/{name}">
              <Button
                size="sm"
                onClick={() => setDraft({ tenantId: '', name: '', module: 'package vpn.posture\n', isNew: true })}
              >
                <Plus className="mr-2 h-4 w-4" />
                New Policy
              </Button>
            </Gated>
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
                      <Gated op="GET /api/v1/vpn/posture-policies/{name}">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => openPolicy(policy)}
                          aria-label={`Edit ${policy.name}`}
                        >
                          View / Edit
                        </Button>
                      </Gated>
                      <Gated op="DELETE /api/v1/vpn/posture-policies/{name}">
                        <Button
                          variant="destructive"
                          size="sm"
                          className="ml-2"
                          onClick={() => setDeleting(policy)}
                          aria-label={`Delete ${policy.name}`}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </Gated>
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
            <Gated op="DELETE /api/v1/vpn/peers/{device_id}">
              <Button
                variant="destructive"
                disabled={revokeSubmitting}
                onClick={() => revoking && revokePeer(revoking)}
              >
                {revokeSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Confirm Revoke
              </Button>
            </Gated>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={enrolling !== null} onOpenChange={(open) => !open && setEnrolling(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Enrol VPN Peer</DialogTitle>
            <DialogDescription>
              Enrolling a device that is already enrolled replaces its zones. The gateways take the
              change on their next pull.
            </DialogDescription>
          </DialogHeader>
          {enrolling && (
            <div className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="vpn-peer-tenant">Tenant *</Label>
                  <Input
                    id="vpn-peer-tenant"
                    value={enrolling.tenantId}
                    onChange={(e) => setEnrolling({ ...enrolling, tenantId: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="vpn-peer-device">Device ID *</Label>
                  <Input
                    id="vpn-peer-device"
                    value={enrolling.deviceId}
                    onChange={(e) => setEnrolling({ ...enrolling, deviceId: e.target.value })}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="vpn-peer-zones">Zones</Label>
                <Input
                  id="vpn-peer-zones"
                  placeholder="management, storage (empty: every allowed zone)"
                  value={enrolling.zones}
                  onChange={(e) => setEnrolling({ ...enrolling, zones: e.target.value })}
                />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEnrolling(null)}>
              Cancel
            </Button>
            <Gated op="POST /api/v1/vpn/peers">
              <Button
                disabled={
                  !enrolling || !enrolling.tenantId.trim() || !enrolling.deviceId.trim() || enrolSubmitting
                }
                onClick={() => enrolling && enrolPeer(enrolling)}
              >
                {enrolSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Enrol
              </Button>
            </Gated>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={deleting !== null} onOpenChange={(open) => !open && setDeleting(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Posture Policy</DialogTitle>
            <DialogDescription>
              {deleting
                ? `Delete posture policy ${deleting.name} of tenant ${deleting.tenantId}? The gateways stop applying it on their next pull.`
                : ''}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleting(null)}>
              Cancel
            </Button>
            <Gated op="DELETE /api/v1/vpn/posture-policies/{name}">
              <Button
                variant="destructive"
                disabled={deleteSubmitting}
                onClick={() => deleting && deletePolicy(deleting)}
              >
                {deleteSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Confirm Delete
              </Button>
            </Gated>
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
            <Gated op="PUT /api/v1/vpn/posture-policies/{name}">
              <Button
                disabled={!draft || !draft.tenantId || !draft.name || !draft.module || draftSubmitting}
                onClick={() => draft && savePolicy(draft)}
              >
                {draftSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Save
              </Button>
            </Gated>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
