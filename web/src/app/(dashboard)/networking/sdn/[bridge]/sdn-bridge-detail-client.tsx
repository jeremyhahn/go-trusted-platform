"use client";

import { useEffect, useState } from 'react';
import { useParams, usePathname, useRouter } from 'next/navigation';
import { ArrowLeft, RefreshCw, Trash2, Plus } from 'lucide-react';
import { resolveDynamicId } from '@/utils/dynamic-route';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { useApi, useSDN, useSDNBridge, useToast } from '@/hooks';
import type { Port, PortStats, SDNPolicy, SDNPolicyType } from 'trusted-platform-sdk';

interface PortView {
  id: string;
  port?: Port;
  stats?: PortStats;
  error?: string;
}

const POLICY_TYPES: SDNPolicyType[] = [
  'POLICY_TYPE_ACL',
  'POLICY_TYPE_QOS',
  'POLICY_TYPE_NAT',
  'POLICY_TYPE_FIREWALL',
  'POLICY_TYPE_ROUTING',
];

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : 'Unknown error';
}

// AuthenticatePortRequest.certificate is a protobuf bytes field, so protojson wants the PEM bytes base64-encoded.
function pemToBase64(pem: string): string {
  let bin = '';
  for (const b of new TextEncoder().encode(pem)) bin += String.fromCharCode(b);
  return btoa(bin);
}

/**
 * SDN bridge detail (#1745): bridge info and delete, per-port state, auth and
 * statistics, and the SDN policies.
 */
export default function SDNBridgeDetailClient() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const { toast } = useToast();
  const sdn = useSDN();
  const bridgeId = resolveDynamicId(params, pathname, 'sdn', 'bridge');
  const {
    bridge,
    ports,
    policies,
    loading,
    bridgeError,
    portsError,
    policiesError,
    refetchBridge,
    refetchPorts,
    refetchPolicies,
  } = useSDNBridge(bridgeId);

  const [confirmDelete, setConfirmDelete] = useState(false);
  const [selectedPort, setSelectedPort] = useState('');
  const [adminState, setAdminState] = useState('down');
  const [certificate, setCertificate] = useState('');
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [applyOpen, setApplyOpen] = useState(false);
  const [policyName, setPolicyName] = useState('');
  const [policyType, setPolicyType] = useState<SDNPolicyType>('POLICY_TYPE_ACL');
  const [viewPolicyId, setViewPolicyId] = useState('');

  // The port panel keeps each answer with the port it was asked for, and
  // drops an answer that arrives after the selection moved on (#1755).
  const [portView, setPortView] = useState<PortView | null>(null);
  const [portReload, setPortReload] = useState(0);
  useEffect(() => {
    setPortView(null);
    if (!selectedPort) return;
    let current = true;
    const id = selectedPort;
    (async () => {
      try {
        const [state, stats] = await Promise.all([sdn.getPort(bridgeId, id), sdn.getPortStats(bridgeId, id)]);
        if (!current) return;
        setPortView({
          id,
          port: state.data?.port,
          stats: stats.data?.stats,
          error: state.error?.message ?? stats.error?.message,
        });
      } catch (err) {
        if (current) setPortView({ id, error: errorText(err) });
      }
    })();
    return () => {
      current = false;
    };
  }, [sdn, bridgeId, selectedPort, portReload]);
  const policyDetail = useApi(
    () => (viewPolicyId ? sdn.getPolicy(viewPolicyId) : Promise.resolve({ success: true, data: null })),
    [viewPolicyId]
  );

  const run = async (
    label: string,
    action: () => Promise<{ success: boolean; error?: { message?: string } }>,
    after?: () => void
  ) => {
    try {
      const res = await action();
      if (!res.success) {
        toast({
          title: `${label} failed`,
          description: res.error?.message ?? 'Request failed',
          variant: 'destructive',
        });
        return;
      }
      toast({ title: label, variant: 'success' });
      after?.();
    } catch (err) {
      toast({ title: `${label} failed`, description: errorText(err), variant: 'destructive' });
    }
  };

  const shown = portView?.id === selectedPort ? portView : null;
  const port = shown?.port;
  const stats = shown?.stats;
  const portError = shown?.error;
  const policy: SDNPolicy | undefined = policyDetail.data?.policy;
  const refreshPort = () => setPortReload((n) => n + 1);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" aria-label="Back" onClick={() => router.push('/networking/sdn')}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold font-mono">{bridge?.config?.name || bridgeId}</h1>
            <p className="text-muted-foreground mt-1">SDN Bridge Details</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="icon" aria-label="Refresh" onClick={refetchBridge} disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
          <Button variant="destructive" onClick={() => setConfirmDelete(true)} disabled={!bridgeId}>
            <Trash2 className="mr-2 h-4 w-4" />
            Delete Bridge
          </Button>
        </div>
      </div>

      <Dialog open={confirmDelete} onOpenChange={setConfirmDelete}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete bridge {bridgeId}?</DialogTitle>
            <DialogDescription>
              The bridge, its ports and its flows are removed. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmDelete(false)}>Cancel</Button>
            <Button
              variant="destructive"
              onClick={() =>
                run('Bridge deleted', () => sdn.deleteBridge(bridgeId), () => {
                  setConfirmDelete(false);
                  router.push('/networking/sdn');
                })
              }
            >
              Confirm Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Card>
        <CardHeader>
          <CardTitle>Bridge Information</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {bridge ? (
            <>
              <div className="flex justify-between">
                <span className="text-muted-foreground">ID</span>
                <span className="font-mono" data-testid="bridge-id">{bridge.id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Type</span>
                <span>{bridge.config?.type ?? '-'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Status</span>
                <Badge variant="outline">{bridge.status ?? '-'}</Badge>
              </div>
            </>
          ) : bridgeError ? (
            <div className="flex items-center justify-between gap-2">
              <div role="alert" data-testid="sdn-bridge-error" className="text-destructive">
                Bridge could not be loaded: {bridgeError}
              </div>
              <Button size="sm" variant="outline" aria-label="Retry bridge" onClick={refetchBridge}>
                Retry
              </Button>
            </div>
          ) : (
            <p className="text-muted-foreground">{loading ? 'Loading bridge' : 'Bridge not found'}</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Ports</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {portsError ? (
                <TableRow>
                  <TableCell colSpan={3} className="text-center">
                    <span role="alert" data-testid="sdn-ports-error" className="text-destructive">
                      Ports could not be loaded: {portsError}
                    </span>{' '}
                    <Button size="sm" variant="outline" aria-label="Retry ports" onClick={refetchPorts}>
                      Retry
                    </Button>
                  </TableCell>
                </TableRow>
              ) : ports.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={3} className="text-center text-muted-foreground">
                    No ports found
                  </TableCell>
                </TableRow>
              ) : (
                ports.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell className="font-medium">{p.config?.name || p.id}</TableCell>
                    <TableCell>{p.status ?? '-'}</TableCell>
                    <TableCell>
                      <Button
                        size="sm"
                        variant="outline"
                        aria-label={`Manage port ${p.config?.name || p.id}`}
                        onClick={() => setSelectedPort(p.id)}
                      >
                        Manage
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
          <div className="mt-2">
            <Button size="sm" variant="ghost" onClick={refetchPorts}>Reload ports</Button>
          </div>
        </CardContent>
      </Card>

      {selectedPort && (
        <Card data-testid="port-panel">
          <CardHeader>
            <CardTitle>Port {selectedPort}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {portError && (
              <p role="alert" data-testid="port-error" className="text-destructive">
                Port could not be loaded: {portError}
              </p>
            )}
            <div className="grid gap-2 md:grid-cols-2" data-testid="port-state">
              <div>Status: <span className="font-mono">{port?.status ?? '-'}</span></div>
              <div>
                Authenticated:{' '}
                <span className="font-mono">{port?.auth?.authenticated ? 'yes' : 'no'}</span>
              </div>
            </div>
            <div className="grid gap-2 md:grid-cols-3" data-testid="port-stats">
              <div>Packets received: {stats?.packetsReceived ?? '-'}</div>
              <div>Packets sent: {stats?.packetsSent ?? '-'}</div>
              <div>Bytes received: {stats?.bytesReceived ?? '-'}</div>
              <div>Bytes sent: {stats?.bytesSent ?? '-'}</div>
              <div>Errors: {stats?.errors ?? '-'}</div>
              <div>Dropped: {stats?.dropped ?? '-'}</div>
            </div>

            <div className="flex items-end gap-2">
              <div className="space-y-1">
                <Label htmlFor="port-admin-state">Admin state</Label>
                <select
                  id="port-admin-state"
                  className="h-9 rounded-md border border-input bg-background px-2"
                  value={adminState}
                  onChange={(e) => setAdminState(e.target.value)}
                >
                  <option value="up">up</option>
                  <option value="down">down</option>
                </select>
              </div>
              <Button
                onClick={() =>
                  run(
                    'Port state updated',
                    () => sdn.setPortState({ bridgeId, portId: selectedPort, adminState }),
                    refreshPort
                  )
                }
              >
                Set State
              </Button>
            </div>

            <div className="space-y-1">
              <Label htmlFor="port-certificate">Certificate (PEM)</Label>
              <Textarea
                id="port-certificate"
                value={certificate}
                onChange={(e) => setCertificate(e.target.value)}
                rows={3}
              />
              <div className="flex gap-2">
                <Button
                  disabled={!certificate}
                  onClick={() =>
                    run(
                      'Port authenticated',
                      () =>
                        sdn.authenticatePort({
                          bridgeId,
                          portId: selectedPort,
                          certificate: pemToBase64(certificate),
                          format: 'PEM',
                        }),
                      refreshPort
                    )
                  }
                >
                  Authenticate Port
                </Button>
                <Button variant="destructive" onClick={() => setConfirmRevoke(true)}>
                  Revoke Auth
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <Dialog open={confirmRevoke} onOpenChange={setConfirmRevoke}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke authentication of port {selectedPort}?</DialogTitle>
            <DialogDescription>The port loses its authorized VLANs until it authenticates again.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmRevoke(false)}>Cancel</Button>
            <Button
              variant="destructive"
              onClick={() =>
                run('Port authentication revoked', () => sdn.revokePortAuth(bridgeId, selectedPort), () => {
                  setConfirmRevoke(false);
                  refreshPort();
                })
              }
            >
              Confirm Revoke
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Policies</CardTitle>
          <Button size="sm" onClick={() => setApplyOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Apply Policy
          </Button>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {policiesError ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-center">
                    <span role="alert" data-testid="sdn-policies-error" className="text-destructive">
                      Policies could not be loaded: {policiesError}
                    </span>{' '}
                    <Button size="sm" variant="outline" aria-label="Retry policies" onClick={refetchPolicies}>
                      Retry
                    </Button>
                  </TableCell>
                </TableRow>
              ) : policies.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-muted-foreground">
                    No policies found
                  </TableCell>
                </TableRow>
              ) : (
                policies.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell className="font-medium">{p.config?.name || p.id}</TableCell>
                    <TableCell>{p.config?.type ?? '-'}</TableCell>
                    <TableCell>{p.status ?? '-'}</TableCell>
                    <TableCell>
                      <Button
                        size="sm"
                        variant="outline"
                        aria-label={`View policy ${p.config?.name || p.id}`}
                        onClick={() => setViewPolicyId(p.id)}
                      >
                        View
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={!!viewPolicyId} onOpenChange={(open) => !open && setViewPolicyId('')}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Policy {policy?.config?.name || viewPolicyId}</DialogTitle>
            <DialogDescription>{policy?.config?.description || 'SDN policy detail'}</DialogDescription>
          </DialogHeader>
          <div className="space-y-1" data-testid="policy-detail">
            <div>ID: <span className="font-mono">{policy?.id ?? viewPolicyId}</span></div>
            <div>Type: {policy?.config?.type ?? '-'}</div>
            <div>Status: {policy?.status ?? '-'}</div>
            <div>Rules: {policy?.config?.rules?.length ?? 0}</div>
            <div>Hits: {policy?.hitCount ?? '0'}</div>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={applyOpen} onOpenChange={setApplyOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Apply Policy</DialogTitle>
            <DialogDescription>Create or replace an SDN policy.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1">
              <Label htmlFor="policy-name">Name *</Label>
              <Input id="policy-name" value={policyName} onChange={(e) => setPolicyName(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="policy-type">Type</Label>
              <select
                id="policy-type"
                className="h-9 w-full rounded-md border border-input bg-background px-2"
                value={policyType}
                onChange={(e) => setPolicyType(e.target.value as SDNPolicyType)}
              >
                {POLICY_TYPES.map((t) => (
                  <option key={t} value={t}>{t.replace('POLICY_TYPE_', '')}</option>
                ))}
              </select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setApplyOpen(false)}>Cancel</Button>
            <Button
              disabled={!policyName}
              onClick={() =>
                run(
                  'Policy applied',
                  () => sdn.applyPolicy({ config: { name: policyName, type: policyType, enabled: true } }),
                  () => {
                    setApplyOpen(false);
                    setPolicyName('');
                    refetchPolicies();
                  }
                )
              }
            >
              Apply
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
