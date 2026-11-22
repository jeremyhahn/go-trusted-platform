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
import { Alert, AlertDescription } from '@/components/ui/alert';
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
import { useSDN, useSDNBridge, useToast } from '@/hooks';
import type {
  Port,
  PortStats,
  SDNPolicy,
  SDNPolicyRuleAction,
  SDNPolicyRuleMatch,
  SDNPolicyType,
} from 'trusted-platform-sdk';

interface PortView {
  id: string;
  /** The refresh count the answer belongs to. */
  reload: number;
  port?: Port;
  stats?: PortStats;
  error?: string;
}

// The policy dialog keeps each answer with the policy it was asked for (#1755).
interface PolicyView {
  id: string;
  policy?: SDNPolicy;
  error?: string;
}

// RATE_LIMIT and MIRROR are left out: SDNService.policyRuleToFlowMod installs "normal" for both (#2024 Codex P1).
// REDIRECT is left out too: the form has no output destination, and a REDIRECT rule
// without actionValue installs no actions, which drops the traffic (#2024 Codex round 2 P1).
// LOG is left out: policyRuleToFlowMod installs "controller" only, with no normal forwarding, so a LOG rule drops the traffic (#2148 Codex round 2 P1).
const RULE_ACTIONS: SDNPolicyRuleAction[] = [
  'POLICY_RULE_ACTION_ALLOW',
  'POLICY_RULE_ACTION_DENY',
];

const RULE_PROTOCOLS = ['any', 'tcp', 'udp', 'icmp'];

// ApplyPolicy installs flows only for bridge targets times config.rules
// (SDNService.ApplyPolicy), so the form always sends one rule bound to this bridge.
function ruleMatch(protocol: string, sourceIp: string, destinationIp: string, destinationPort: string) {
  const match: SDNPolicyRuleMatch = {};
  if (protocol && protocol !== 'any') match.protocol = protocol;
  if (sourceIp.trim()) match.sourceIp = sourceIp.trim();
  if (destinationIp.trim()) match.destinationIp = destinationIp.trim();
  if (destinationPort.trim()) match.destinationPort = Number(destinationPort);
  return match;
}

// The protocol as the daemon maps it to nw_proto: names are case-blind and a
// protocol number is the same match as its name (#2148 Codex).
const PROTOCOL_NUMBERS: Record<string, string> = { '6': 'tcp', '17': 'udp', '1': 'icmp', '132': 'sctp' };
function canonicalProtocol(v: string) {
  const p = v.trim().toLowerCase();
  if (PROTOCOL_NUMBERS[p]) return PROTOCOL_NUMBERS[p];
  if (/^\d+$/.test(p) && Number(p) <= 255) {
    const n = String(Number(p));
    return PROTOCOL_NUMBERS[n] ?? n;
  }
  return p;
}

// An IPv4 match as pkg/sdn/ovs/flow.go installs it: a bare address is an
// exact /32 match and a CIDR is masked to its network, as net.ParseCIDR does.
// Anything else is returned trimmed.
function canonicalIPv4(v: string) {
  const t = v.trim();
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(t);
  if (!m) return t;
  const octets = m.slice(1, 5).map(Number);
  if (octets.some((o) => o > 255)) return t;
  const bits = m[5] === undefined ? 32 : Number(m[5]);
  if (bits > 32) return t;
  const addr = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const net = (addr & mask) >>> 0;
  return `${[net >>> 24, (net >>> 16) & 255, (net >>> 8) & 255, net & 255].join('.')}/${bits}`;
}

// The match fields SDNService.policyRuleMatch (pkg/api/daemon/sdn_service.go)
// installs in the flow; it ignores every other field of the rule match.
const INSTALLED_MATCH_FIELDS: ReadonlySet<string> = new Set([
  'protocol',
  'sourceIp',
  'destinationIp',
  'sourcePort',
  'destinationPort',
  'vlanId',
]);

// A match in a form two equal matches share: unset and empty fields dropped,
// keys sorted, so key order or a blank field never hides an equal match.
// Protocol aliases and IPv4 addresses compare as OpenFlow installs them: the
// switch masks a CIDR to its network and a bare address is /32 (#2148 Codex).
// Fields the switch never installs (direction, interface, dscp, application)
// are dropped, since two matches that differ only there install the same flow
// (#2148 Codex round 2).
function matchKey(match: SDNPolicyRuleMatch | undefined) {
  const entries = Object.entries(match ?? {})
    .filter(([k]) => INSTALLED_MATCH_FIELDS.has(k))
    .map(([k, v]) => {
      if (typeof v !== 'string') return [k, v] as const;
      if (k === 'protocol') return [k, canonicalProtocol(v)] as const;
      if (k === 'sourceIp' || k === 'destinationIp') return [k, canonicalIPv4(v)] as const;
      return [k, v.trim()] as const;
    })
    .filter(([, v]) => v !== undefined && v !== null && v !== '' && v !== 0)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return JSON.stringify(entries);
}

// The priority the switch holds: flow.go installs uint16(flow.Priority).
function installedPriority(p: number) {
  return ((p % 65536) + 65536) % 65536;
}

// The priority the daemon installs a recorded rule at. Mirrors the daemon's
// policyRuleToFlowMod: a rule priority 0 installs at the policy's priority.
function effectiveRulePriority(rule: { priority?: number }, config: { priority?: number }) {
  return rule.priority ? rule.priority : (config.priority ?? 0);
}

// OpenFlow OFPFCAdd replaces a flow with the same match and priority, so a
// differently named policy on the same bridge with such a rule would take
// over that policy's flow while both stay ACTIVE (#2024 Codex, P1). Returns
// the policy the new rule would displace, if any. A policy with no targets is
// counted as on this bridge: the page lists it here. A recorded rule is
// compared at the priority the daemon installs it at (rule priority 0 means
// the policy priority), and a bridge target matches any of this bridge's
// identities, id or name, as the daemon's findBridgeName resolves both
// (#2024 Codex R13).
function conflictingPolicy(
  policies: SDNPolicy[],
  bridgeIds: string[],
  name: string,
  priority: number,
  match: SDNPolicyRuleMatch
): SDNPolicy | undefined {
  const key = matchKey(match);
  return policies.find((p) => {
    const config = p.config;
    if (!config || config.name === name) return false;
    const targets = config.targets ?? [];
    const onBridge =
      targets.length === 0 || targets.some((t) => t.type === 'POLICY_TARGET_TYPE_BRIDGE' && bridgeIds.includes(t.id ?? ''));
    if (!onBridge) return false;
    return (config.rules ?? []).some(
      (r) =>
        installedPriority(effectiveRulePriority(r, config)) === installedPriority(priority) &&
        matchKey(r.match) === key
    );
  });
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
    policiesLoaded,
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
  const [ruleAction, setRuleAction] = useState<SDNPolicyRuleAction | ''>('');
  const [rulePriority, setRulePriority] = useState('100');
  const [ruleProtocol, setRuleProtocol] = useState('any');
  const [ruleSourceIp, setRuleSourceIp] = useState('');
  const [ruleDestinationIp, setRuleDestinationIp] = useState('');
  const [ruleDestinationPort, setRuleDestinationPort] = useState('');

  // The port panel keeps each answer with the port it was asked for, and
  // drops an answer that arrives after the selection moved on (#1755).
  const [portView, setPortView] = useState<PortView | null>(null);
  const [portReload, setPortReload] = useState(0);
  // The view is shown only for the port and refresh it answers, so a change
  // needs no reset here.
  useEffect(() => {
    if (!selectedPort) return;
    let current = true;
    const id = selectedPort;
    const reload = portReload;
    (async () => {
      try {
        const [state, stats] = await Promise.all([sdn.getPort(bridgeId, id), sdn.getPortStats(bridgeId, id)]);
        if (!current) return;
        setPortView({
          id,
          reload,
          port: state.data?.port,
          stats: stats.data?.stats,
          error: state.error?.message ?? stats.error?.message,
        });
      } catch (err) {
        if (current) setPortView({ id, reload, error: errorText(err) });
      }
    })();
    return () => {
      current = false;
    };
  }, [sdn, bridgeId, selectedPort, portReload]);
  // Same identity rule for the policy dialog: a failure or a late answer for
  // another policy is never shown as this policy's data (#1755 Codex round 4).
  const [policyView, setPolicyView] = useState<PolicyView | null>(null);
  useEffect(() => {
    if (!viewPolicyId) return;
    let current = true;
    const id = viewPolicyId;
    (async () => {
      try {
        const res = await sdn.getPolicy(id);
        if (!current) return;
        if (!res.success) {
          setPolicyView({ id, error: res.error?.message ?? 'Request failed' });
          return;
        }
        setPolicyView({ id, policy: res.data?.policy });
      } catch (err) {
        if (current) setPolicyView({ id, error: errorText(err) });
      }
    })();
    return () => {
      current = false;
    };
  }, [sdn, viewPolicyId]);

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

  const shown = portView?.id === selectedPort && portView.reload === portReload ? portView : null;
  const port = shown?.port;
  const stats = shown?.stats;
  const portError = shown?.error;
  const policyShown = policyView?.id === viewPolicyId ? policyView : null;
  const policy: SDNPolicy | undefined = policyShown?.policy;
  const resetRule = () => {
    setRuleAction('');
    setRulePriority('100');
    setRuleProtocol('any');
    setRuleSourceIp('');
    setRuleDestinationIp('');
    setRuleDestinationPort('');
  };
  // The daemon compares policy names exactly (SDNService.ApplyPolicy).
  const existingPolicy: SDNPolicy | undefined = policyName
    ? policies.find((p) => p.config?.name === policyName)
    : undefined;
  const applyPolicy = () => {
    const priority = rulePriorityValue;
    // SDNService.ApplyPolicy refuses an existing name without its ID
    // (AlreadyExists), so a replacement carries the policy's ID and keeps
    // the bridges it already targets (#2148 Codex, P1).
    const ownTarget = { type: 'POLICY_TARGET_TYPE_BRIDGE' as const, id: bridgeId };
    let targets: NonNullable<NonNullable<SDNPolicy['config']>['targets']> = [ownTarget];
    if (existingPolicy) {
      const names = [bridgeId, bridge?.id, bridge?.config?.name].filter((v): v is string => !!v);
      const kept = (existingPolicy.config?.targets ?? []).filter((t) => t.type === 'POLICY_TARGET_TYPE_BRIDGE');
      targets = kept.some((t) => !!t.id && names.includes(t.id)) ? kept : [...kept, ownTarget];
    }
    return sdn.applyPolicy({
      ...(existingPolicy?.id ? { policyId: existingPolicy.id } : {}),
      config: {
        name: policyName,
        type: policyType,
        enabled: true,
        priority,
        rules: [
          {
            ruleId: 'rule-1',
            priority,
            action: ruleAction as SDNPolicyRuleAction,
            match: ruleMatch(ruleProtocol, ruleSourceIp, ruleDestinationIp, ruleDestinationPort),
          },
        ],
        targets,
      },
    });
  };
  const refreshPort = () => setPortReload((n) => n + 1);
  // OpenFlow matches a destination port only under tcp or udp; the switch
  // rejects a port match with any or icmp (#2024 Codex round 4, P1).
  const portNeedsTransport = (protocol: string) => protocol === 'tcp' || protocol === 'udp';
  // The backend reads destinationPort 0 as "no port match", so an explicit 0
  // would cover every port: only 1-65535 is accepted (#2024 Codex round 5, P1).
  // flow.go installs uint16(flow.Priority), so a priority outside 1-65535
  // would install at another value than the guard compares (#2148 Codex).
  const priorityText = rulePriority.trim();
  const rulePriorityValue = Number(priorityText);
  const rulePriorityError =
    /^\d+$/.test(priorityText) && rulePriorityValue >= 1 && rulePriorityValue <= 65535
      ? ''
      : 'Rule rule-1: the priority must be a whole number between 1 and 65535';
  const portText = ruleDestinationPort.trim();
  const portValue = Number(portText);
  const rulePortError = !portText
    ? ''
    : !portNeedsTransport(ruleProtocol)
      ? 'Rule rule-1: a destination port needs protocol tcp or udp'
      : !Number.isInteger(portValue) || portValue < 1 || portValue > 65535
        ? 'Rule rule-1: the destination port must be between 1 and 65535'
        : '';
  // A policy is applied only to a bridge this page loaded: an unresolved URL
  // ID would target nothing (#2024 Codex round 5, P1).
  const bridgeLoaded = !!bridge && !bridgeError;
  const conflict = policyName
    ? conflictingPolicy(
        policies,
        [bridgeId, bridge?.id, bridge?.config?.name].filter((v): v is string => !!v),
        policyName,
        rulePriorityValue,
        ruleMatch(ruleProtocol, ruleSourceIp, ruleDestinationIp, ruleDestinationPort)
      )
    : undefined;
  const policyConflictError = conflict
    ? `Policy ${conflict.config?.name || conflict.id} already matches this traffic at priority ${rulePriorityValue} on this bridge: a second policy would replace its flow. Change the match or the priority, or edit that policy.`
    : '';
  const changeRuleProtocol = (protocol: string) => {
    setRuleProtocol(protocol);
    if (!portNeedsTransport(protocol)) setRuleDestinationPort('');
  };

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
          <Button
            size="sm"
            disabled={!bridgeLoaded}
            title={bridgeLoaded ? undefined : 'The bridge must load before a policy can be applied'}
            onClick={() => setApplyOpen(true)}
          >
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
          {!policyShown ? (
            <p className="text-muted-foreground" data-testid="policy-detail-loading">Loading policy...</p>
          ) : policyShown.error ? (
            <Alert variant="destructive" data-testid="policy-detail-error">
              <AlertDescription>Policy could not be loaded: {policyShown.error}</AlertDescription>
            </Alert>
          ) : (
            <div className="space-y-1" data-testid="policy-detail">
              <div>ID: <span className="font-mono">{policy?.id ?? viewPolicyId}</span></div>
              <div>Type: {policy?.config?.type ?? '-'}</div>
              <div>Status: {policy?.status ?? '-'}</div>
              <div>Rules: {policy?.config?.rules?.length ?? 0}</div>
              <div>Hits: {policy?.hitCount ?? '0'}</div>
            </div>
          )}
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
              {existingPolicy && (
                <p data-testid="policy-replace-note" className="text-sm text-muted-foreground">
                  Replaces policy {existingPolicy.config?.name}
                </p>
              )}
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
            <p className="text-sm text-muted-foreground">
              Rule applied to bridge <span className="font-mono">{bridgeId}</span>
            </p>
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-1">
                <Label htmlFor="rule-action">Action *</Label>
                <select
                  id="rule-action"
                  className="h-9 w-full rounded-md border border-input bg-background px-2"
                  value={ruleAction}
                  onChange={(e) => setRuleAction(e.target.value as SDNPolicyRuleAction | '')}
                >
                  <option value="">Select action</option>
                  {RULE_ACTIONS.map((a) => (
                    <option key={a} value={a}>{a.replace('POLICY_RULE_ACTION_', '')}</option>
                  ))}
                </select>
              </div>
              <div className="space-y-1">
                <Label htmlFor="rule-priority">Priority</Label>
                <Input
                  id="rule-priority"
                  type="number"
                  min={1}
                  max={65535}
                  step={1}
                  value={rulePriority}
                  onChange={(e) => setRulePriority(e.target.value)}
                  aria-invalid={rulePriorityError ? true : undefined}
                  aria-describedby={rulePriorityError ? 'rule-priority-error' : undefined}
                />
                {rulePriorityError && (
                  <p
                    id="rule-priority-error"
                    role="alert"
                    data-testid="rule-priority-error"
                    className="text-sm text-destructive"
                  >
                    {rulePriorityError}
                  </p>
                )}
              </div>
              <div className="space-y-1">
                <Label htmlFor="rule-protocol">Protocol</Label>
                <select
                  id="rule-protocol"
                  className="h-9 w-full rounded-md border border-input bg-background px-2"
                  value={ruleProtocol}
                  onChange={(e) => changeRuleProtocol(e.target.value)}
                >
                  {RULE_PROTOCOLS.map((p) => (
                    <option key={p} value={p}>{p}</option>
                  ))}
                </select>
              </div>
              <div className="space-y-1">
                <Label htmlFor="rule-destination-port">Destination port</Label>
                <Input
                  id="rule-destination-port"
                  type="number"
                  min={1}
                  max={65535}
                  value={ruleDestinationPort}
                  onChange={(e) => setRuleDestinationPort(e.target.value)}
                  aria-invalid={rulePortError ? true : undefined}
                  aria-describedby={rulePortError ? 'rule-port-error' : undefined}
                />
                {rulePortError && (
                  <p id="rule-port-error" role="alert" data-testid="rule-port-error" className="text-sm text-destructive">
                    {rulePortError}
                  </p>
                )}
              </div>
              <div className="space-y-1">
                <Label htmlFor="rule-source-ip">Source IP</Label>
                <Input id="rule-source-ip" value={ruleSourceIp} onChange={(e) => setRuleSourceIp(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="rule-destination-ip">Destination IP</Label>
                <Input
                  id="rule-destination-ip"
                  value={ruleDestinationIp}
                  onChange={(e) => setRuleDestinationIp(e.target.value)}
                />
              </div>
            </div>
          </div>
          {policyConflictError && (
            <p role="alert" data-testid="policy-conflict-error" className="text-sm text-destructive">
              {policyConflictError}
            </p>
          )}
          {!policiesLoaded && (
            // #2024 Codex: an unloaded policy list is not "no conflict": a policy
            // sharing another's match and priority would replace its flow.
            <p role="alert" data-testid="policy-list-not-loaded" className="text-sm text-destructive">
              {policiesError
                ? 'The policy list could not be loaded, so a conflicting policy cannot be ruled out. Retry the policy list before applying.'
                : 'Waiting for the policy list to load before a policy can be applied.'}
            </p>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setApplyOpen(false)}>Cancel</Button>
            <Button
              disabled={
                !bridgeLoaded ||
                !policiesLoaded ||
                !policyName ||
                !ruleAction ||
                !!rulePortError ||
                !!rulePriorityError ||
                !!policyConflictError
              }
              onClick={() =>
                bridgeLoaded &&
                policiesLoaded &&
                !rulePortError &&
                !rulePriorityError &&
                !policyConflictError &&
                run(
                  'Policy applied',
                  applyPolicy,
                  () => {
                    setApplyOpen(false);
                    setPolicyName('');
                    resetRule();
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
