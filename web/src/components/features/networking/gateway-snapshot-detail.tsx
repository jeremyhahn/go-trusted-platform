'use client';

import * as React from 'react';
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
import type { GatewaySnapshot } from 'trusted-platform-sdk';

/**
 * Renders one gateway's datapath: what its services actually programmed,
 * from the telemetry snapshot the control plane holds (#594).
 *
 * A section a gateway does not run is absent from the snapshot, and this
 * component renders nothing for it — an operator must never read an empty
 * table as "running with nothing configured".
 */
export interface GatewaySnapshotDetailProps {
  snapshot: GatewaySnapshot;
}

/** Formats a byte count for the tunnel counters. */
function formatBytes(bytes?: number): string {
  if (!bytes) {
    return '0';
  }
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

/** Green for the good state, red otherwise — one place, one rule. */
function stateBadgeClass(good: boolean): string {
  return good
    ? 'bg-green-500/10 text-green-600 border-green-500/20'
    : 'bg-red-500/10 text-red-600 border-red-500/20';
}

export function GatewaySnapshotDetail({ snapshot }: GatewaySnapshotDetailProps) {
  const services = snapshot.services ?? [];
  const peers = snapshot.bgp?.peers ?? [];
  const tunnels = snapshot.tunnels ?? [];
  const uplinks = snapshot.uplinks ?? [];

  return (
    <div className="space-y-6" data-testid="gateway-snapshot-detail">
      <Card>
        <CardHeader>
          <CardTitle>Datapath — {snapshot.gateway_id}</CardTitle>
          <CardDescription>
            What this gateway&apos;s services programmed, as each service
            reports it. A section a gateway does not run is not shown.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {services.length > 0 && (
            <section>
              <h3 className="text-sm font-medium mb-2">Services</h3>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Service</TableHead>
                    <TableHead>Active</TableHead>
                    <TableHead>Healthy</TableHead>
                    <TableHead>Refused because</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {services.map((service) => (
                    <TableRow key={service.name}>
                      <TableCell className="font-mono text-xs">{service.name}</TableCell>
                      <TableCell>{service.active ? 'yes' : 'no'}</TableCell>
                      <TableCell>
                        <Badge className={stateBadgeClass(service.healthy)}>
                          {service.healthy ? 'healthy' : 'unhealthy'}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {service.refused_reason ?? '—'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </section>
          )}

          {peers.length > 0 && (
            <section>
              <h3 className="text-sm font-medium mb-2">
                BGP sessions — AS {snapshot.bgp?.local_asn ?? '—'}, router-id{' '}
                {snapshot.bgp?.router_id ?? '—'}
              </h3>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Neighbour</TableHead>
                    <TableHead>ASN</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Received</TableHead>
                    <TableHead>Accepted</TableHead>
                    <TableHead>Sent</TableHead>
                    <TableHead>BFD</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {peers.map((peer) => (
                    <TableRow key={peer.address}>
                      <TableCell className="font-mono text-xs">{peer.address}</TableCell>
                      <TableCell>{peer.asn ?? '—'}</TableCell>
                      <TableCell>
                        <Badge className={stateBadgeClass(peer.state === 'Established')}>
                          {peer.state}
                        </Badge>
                      </TableCell>
                      <TableCell>{peer.prefixes_received}</TableCell>
                      <TableCell>{peer.prefixes_accepted}</TableCell>
                      <TableCell>{peer.prefixes_sent}</TableCell>
                      <TableCell className="text-xs">
                        {peer.bfd ? (
                          <Badge className={stateBadgeClass(peer.bfd.state === 'up')}>
                            {peer.bfd.state}
                            {peer.bfd.failure_transitions
                              ? ` · ${peer.bfd.failure_transitions} failures`
                              : ''}
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground">not configured</span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </section>
          )}

          {tunnels.length > 0 && (
            <section>
              <h3 className="text-sm font-medium mb-2">Tunnels</h3>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Transport</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Uplink</TableHead>
                    <TableHead>Endpoints</TableHead>
                    <TableHead>Rx / Tx</TableHead>
                    <TableHead>Last rekey</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {tunnels.map((tunnel) => (
                    <TableRow key={tunnel.name}>
                      <TableCell className="font-mono text-xs">{tunnel.name}</TableCell>
                      <TableCell>{tunnel.transport ?? '—'}</TableCell>
                      <TableCell>
                        <Badge className={stateBadgeClass(tunnel.state === 'up')}>
                          {tunnel.state}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs">
                        {tunnel.uplink ? `${tunnel.uplink}${tunnel.bound ? ' (pinned)' : ''}` : '—'}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {tunnel.local_ip ?? '—'} → {tunnel.remote_ip ?? '—'}
                      </TableCell>
                      <TableCell className="text-xs">
                        {formatBytes(tunnel.rx_bytes)} / {formatBytes(tunnel.tx_bytes)}
                      </TableCell>
                      <TableCell className="text-xs">
                        {tunnel.last_rekey
                          ? new Date(tunnel.last_rekey).toLocaleString()
                          : '—'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </section>
          )}

          {uplinks.length > 0 && (
            <section>
              <h3 className="text-sm font-medium mb-2">Uplink policy routes</h3>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Uplink</TableHead>
                    <TableHead>Interface</TableHead>
                    <TableHead>Table</TableHead>
                    <TableHead>Next hop</TableHead>
                    <TableHead>Rules</TableHead>
                    <TableHead>Pinned tunnels</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {uplinks.map((uplink) => (
                    <TableRow key={uplink.name}>
                      <TableCell className="font-mono text-xs">{uplink.name}</TableCell>
                      <TableCell>{uplink.interface ?? '—'}</TableCell>
                      <TableCell>{uplink.table}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {uplink.gateway_v4 ?? uplink.gateway_v6 ?? '—'}
                      </TableCell>
                      <TableCell>{uplink.rule_count}</TableCell>
                      <TableCell className="text-xs">
                        {uplink.tunnels?.join(', ') || '—'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </section>
          )}

          <section className="grid gap-4 md:grid-cols-2">
            {snapshot.host_firewall && (
              <div className="rounded-lg border border-border p-4">
                <div className="text-sm font-medium mb-2">Host filter (nftables)</div>
                <dl className="text-xs space-y-1">
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">Installed</dt>
                    <dd>{snapshot.host_firewall.installed ? 'yes' : 'no'}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">Rules</dt>
                    <dd>{snapshot.host_firewall.rule_count}</dd>
                  </div>
                  <div className="flex justify-between gap-4">
                    <dt className="text-muted-foreground">Fingerprint</dt>
                    <dd className="font-mono truncate">
                      {snapshot.host_firewall.fingerprint ?? '—'}
                    </dd>
                  </div>
                  {snapshot.host_firewall.last_error && (
                    <div className="text-destructive">
                      Last error: {snapshot.host_firewall.last_error}
                    </div>
                  )}
                </dl>
              </div>
            )}

            {snapshot.firewall && (
              <div className="rounded-lg border border-border p-4">
                <div className="text-sm font-medium mb-2">Firewall (OVS conntrack)</div>
                <dl className="text-xs space-y-1">
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">Active</dt>
                    <dd>{snapshot.firewall.active ? 'yes' : 'no'}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">Flows</dt>
                    <dd>{snapshot.firewall.flow_count}</dd>
                  </div>
                </dl>
              </div>
            )}

            {snapshot.nat && (
              <div className="rounded-lg border border-border p-4">
                <div className="text-sm font-medium mb-2">NAT</div>
                <dl className="text-xs space-y-1">
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">SNAT</dt>
                    <dd>{snapshot.nat.snat_enabled ? 'enabled' : 'disabled'}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">DNAT bindings</dt>
                    <dd>{snapshot.nat.dnat_rules}</dd>
                  </div>
                  {snapshot.nat.uplinks?.map((uplink) => (
                    <div key={uplink.name} className="flex justify-between">
                      <dt className="text-muted-foreground">
                        {uplink.name}
                        {uplink.default ? ' (default)' : ''}
                      </dt>
                      <dd>
                        {uplink.pool_addresses} addresses × {uplink.ports} ports
                      </dd>
                    </div>
                  ))}
                </dl>
              </div>
            )}

            {snapshot.pipeline && (
              <div className="rounded-lg border border-border p-4">
                <div className="text-sm font-medium mb-2">Base pipeline</div>
                <dl className="text-xs space-y-1">
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">Bridge</dt>
                    <dd className="font-mono">{snapshot.pipeline.bridge ?? '—'}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">Owner</dt>
                    <dd className="font-mono">{snapshot.pipeline.owner ?? '—'}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">Terminal</dt>
                    <dd>{snapshot.pipeline.terminal ?? '—'}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">Fail mode</dt>
                    <dd>{snapshot.pipeline.fail_mode ?? '—'}</dd>
                  </div>
                </dl>
              </div>
            )}
          </section>
        </CardContent>
      </Card>
    </div>
  );
}
