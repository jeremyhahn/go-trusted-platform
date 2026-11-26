'use client';

/**
 * GatewayVIPsCard — the gateway's load-balancer VIPs (#2052).
 *
 * Lists the VIPs (GET /api/v1/gateway/lb/vips) with their backend health and,
 * for an admin, adds a VIP (POST /lb/vips), replaces its backend set
 * (PUT /lb/vips/{protocol}/{address}/{port}/backends) and removes it after a
 * confirm (DELETE /lb/vips/{protocol}/{address}/{port}). Every write
 * reprograms the gateway's switch, so a non-admin sees the controls disabled
 * with the reason and sends nothing. Each write is also gated on the server's
 * capability for its route (<Gated>): an op the server does not offer leaves
 * its control disabled with the server's reason. The SDK sends each write once, never
 * retried. A successful write re-reads the list once; a refused one shows the
 * server's message. The mount read and every re-read share one generation: a
 * newer list read supersedes an older one, so a slow first read never restores
 * the list a write has already replaced.
 *
 * Each row's Details button reads that VIP through GetVIP
 * (GET /lb/vips/{protocol}/{address}/{port}) and shows its conntrack zone,
 * select group and per-backend health in the row; a refused read shows the
 * server's message there. It is a read, open to every role, and gated on its
 * route like the writes.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { Network } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { useGateway, useOptionalAuth } from '@/hooks';
import type { VIPBackend, VIPStatus } from 'trusted-platform-sdk';
import { Gated } from '@/components/features/capabilities/gated';

const BACKEND_LINE = /^(\S+):(\d+)(?:\s+(\d+))?$/;

// The server's op strings for the writes (routes.golden).
const ADD_OP = 'POST /api/v1/gateway/lb/vips';
const BACKENDS_OP = 'PUT /api/v1/gateway/lb/vips/{protocol}/{address}/{port}/backends';
const REMOVE_OP = 'DELETE /api/v1/gateway/lb/vips/{protocol}/{address}/{port}';
const GET_OP = 'GET /api/v1/gateway/lb/vips/{protocol}/{address}/{port}';

/**
 * Parse one backend per line as `address:port [weight]` (weight defaults to
 * 0, which the server treats as 1). Blank lines are skipped. Returns the
 * backends, or a message naming the first bad line.
 */
export function parseBackends(text: string): VIPBackend[] | string {
  const backends: VIPBackend[] = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === '') {
      continue;
    }
    const m = BACKEND_LINE.exec(line);
    const port = m ? Number(m[2]) : 0;
    if (!m || port < 1 || port > 65535) {
      return `Line ${i + 1}: expected address:port [weight]`;
    }
    backends.push({ address: m[1], port, weight: m[3] ? Number(m[3]) : 0 });
  }
  return backends;
}

function formatBackends(backends: VIPBackend[]): string {
  return backends.map((b) => `${b.address}:${b.port}${b.weight ? ` ${b.weight}` : ''}`).join('\n');
}

function keyOf(vip: VIPStatus): string {
  return `${vip.vip?.protocol ?? ''}-${vip.vip?.address ?? ''}-${vip.vip?.port ?? 0}`;
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function GatewayVIPsCard() {
  const gateway = useGateway();
  const auth = useOptionalAuth();
  const isAdmin = auth?.user?.roles.includes('admin') ?? false;

  const [vips, setVIPs] = useState<VIPStatus[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [protocol, setProtocol] = useState('tcp');
  const [address, setAddress] = useState('');
  const [port, setPort] = useState('');
  const [backendsText, setBackendsText] = useState('');
  const [formError, setFormError] = useState<string | null>(null);

  const [editKey, setEditKey] = useState<string | null>(null);
  const [editText, setEditText] = useState('');
  const [removing, setRemoving] = useState<VIPStatus | null>(null);
  const [detail, setDetail] = useState<{ key: string; vip: VIPStatus | null; error: string | null } | null>(null);
  const [detailBusy, setDetailBusy] = useState(false);
  // Each list read takes the next generation; only the newest one applies.
  const generation = useRef(0);
  const mounted = useRef(true);

  // Reads the list without touching state, so the mount effect and the
  // post-write re-read share it.
  const readList = useCallback(async (): Promise<{ vips: VIPStatus[] } | { error: string }> => {
    try {
      const res = await gateway.listVIPs();
      if (res.error) {
        return { error: res.error.message || 'The gateway did not list its VIPs' };
      }
      return { vips: res.data?.vips ?? [] };
    } catch (err) {
      return { error: errorText(err) };
    }
  }, [gateway]);

  const applyList = useCallback((list: { vips: VIPStatus[] } | { error: string }) => {
    if ('error' in list) {
      setError(list.error);
    } else {
      setVIPs(list.vips);
    }
    setLoaded(true);
  }, []);

  const load = useCallback(async () => {
    const gen = ++generation.current;
    const list = await readList();
    if (mounted.current && gen === generation.current) {
      applyList(list);
    }
  }, [readList, applyList]);

  useEffect(() => {
    mounted.current = true;
    void load();
    return () => {
      mounted.current = false;
    };
  }, [load]);

  // Runs one write; on success re-reads the list once.
  const write = async (send: () => Promise<{ error?: { message?: string } | null }>): Promise<boolean> => {
    if (!isAdmin) {
      return false;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await send();
      if (res.error) {
        setError(res.error.message || 'The gateway refused the change');
        return false;
      }
      await load();
      return true;
    } catch (err) {
      setError(errorText(err));
      return false;
    } finally {
      setBusy(false);
    }
  };

  const handleAdd = async () => {
    const backends = parseBackends(backendsText);
    if (typeof backends === 'string') {
      setFormError(backends);
      return;
    }
    const portNum = Number(port);
    if (address.trim() === '' || !Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      setFormError('Enter an address and a port from 1 to 65535');
      return;
    }
    setFormError(null);
    const ok = await write(() =>
      gateway.addVIP({ protocol, address: address.trim(), port: portNum, algorithm: '', backends })
    );
    if (ok) {
      setAddress('');
      setPort('');
      setBackendsText('');
    }
  };

  const handleSave = async (vip: VIPStatus) => {
    const backends = parseBackends(editText);
    if (typeof backends === 'string') {
      setError(backends);
      return;
    }
    const cfg = vip.vip;
    if (!cfg) {
      return;
    }
    const ok = await write(() => gateway.setVIPBackends(cfg.protocol, cfg.address, cfg.port, backends));
    if (ok) {
      setEditKey(null);
    }
  };

  const handleRemove = async () => {
    const cfg = removing?.vip;
    setRemoving(null);
    if (!cfg) {
      return;
    }
    await write(() => gateway.removeVIP(cfg.protocol, cfg.address, cfg.port));
  };

  // Reads one VIP through GetVIP. A read: open to every role, no list re-read.
  const handleDetails = async (vip: VIPStatus) => {
    const cfg = vip.vip;
    if (!cfg) {
      return;
    }
    const key = keyOf(vip);
    setDetailBusy(true);
    try {
      const res = await gateway.getVIP(cfg.protocol, cfg.address, cfg.port);
      if (res.error) {
        setDetail({ key, vip: null, error: res.error.message || 'The gateway did not return the VIP' });
      } else {
        setDetail({ key, vip: res.data?.vip ?? null, error: null });
      }
    } catch (err) {
      setDetail({ key, vip: null, error: errorText(err) });
    } finally {
      setDetailBusy(false);
    }
  };

  const writesDisabled = !isAdmin || busy;

  return (
    <Card data-testid="vips-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Network className="h-5 w-5" />
          Load-balancer VIPs
        </CardTitle>
        <CardDescription>Virtual IPs this gateway balances across their backends.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!isAdmin && (
          <p className="text-sm text-muted-foreground" data-testid="vips-admin-only">
            Requires the admin role: VIP changes reprogram the gateway&apos;s switch.
          </p>
        )}
        {error !== null && (
          <Alert variant="destructive">
            <AlertTitle>VIP change not made</AlertTitle>
            <AlertDescription data-testid="vips-error" className="whitespace-pre-wrap break-words">
              {error}
            </AlertDescription>
          </Alert>
        )}

        {loaded && vips.length === 0 && (
          <p className="text-sm text-muted-foreground" data-testid="vips-empty">
            No VIPs configured.
          </p>
        )}
        <ul className="space-y-3">
          {vips.map((vip) => {
            const key = keyOf(vip);
            const cfg = vip.vip;
            const healthy = vip.backends.filter((b) => b.healthy).length;
            return (
              <li key={key} className="rounded-md border p-3 text-sm" data-testid={`vip-${key}`}>
                <div className="flex items-center justify-between gap-2">
                  <div>
                    <span className="font-mono">
                      {cfg ? `${cfg.protocol} ${cfg.address}:${cfg.port}` : key}
                    </span>
                    <span className="ml-3 text-muted-foreground">{cfg?.algorithm || 'default'}</span>
                    <span className="ml-3">
                      {`${healthy}/${vip.backends.length} backends healthy`}
                    </span>
                  </div>
                  <div className="flex gap-2">
                    <Gated op={GET_OP}>
                      <Button
                        variant="outline"
                        size="sm"
                        data-testid={`vip-details-${key}`}
                        disabled={detailBusy}
                        onClick={() => void handleDetails(vip)}
                      >
                        Details
                      </Button>
                    </Gated>
                    <Gated op={BACKENDS_OP}>
                      <Button
                        variant="outline"
                        size="sm"
                        data-testid={`vip-edit-${key}`}
                        disabled={writesDisabled}
                        onClick={() => {
                          setEditKey(key);
                          setEditText(formatBackends(cfg?.backends ?? []));
                        }}
                      >
                        Edit backends
                      </Button>
                    </Gated>
                    <Gated op={REMOVE_OP}>
                      <Button
                        variant="destructive"
                        size="sm"
                        data-testid={`vip-remove-${key}`}
                        disabled={writesDisabled}
                        onClick={() => setRemoving(vip)}
                      >
                        Remove
                      </Button>
                    </Gated>
                  </div>
                </div>
                {editKey === key && isAdmin && (
                  <div className="mt-3 space-y-2">
                    <Textarea
                      aria-label="Backends, one address:port [weight] per line"
                      data-testid={`vip-edit-backends-${key}`}
                      value={editText}
                      onChange={(e) => setEditText(e.target.value)}
                    />
                    <div className="flex gap-2">
                      <Gated op={BACKENDS_OP}>
                        <Button
                          size="sm"
                          data-testid={`vip-save-${key}`}
                          disabled={writesDisabled}
                          onClick={() => void handleSave(vip)}
                        >
                          Save backends
                        </Button>
                      </Gated>
                      <Button variant="outline" size="sm" onClick={() => setEditKey(null)}>
                        Cancel
                      </Button>
                    </div>
                  </div>
                )}
                {detail?.key === key &&
                  (detail.error !== null ? (
                    <p className="mt-2 text-sm text-destructive" data-testid={`vip-detail-error-${key}`}>
                      {detail.error}
                    </p>
                  ) : (
                    <dl className="mt-2 text-sm" data-testid={`vip-detail-${key}`}>
                      <div>
                        <dt className="inline text-muted-foreground">Conntrack: </dt>
                        <dd className="inline font-mono">{`ct zone ${detail.vip?.ctZone ?? '-'}`}</dd>
                      </div>
                      <div>
                        <dt className="inline text-muted-foreground">Select group: </dt>
                        <dd className="inline font-mono">{`group ${detail.vip?.groupId ?? '-'}`}</dd>
                      </div>
                      {(detail.vip?.backends ?? []).map((b, i) => (
                        <div key={`${b.backend?.address ?? ''}:${b.backend?.port ?? i}`}>
                          <dt className="inline text-muted-foreground">Backend: </dt>
                          <dd className="inline font-mono">
                            {`${b.backend?.address ?? '?'}:${b.backend?.port ?? '?'} ${b.healthy ? 'healthy' : 'unhealthy'}`}
                          </dd>
                        </div>
                      ))}
                    </dl>
                  ))}
              </li>
            );
          })}
        </ul>

        <div className="space-y-2 rounded-md border p-3">
          <div className="text-sm font-medium">Add a VIP</div>
          <div className="grid gap-2 md:grid-cols-3">
            <select
              aria-label="Protocol"
              className="h-10 rounded-md border border-input bg-background px-3 text-sm"
              data-testid="vip-protocol"
              value={protocol}
              disabled={!isAdmin}
              onChange={(e) => setProtocol(e.target.value)}
            >
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
            </select>
            <Input
              aria-label="Address"
              placeholder="Virtual IPv4 address"
              data-testid="vip-address"
              value={address}
              disabled={!isAdmin}
              onChange={(e) => setAddress(e.target.value)}
            />
            <Input
              aria-label="Port"
              placeholder="Port"
              inputMode="numeric"
              data-testid="vip-port"
              value={port}
              disabled={!isAdmin}
              onChange={(e) => setPort(e.target.value)}
            />
          </div>
          <Textarea
            aria-label="Backends, one address:port [weight] per line"
            placeholder="address:port [weight], one per line"
            data-testid="vip-backends"
            value={backendsText}
            disabled={!isAdmin}
            onChange={(e) => setBackendsText(e.target.value)}
          />
          {formError !== null && (
            <p className="text-sm text-destructive" data-testid="vip-form-error">
              {formError}
            </p>
          )}
          <Gated op={ADD_OP}>
            <Button size="sm" data-testid="vip-add" disabled={writesDisabled} onClick={() => void handleAdd()}>
              Add VIP
            </Button>
          </Gated>
        </div>
      </CardContent>

      <Dialog open={removing !== null} onOpenChange={(open) => !open && setRemoving(null)}>
        <DialogContent className="sm:max-w-[480px]" data-testid="vip-remove-dialog">
          <DialogHeader>
            <DialogTitle>Remove this VIP?</DialogTitle>
            <DialogDescription>
              {removing?.vip
                ? `${removing.vip.protocol} ${removing.vip.address}:${removing.vip.port} stops balancing ` +
                  `across its ${removing.backends.length} backends; the gateway's switch is reprogrammed.`
                : ''}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" data-testid="vip-remove-cancel" onClick={() => setRemoving(null)}>
              Cancel
            </Button>
            <Gated op={REMOVE_OP}>
              <Button variant="destructive" data-testid="vip-remove-confirm" onClick={() => void handleRemove()}>
                Remove VIP
              </Button>
            </Gated>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
