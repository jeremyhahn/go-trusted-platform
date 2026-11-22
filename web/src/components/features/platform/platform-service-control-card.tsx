'use client';

/**
 * PlatformServiceControlCard — the platform daemon's services and their
 * status (ListServices, GetServiceStatus; #2047).
 *
 * Stopping or restarting a service interrupts it, so the card asks first.
 * Refusals are shown verbatim, because the daemon's message says why it
 * refused.
 */

import { useCallback, useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Gated } from '@/components/features/capabilities/gated';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { useToast } from '@/hooks/use-toast';
import {
  usePlatformServices,
  type PlatformServiceInfo,
  type ServiceAction,
} from '@/hooks/use-platform-services';

const DONE: Record<ServiceAction, string> = {
  start: 'Service started',
  stop: 'Service stopped',
  restart: 'Service restarted',
};

const VERB: Record<ServiceAction, string> = {
  start: 'Start',
  stop: 'Stop',
  restart: 'Restart',
};

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function statusVariant(status?: string): 'default' | 'destructive' | 'secondary' {
  if (status === 'running') return 'default';
  if (status === 'error') return 'destructive';
  return 'secondary';
}

export function PlatformServiceControlCard(): JSX.Element {
  const services = usePlatformServices();
  const { toast } = useToast();
  const [list, setList] = useState<PlatformServiceInfo[] | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [detail, setDetail] = useState<PlatformServiceInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<{ name: string; action: 'stop' | 'restart' } | null>(null);

  const reload = useCallback(async () => {
    try {
      const res = await services.listServices();
      if (res.success && res.data) {
        setList(res.data.services ?? []);
        setRefusal(null);
      } else {
        setList(null);
        setRefusal(res.error?.message || 'The daemon did not list its services');
      }
    } catch (err) {
      setList(null);
      setRefusal(errorMessage(err));
    }
  }, [services]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const showDetail = async (name: string) => {
    try {
      const res = await services.getService(name);
      if (res.success && res.data) {
        setDetail(res.data);
      } else {
        toast({
          title: 'Service status failed',
          description: res.error?.message || `No status for ${name}`,
          variant: 'destructive',
        });
      }
    } catch (err) {
      toast({ title: 'Service status failed', description: errorMessage(err), variant: 'destructive' });
    }
  };

  const run = async (name: string, action: ServiceAction) => {
    setBusy(true);
    try {
      const res = await services.act(name, action);
      if (res.success && res.data?.success !== false) {
        toast({ title: DONE[action], description: res.data?.message, variant: 'success' });
        await reload();
      } else {
        toast({
          title: `${VERB[action]} failed`,
          description: res.error?.message ?? res.data?.message,
          variant: 'destructive',
        });
      }
    } catch (err) {
      toast({ title: `${VERB[action]} failed`, description: errorMessage(err), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  const confirmAction = () => {
    if (confirm === null) return;
    const { name, action } = confirm;
    setConfirm(null);
    void run(name, action);
  };

  return (
    <Card data-testid="platform-service-control-card">
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle>Daemon services</CardTitle>
          <CardDescription>Status of each platform service.</CardDescription>
        </div>
        <Button variant="outline" size="sm" onClick={() => void reload()}>
          Refresh
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        {refusal !== null && (
          <p role="alert" className="text-sm text-destructive whitespace-pre-wrap break-words">
            {refusal}
          </p>
        )}
        {list !== null && list.length === 0 && (
          <p className="text-sm text-muted-foreground">No services registered.</p>
        )}
        {list !== null && list.length > 0 && (
          <table data-testid="platform-services" className="w-full text-sm">
            <thead>
              <tr className="text-left">
                <th>Service</th>
                <th>Status</th>
                <th>Uptime</th>
                <th>Last error</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.map((svc) => (
                <tr key={svc.name} data-testid={`service-row-${svc.name}`}>
                  <td className="font-mono">{svc.name}</td>
                  <td>
                    <Badge data-testid={`service-status-${svc.name}`} variant={statusVariant(svc.status)}>
                      {svc.status}
                    </Badge>
                  </td>
                  <td>{svc.uptime ?? '-'}</td>
                  <td className="text-destructive">{svc.last_error ? svc.last_error : null}</td>
                  <td className="space-x-1 text-right">
                    <Gated op="POST /api/v1/platform/services/{service}/start">
                    <Button
                      variant="outline"
                      size="sm"
                      aria-label={`Start ${svc.name}`}
                      disabled={busy}
                      onClick={() => void run(svc.name, 'start')}
                    >
                      Start
                    </Button>
                    </Gated>
                    <Gated op="POST /api/v1/platform/services/{service}/stop">
                    <Button
                      variant="outline"
                      size="sm"
                      aria-label={`Stop ${svc.name}`}
                      disabled={busy}
                      onClick={() => setConfirm({ name: svc.name, action: 'stop' })}
                    >
                      Stop
                    </Button>
                    </Gated>
                    <Gated op="POST /api/v1/platform/services/{service}/restart">
                    <Button
                      variant="outline"
                      size="sm"
                      aria-label={`Restart ${svc.name}`}
                      disabled={busy}
                      onClick={() => setConfirm({ name: svc.name, action: 'restart' })}
                    >
                      Restart
                    </Button>
                    </Gated>
                    <Button variant="ghost" size="sm" onClick={() => void showDetail(svc.name)}>
                      Details
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {detail !== null && (
          <dl data-testid="service-detail" className="grid grid-cols-2 gap-1 text-sm">
            <dt>Service</dt>
            <dd className="font-mono">{detail.name}</dd>
            <dt>Status</dt>
            <dd>{detail.status}</dd>
            <dt>Started</dt>
            <dd>{detail.started_at ?? '-'}</dd>
            <dt>Starts</dt>
            <dd>{detail.start_count ?? 0}</dd>
            <dt>Stops</dt>
            <dd>{detail.stop_count ?? 0}</dd>
          </dl>
        )}
      </CardContent>

      <Dialog open={confirm !== null} onOpenChange={(open) => !open && setConfirm(null)}>
        <DialogContent>
          {confirm !== null && (
            <>
              <DialogHeader>
                <DialogTitle>{`${VERB[confirm.action]} ${confirm.name}?`}</DialogTitle>
                <DialogDescription>
                  {`Requests to the ${confirm.name} service fail until it is running again.`}
                </DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button variant="outline" onClick={() => setConfirm(null)}>
                  Cancel
                </Button>
                <Button variant="destructive" onClick={confirmAction}>
                  {VERB[confirm.action]}
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
    </Card>
  );
}
