'use client';

/**
 * SDN port state card: GetPort and SetPortState on
 * `GET|PUT /api/v1/sdn/bridges/{name}/ports/{port}/state` through
 * useSDNPortState.
 *
 * Setting a port down cuts its traffic, so the card asks first. A zero rate
 * leaves the port's policing as it is. Refusals are shown verbatim.
 */

import { useCallback, useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useSDNPortState } from '@/hooks/use-sdn-port-state';
import type { Port } from 'trusted-platform-sdk';

/** "PORT_STATUS_UP" -> "UP"; "" or undefined -> "UNKNOWN"; any other string is returned without the "PORT_STATUS_" prefix. */
export function portStatusLabel(status: string | undefined): string {
  if (!status) return 'UNKNOWN';
  return status.startsWith('PORT_STATUS_') ? status.slice('PORT_STATUS_'.length) : status;
}

/** "" (after trim) -> undefined; a finite number >= 0 -> that number; anything else -> NaN. */
export function parseRate(text: string): number | undefined {
  const trimmed = text.trim();
  if (trimmed === '') return undefined;
  const value = Number(trimmed);
  return Number.isFinite(value) && value >= 0 ? value : NaN;
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function statusVariant(label: string): 'default' | 'destructive' | 'secondary' {
  if (label === 'UP') return 'default';
  if (label === 'DOWN') return 'destructive';
  return 'secondary';
}

export interface SDNPortStateCardProps {
  bridgeId: string;
  portId: string;
}

export function SDNPortStateCard({ bridgeId, portId }: SDNPortStateCardProps) {
  const ops = useSDNPortState(bridgeId, portId);
  const [port, setPort] = useState<Port | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      const res = await ops.getPort();
      if (res.success && res.data) {
        setPort(res.data.port);
        setLoadError(null);
      } else {
        setLoadError(res.error?.message ?? 'Get port failed');
      }
    } catch (err) {
      setLoadError(messageOf(err));
    }
  }, [ops]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const label = port ? portStatusLabel(String(port.status)) : '';

  return (
    <Card>
      <CardHeader>
        <CardTitle>Port state</CardTitle>
        <CardDescription>
          Port {portId} on bridge {bridgeId}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-2">
          {port && (
            <>
              <span data-testid="sdn-port-name" className="font-mono">
                {port.config?.name ?? port.id}
              </span>
              <Badge data-testid="sdn-port-status" variant={statusVariant(label)}>
                {label}
              </Badge>
            </>
          )}
          <Button variant="outline" size="sm" onClick={() => void reload()}>
            Refresh
          </Button>
        </div>
        {loadError && (
          <p role="alert" className="text-sm text-destructive">
            {loadError}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
