'use client';

/**
 * BMCSystemCard — the host power state (BMCService.PowerStatus) and the BMC's
 * system information (BMCService.GetSystemInfo) for one BMC profile, read
 * through useBMCStatus on the SDK API client on mount and on Refresh (#2039).
 *
 * A refusal (an unknown profile, a BMC that cannot be reached) is shown
 * verbatim in place of the value it stopped.
 */

import { useCallback, useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useBMCStatus, type BMCSystemInfo } from '@/hooks/use-bmc-status';

export interface BMCSystemCardProps {
  profileID: string;
}

/** The label for a PowerStatus state: 'on', 'off', anything else is unknown. */
export function powerStateLabel(state: string): string {
  if (state === 'on') return 'On';
  if (state === 'off') return 'Off';
  return 'Unknown';
}

function powerVariant(state: string): 'default' | 'secondary' | 'outline' {
  if (state === 'on') return 'default';
  if (state === 'off') return 'secondary';
  return 'outline';
}

function orDash(value: string | undefined): string {
  return value ? value : '-';
}

export function BMCSystemCard({ profileID }: BMCSystemCardProps) {
  const ops = useBMCStatus(profileID);
  const [power, setPower] = useState<string | null>(null);
  const [info, setInfo] = useState<BMCSystemInfo | null>(null);
  const [powerError, setPowerError] = useState<string | null>(null);
  const [infoError, setInfoError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const [powerRes, infoRes] = await Promise.all([ops.getPower(), ops.getSystemInfo()]);
      if (powerRes.success && powerRes.data) {
        setPower(powerRes.data.state);
        setPowerError(null);
      } else {
        setPower(null);
        setPowerError(powerRes.error?.message ?? 'request failed');
      }
      if (infoRes.success && infoRes.data) {
        setInfo(infoRes.data);
        setInfoError(null);
      } else {
        setInfo(null);
        setInfoError(infoRes.error?.message ?? 'request failed');
      }
    } finally {
      setLoading(false);
    }
  }, [ops]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const fields: [string, string | undefined][] = info
    ? [
        ['Manufacturer', info.manufacturer],
        ['Product', info.product],
        ['Serial number', info.serial_number],
        ['Firmware', info.firmware_version],
        ['BIOS', info.bios_version],
      ]
    : [];

  return (
    <Card data-testid="bmc-system-card">
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle>BMC system</CardTitle>
          <CardDescription>BMC profile {profileID}</CardDescription>
        </div>
        <Button variant="outline" size="sm" disabled={loading} onClick={() => void reload()}>
          Refresh
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-2 text-sm">
          <span className="text-muted-foreground">Power</span>
          <span data-testid="bmc-power-state">
            {powerError !== null ? (
              `Power state unavailable: ${powerError}`
            ) : power !== null ? (
              <Badge variant={powerVariant(power)}>{powerStateLabel(power)}</Badge>
            ) : null}
          </span>
        </div>
        {infoError !== null ? (
          <p role="alert" className="text-sm text-destructive">
            System info unavailable: {infoError}
          </p>
        ) : info !== null ? (
          <dl data-testid="bmc-system-info" className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            {fields.map(([label, value]) => (
              <div key={label} className="contents">
                <dt className="text-muted-foreground">{label}</dt>
                <dd>{orDash(value)}</dd>
              </div>
            ))}
          </dl>
        ) : null}
      </CardContent>
    </Card>
  );
}
