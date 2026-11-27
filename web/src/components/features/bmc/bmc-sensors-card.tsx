'use client';

/**
 * BMCSensorsCard — the BMC's sensor readings (BMCService.GetSensors) for one
 * BMC profile, read through useBMCStatus on the SDK API client on mount and on
 * Refresh (#2039).
 *
 * Readings whose status is not ok are named first in a warning line and their
 * rows are marked in the table. A refusal is shown verbatim instead of the
 * table.
 */

import { useCallback, useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { sensorsNeedingAttention, useBMCStatus, type BMCSensorReading } from '@/hooks/use-bmc-status';

export interface BMCSensorsCardProps {
  profileID: string;
}

/** A reading's value and units: integers as they are, others to one decimal. */
export function formatSensorValue(r: BMCSensorReading): string {
  const value = Number.isInteger(r.value) ? String(r.value) : r.value.toFixed(1);
  return `${value} ${r.units}`.trim();
}

function statusVariant(status: string): 'destructive' | 'secondary' | 'outline' {
  if (status === 'critical') return 'destructive';
  if (status === 'warning') return 'secondary';
  return 'outline';
}

export function BMCSensorsCard({ profileID }: BMCSensorsCardProps) {
  const ops = useBMCStatus(profileID);
  const [readings, setReadings] = useState<BMCSensorReading[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const res = await ops.getSensors();
      if (res.success) {
        setReadings(res.data ?? []);
        setError(null);
      } else {
        setReadings(null);
        setError(res.error?.message ?? 'request failed');
      }
    } finally {
      setLoading(false);
    }
  }, [ops]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const attention = readings ? sensorsNeedingAttention(readings) : [];

  return (
    <Card data-testid="bmc-sensors-card">
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle>BMC sensors</CardTitle>
          <CardDescription>BMC profile {profileID}</CardDescription>
        </div>
        <Button variant="outline" size="sm" disabled={loading} onClick={() => void reload()}>
          Refresh
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        {error !== null ? (
          <p role="alert" className="text-sm text-destructive">
            {`Sensors unavailable: ${error}`}
          </p>
        ) : readings !== null ? (
          <>
            {attention.length > 0 && (
              <p role="status" data-testid="bmc-sensors-attention" className="text-sm font-medium">
                {`${attention.length} ${attention.length === 1 ? 'sensor needs' : 'sensors need'} attention: ${attention
                  .map((r) => r.name)
                  .join(', ')}`}
              </p>
            )}
            <Table data-testid="bmc-sensors">
              <TableHeader>
                <TableRow>
                  <TableHead>Sensor</TableHead>
                  <TableHead>Reading</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {readings.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} className="text-muted-foreground">
                      No sensors reported.
                    </TableCell>
                  </TableRow>
                ) : (
                  readings.map((r, i) => (
                    <TableRow key={`${r.name}-${i}`} data-attention={r.status !== 'ok' ? 'true' : undefined}>
                      <TableCell>{r.name}</TableCell>
                      <TableCell>{formatSensorValue(r)}</TableCell>
                      <TableCell>
                        <Badge variant={statusVariant(r.status)}>{r.status}</Badge>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}
