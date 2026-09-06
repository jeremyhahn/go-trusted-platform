'use client';

/**
 * DeviceReportCard — one device's attestation report as the collector serves
 * it (#428): the verdict WITH its age, which check failed and whether it
 * failed cryptographically, the baseline's provenance, and the
 * "Refresh attestation" control (an enqueue that answers 202, never a quote).
 *
 * Four states, rendered distinctly: fresh report, stale report (still shown),
 * never collected (404), and reporting not configured (503).
 */

import { useCallback, useEffect, useState } from 'react';
import { Check, RefreshCw, Shield, X } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAttestation, useToast } from '@/hooks';
import { classifyDeviceReport } from 'trusted-platform-sdk';
import type { DeviceReportState } from 'trusted-platform-sdk';
import {
  baselineAge,
  baselineSourceBadge,
  checkRows,
  clockBadge,
  freshnessBadge,
  reportStateBadge,
  verdictBadge,
} from '@/lib/attestation-report';

interface DeviceReportCardProps {
  deviceId: string;
}

export function DeviceReportCard({ deviceId }: DeviceReportCardProps) {
  const attestation = useAttestation();
  const { toast } = useToast();
  const [state, setState] = useState<DeviceReportState | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const load = useCallback(async () => {
    try {
      const response = await attestation.getDeviceReport(deviceId);
      setState(classifyDeviceReport(response));
    } catch (err) {
      setState({ kind: 'error', message: err instanceof Error ? err.message : String(err) });
    }
  }, [attestation, deviceId]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      const response = await attestation.refreshDeviceReport(deviceId);
      if (response.success && response.data?.enqueued) {
        toast({
          title: 'Collection enqueued',
          description: 'The collector will attest the device on its next pass; the report below re-reads with the new age.',
        });
      } else {
        toast({
          title: 'Refresh not accepted',
          description: response.error?.message || 'The collector did not accept the request',
          variant: 'destructive',
        });
      }
    } catch (err) {
      toast({
        title: 'Refresh failed',
        description: err instanceof Error ? err.message : String(err),
        variant: 'destructive',
      });
    } finally {
      setIsRefreshing(false);
      await load();
    }
  };

  const refreshDisabled = isRefreshing || state === null || state.kind === 'not-configured';

  return (
    <Card data-testid="device-report-card">
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Attestation Report
          </CardTitle>
          <CardDescription>
            The control plane&apos;s cached verdict for this device and how old the evidence is
          </CardDescription>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={handleRefresh}
          disabled={refreshDisabled}
          title="Enqueue an out-of-cycle collection; the verdict arrives when the collector has attested the device"
        >
          <RefreshCw className={`mr-2 h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} />
          Refresh attestation
        </Button>
      </CardHeader>
      <CardContent>
        {state === null && <p className="text-sm text-muted-foreground">Loading report…</p>}
        {state !== null && state.kind !== 'report' && <ReportAbsent state={state} />}
        {state !== null && state.kind === 'report' && <ReportBody state={state} />}
      </CardContent>
    </Card>
  );
}

function ReportAbsent({ state }: { state: Exclude<DeviceReportState, { kind: 'report' }> }) {
  const badge = reportStateBadge(state);
  return (
    <div className="flex flex-col gap-2" data-testid={`report-state-${state.kind}`}>
      <Badge variant={badge.variant} title={badge.title} className="w-fit">
        {badge.label}
      </Badge>
      <p className="text-sm text-muted-foreground">{badge.title}</p>
    </div>
  );
}

function ReportBody({ state }: { state: Extract<DeviceReportState, { kind: 'report' }> }) {
  const { report } = state;
  const verdict = verdictBadge(report);
  const freshness = freshnessBadge(report);
  const baseline = baselineSourceBadge(report);
  const baselineAgeLabel = baselineAge(report);
  const clock = clockBadge(report);

  return (
    <div className="space-y-4" data-testid="report-state-report" data-fresh={report.fresh ? 'true' : 'false'}>
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={verdict.variant} title={verdict.title} data-testid="report-verdict">
          {verdict.label}
        </Badge>
        <Badge variant={freshness.variant} title={freshness.title} data-testid="report-age">
          {freshness.label}
        </Badge>
        {baseline && (
          <Badge variant={baseline.variant} title={baseline.title} data-testid="report-baseline-source">
            {baseline.label}
            {baselineAgeLabel ? ` · ${baselineAgeLabel} old` : ''}
          </Badge>
        )}
        <Badge variant={clock.variant} title={clock.title} data-testid="report-clock">
          {clock.label}
        </Badge>
        {!report.verified && (
          <span className="text-xs text-muted-foreground" data-testid="report-failure-class">
            {report.cryptographic_failure
              ? 'A check ran and failed (cryptographic): the device is denied and quarantined'
              : 'A check could not run: the device is denied, not quarantined'}
          </span>
        )}
      </div>

      {report.message && <p className="text-sm text-muted-foreground">{report.message}</p>}

      <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {checkRows(report).map((row) => (
          <div key={row.key} className="flex items-center justify-between text-sm" title={row.hint} data-testid={`check-${row.key}`}>
            <dt className="text-muted-foreground">{row.label}</dt>
            <dd>
              {row.passed ? (
                <span className="flex items-center gap-1 text-green-600">
                  <Check className="h-4 w-4" />
                  passed
                </span>
              ) : (
                <span className="flex items-center gap-1 text-red-600">
                  <X className="h-4 w-4" />
                  failed
                </span>
              )}
            </dd>
          </div>
        ))}
      </dl>

      <dl className="grid grid-cols-1 gap-2 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-muted-foreground">Attested at</dt>
          <dd>{report.attested_at}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Collected at</dt>
          <dd>{report.collected_at}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Status</dt>
          <dd>{report.status}</dd>
        </div>
        {report.pcr_baseline_captured && (
          <div>
            <dt className="text-muted-foreground">Baseline</dt>
            <dd>This collection recorded the profile&apos;s trust-on-first-use baseline</dd>
          </div>
        )}
      </dl>
    </div>
  );
}
