import * as React from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Gated } from '@/components/features/capabilities/gated';
import { useGatewayAdmittedVTEPs } from '@/hooks/use-gateway-admitted-vteps';
import type { GatewayAdmittedVTEP, GatewayOverlay } from 'trusted-platform-sdk';

export type { GatewayAdmittedVTEP, GatewayOverlay };

/** The server's op strings of the two admitted-VTEP reads (routes.golden). */
const LIST_OP = 'GET /api/v1/gateway/state/{id}/admitted-vteps';
const GET_OP = 'GET /api/v1/gateway/state/{id}/admitted-vteps/{vtep}';

/** The Details panel: the VTEP asked for and its answer or refusal. */
interface DetailState {
  gatewayId: string;
  vtep: string;
  entry?: GatewayAdmittedVTEP;
  error?: string;
}

function stateBadgeClass(good: boolean): string {
  return good
    ? 'bg-green-500/10 text-green-600 border-green-500/20'
    : 'bg-red-500/10 text-red-600 border-red-500/20';
}

/** A reported value, or '-' when the gateway did not report it. */
function show(value: string | number | undefined | null): string {
  return value === undefined || value === null || value === '' ? '-' : String(value);
}

function Field({ label, value }: { label: string; value: string | number | undefined }) {
  return (
    <div className="flex justify-between gap-4">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="font-mono">{show(value)}</dd>
    </div>
  );
}

/**
 * Renders the overlay a gateway reported in its telemetry snapshot and the
 * VTEPs it admitted. The list starts as the snapshot reported it; Refresh
 * lists the VTEPs again and Details reads one, through the SDK, each behind
 * the capability gate of its route.
 */
export function GatewayAdmittedVTEPs({ gatewayId, overlay }: { gatewayId: string; overlay: GatewayOverlay }) {
  const admitted = useGatewayAdmittedVTEPs(gatewayId, { auto: false });
  // The gateway a Refresh answered for: a refreshed list or refusal shows
  // only while that gateway is still the one on screen.
  const [refreshedFor, setRefreshedFor] = React.useState<string | null>(null);
  const [detail, setDetail] = React.useState<DetailState | null>(null);
  // Each Details read takes a sequence number; only the newest one publishes.
  const detailSeq = React.useRef(0);

  // A gateway switch drops the open Details and any Details read in flight.
  React.useEffect(() => {
    detailSeq.current++;
    setDetail(null);
  }, [gatewayId]);

  const current = refreshedFor === gatewayId;
  const vteps: GatewayAdmittedVTEP[] =
    current && !admitted.error ? (admitted.vteps ?? []) : (overlay.admitted_vteps ?? []);

  const refresh = async () => {
    const gw = gatewayId;
    await admitted.refetch();
    setRefreshedFor(gw);
  };

  const openDetails = async (vtep: string) => {
    const gw = gatewayId;
    const id = ++detailSeq.current;
    try {
      const entry = await admitted.get(vtep);
      if (id === detailSeq.current) setDetail({ gatewayId: gw, vtep, entry });
    } catch (err) {
      if (id === detailSeq.current) {
        setDetail({ gatewayId: gw, vtep, error: err instanceof Error ? err.message : String(err) });
      }
    }
  };

  const closeDetails = () => {
    detailSeq.current++;
    setDetail(null);
  };

  const shown = detail?.gatewayId === gatewayId ? detail : null;
  const opened = shown?.entry;

  return (
    <div className="rounded-lg border p-4 space-y-4">
      <div className="flex items-center justify-between">
        <div className="text-sm font-medium">Overlay</div>
        <Badge className={stateBadgeClass(overlay.running)}>
          {overlay.running ? 'Running' : 'Stopped'}
        </Badge>
      </div>

      <dl className="text-xs space-y-1" data-testid="gateway-overlay-summary">
        <Field label="Local VTEP" value={overlay.local_vtep} />
        <Field label="VNIs" value={overlay.vni_count} />
        <Field label="L3 VNI" value={overlay.l3_vni} />
        <Field label="Remote VTEPs" value={overlay.remote_vtep_count} />
        <Field label="Local MACs" value={overlay.local_mac_count} />
        <Field label="Remote MACs" value={overlay.remote_mac_count} />
        <Field label="Prefixes" value={overlay.prefix_count} />
        <Field label="Refused bindings" value={overlay.refused_bindings} />
        <Field label="Refused replays" value={overlay.refused_replays} />
      </dl>

      <div>
        <div className="flex items-center justify-between mb-2">
          <h4 className="text-sm font-medium">Admitted VTEPs</h4>
          <Gated op={LIST_OP}>
            <Button variant="outline" size="sm" disabled={admitted.isLoading} onClick={() => void refresh()}>
              Refresh
            </Button>
          </Gated>
        </div>
        {current && admitted.error && (
          <p className="text-xs text-red-600 mb-2" role="alert">
            {admitted.error}
          </p>
        )}
        {vteps.length === 0 ? (
          <p className="text-xs text-muted-foreground">No VTEP is admitted</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>VTEP</TableHead>
                <TableHead>Host</TableHead>
                <TableHead>Serial</TableHead>
                <TableHead>Baseline</TableHead>
                <TableHead>Verdict</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {vteps.map((v) => (
                <TableRow key={v.vtep} data-testid="gateway-admitted-vtep-row">
                  <TableCell className="font-mono text-xs">{v.vtep}</TableCell>
                  <TableCell className="text-xs">{show(v.hostname ?? v.host_id)}</TableCell>
                  <TableCell className="text-xs">{show(v.serial)}</TableCell>
                  <TableCell className="text-xs">{show(v.baseline_source)}</TableCell>
                  <TableCell className="text-xs">{show(v.verdict_at)}</TableCell>
                  <TableCell>
                    <Gated op={GET_OP}>
                      <Button
                        variant="ghost"
                        size="sm"
                        aria-label={`Details ${v.vtep}`}
                        onClick={() => void openDetails(v.vtep)}
                      >
                        Details
                      </Button>
                    </Gated>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      {shown && (
        <div className="rounded-md border p-3 space-y-2" data-testid="gateway-admitted-vtep-detail">
          <div className="flex items-center justify-between">
            <div className="text-sm font-medium">VTEP {shown.vtep}</div>
            <Button variant="ghost" size="sm" onClick={closeDetails}>
              Close
            </Button>
          </div>
          {shown.error ? (
            <p className="text-xs text-red-600" role="alert">
              {shown.error}
            </p>
          ) : (
            opened && (
              <dl className="text-xs space-y-1">
                <Field label="VTEP" value={opened.vtep} />
                <Field label="Device" value={opened.device_id} />
                <Field label="Host ID" value={opened.host_id} />
                <Field label="Hostname" value={opened.hostname} />
                <Field label="Serial" value={opened.serial} />
                <Field label="Allocation" value={opened.allocation_id} />
                <Field label="Baseline" value={opened.baseline_source} />
                <Field label="Profile" value={opened.profile_id} />
                <Field label="Verdict at" value={opened.verdict_at} />
              </dl>
            )
          )}
        </div>
      )}
    </div>
  );
}
