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

/**
 * One VTEP the gateway admitted to its overlay, with the admission record it
 * reported. Field names are the json tags of the Go state.AdmittedVTEPState.
 * TODO(#2051): move to the SDK as GatewaySnapshot.overlay's types.
 */
export interface GatewayAdmittedVTEP {
  vtep: string;
  device_id?: number;
  host_id?: string;
  serial?: string;
  hostname?: string;
  allocation_id?: string;
  baseline_source?: string;
  profile_id?: number;
  verdict_at?: string;
}

/** The overlay section of a gateway snapshot (Go state.OverlayState). */
export interface GatewayOverlay {
  running: boolean;
  local_vtep?: string;
  vni_count?: number;
  remote_vtep_count?: number;
  local_mac_count?: number;
  remote_mac_count?: number;
  prefix_count?: number;
  refused_bindings?: number;
  refused_replays?: number;
  l3_vni?: number;
  admitted_vteps?: GatewayAdmittedVTEP[];
  nd_counters?: Record<string, number>;
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
 * VTEPs it admitted. Pure: it shows data the snapshot read already returned,
 * which is gated where the snapshots card opens it.
 */
export function GatewayAdmittedVTEPs({ overlay }: { overlay: GatewayOverlay }) {
  const vteps = overlay.admitted_vteps ?? [];
  const [openVtep, setOpenVtep] = React.useState<string | null>(null);
  const opened = vteps.find((v) => v.vtep === openVtep);

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
        <h4 className="text-sm font-medium mb-2">Admitted VTEPs</h4>
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
                    <Button
                      variant="ghost"
                      size="sm"
                      aria-label={`Details ${v.vtep}`}
                      onClick={() => setOpenVtep(v.vtep)}
                    >
                      Details
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      {opened && (
        <div className="rounded-md border p-3 space-y-2" data-testid="gateway-admitted-vtep-detail">
          <div className="flex items-center justify-between">
            <div className="text-sm font-medium">VTEP {opened.vtep}</div>
            <Button variant="ghost" size="sm" onClick={() => setOpenVtep(null)}>
              Close
            </Button>
          </div>
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
        </div>
      )}
    </div>
  );
}
