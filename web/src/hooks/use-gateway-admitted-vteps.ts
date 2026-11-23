/**
 * Admitted-VTEP reads of one gateway's overlay (#2051), through the SDK's
 * GatewayService: GET /gateway/state/{id}/admitted-vteps lists them and
 * GET /gateway/state/{id}/admitted-vteps/{vtep} reads one.
 */
import * as React from 'react';
import { useGateway, type GatewayService } from 'trusted-platform-sdk';

/** The data of a successful answer of one GatewayService read. */
type Data<F extends (...args: never[]) => Promise<{ data?: unknown }>> = NonNullable<Awaited<ReturnType<F>>['data']>;

export type GatewayAdmittedVTEPList = Data<GatewayService['listAdmittedVTEPs']>;

export type GatewayAdmittedVTEPEntry = Data<GatewayService['getAdmittedVTEP']>;

export type GatewayAdmittedVTEPId = Parameters<GatewayService['getAdmittedVTEP']>[1];

export interface UseGatewayAdmittedVTEPsResult {
  vteps: GatewayAdmittedVTEPList['admitted_vteps'];
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  get: (vtep: GatewayAdmittedVTEPId) => Promise<GatewayAdmittedVTEPEntry>;
}

/** An API refusal as an Error whose message keeps the HTTP status. */
function apiFailure(error: { status?: number; message: string }): Error {
  return new Error(error.status !== undefined ? `HTTP ${error.status}: ${error.message}` : error.message);
}

export function useGatewayAdmittedVTEPs(gatewayId: string): UseGatewayAdmittedVTEPsResult {
  const gateway = useGateway();
  const [vteps, setVteps] = React.useState<GatewayAdmittedVTEPList['admitted_vteps']>([]);
  const [isLoading, setIsLoading] = React.useState(Boolean(gatewayId));
  const [error, setError] = React.useState<string | null>(null);

  // Every read takes a sequence number and publishes only while it is still
  // the newest one, so a read for an earlier gateway never replaces a later one.
  const seq = React.useRef(0);

  const read = React.useCallback(async () => {
    const id = ++seq.current;
    if (!gatewayId) {
      setVteps([]);
      setError(null);
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    try {
      const res = await gateway.listAdmittedVTEPs(gatewayId);
      if (id !== seq.current) return;
      if (res.error) {
        setError(apiFailure(res.error).message);
        setVteps([]);
      } else {
        setError(null);
        setVteps(res.data?.admitted_vteps ?? []);
      }
    } finally {
      if (id === seq.current) setIsLoading(false);
    }
  }, [gateway, gatewayId]);

  React.useEffect(() => {
    void read();
    return () => {
      seq.current++;
    };
  }, [read]);

  const get = React.useCallback(
    async (vtep: GatewayAdmittedVTEPId) => {
      const res = await gateway.getAdmittedVTEP(gatewayId, vtep);
      if (res.error) throw apiFailure(res.error);
      if (!res.data) throw new Error(`VTEP ${vtep} was not returned`);
      return res.data;
    },
    [gateway, gatewayId]
  );

  return { vteps, isLoading, error, refetch: read, get };
}
