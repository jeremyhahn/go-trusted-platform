import type { APIResponse, Page } from '@playwright/test';

/**
 * Direct calls to daemon routes the JS SDK has no client for (#2037).
 *
 * The part 3 ports read back service, SDN policy, switch port, TPM
 * capability and tenant barrier state the server really serves, but the
 * SDK on this branch has no method for those routes. Each call goes through
 * the admin page's request context (the same one the `sdk` fixture uses),
 * so it carries the admin session. The reply is the server's
 * `{code, success, error, payload}` envelope, read without throwing: the
 * specs assert `success` false on refusals. These are SDK gaps for the
 * route audit (docs/plans/1665-port-3.md).
 */

export interface DaemonResult<T> {
  success: boolean;
  status: number;
  data?: T;
  error?: unknown;
}

export interface ServiceInfo {
  name: string;
  status?: string;
  uptimeSeconds?: string;
  [k: string]: unknown;
}

export interface PolicyConfig {
  name?: string;
  type?: string;
  enabled?: boolean;
  priority?: number;
  rules?: unknown[];
  targets?: { type: string; id: string }[];
  [k: string]: unknown;
}

export interface Policy {
  id: string;
  config?: PolicyConfig;
}

export interface ApplyPolicyRequest {
  policyId?: string;
  config: PolicyConfig;
}

async function readResult<T>(res: APIResponse): Promise<DaemonResult<T>> {
  const status = res.status();
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    body = undefined;
  }
  if (typeof body === 'object' && body !== null && !Array.isArray(body) && 'success' in body) {
    const env = body as { success?: unknown; error?: unknown; payload?: unknown };
    const success = res.ok() && env.success === true;
    return {
      success,
      status,
      data: success && env.payload !== null ? (env.payload as T) : undefined,
      error: success ? undefined : (env.error ?? status),
    };
  }
  return res.ok()
    ? { success: true, status, data: body as T }
    : { success: false, status, error: body ?? status };
}

const seg = encodeURIComponent;

/** The daemon routes the ports call directly, as the admin of `page`. */
export function daemonApi(page: Page) {
  const request = page.context().request;
  const get = async <T>(path: string) =>
    readResult<T>(await request.get(`/api/v1${path}`, { failOnStatusCode: false }));
  const post = async <T>(path: string, data: unknown = {}) =>
    readResult<T>(await request.post(`/api/v1${path}`, { data, failOnStatusCode: false }));
  const put = async <T>(path: string, data: unknown) =>
    readResult<T>(await request.put(`/api/v1${path}`, { data, failOnStatusCode: false }));
  const port = (sw: string, p: string) => `/switches/${seg(sw)}/ports/${seg(p)}`;

  return {
    getStatus: () => get<Record<string, unknown>>('/status'),
    listServices: () => get<{ services?: ServiceInfo[] }>('/services'),
    getServiceStatus: (name: string) => get<ServiceInfo>(`/services/${seg(name)}`),
    startService: (name: string) => post<ServiceInfo>(`/services/${seg(name)}/start`),
    stopService: (name: string) => post<ServiceInfo>(`/services/${seg(name)}/stop`),

    listPolicies: () => get<{ policies?: Policy[] }>('/sdn/policies'),
    applyPolicy: (req: ApplyPolicyRequest) => post<{ policy?: Policy }>('/sdn/policies', req),

    listSwitchPorts: (sw: string) => get<unknown>(`/switches/${seg(sw)}/ports`),
    getSwitchPortStatus: (sw: string, p: string) => get<unknown>(port(sw, p)),
    enableSwitchPort: (sw: string, p: string) => post<unknown>(`${port(sw, p)}/enable`),
    disableSwitchPort: (sw: string, p: string) => post<unknown>(`${port(sw, p)}/disable`),
    setSwitchPortVLAN: (sw: string, p: string, vlan: number) =>
      put<unknown>(`${port(sw, p)}/vlan`, { vlan_id: vlan }),

    getTPMCapabilities: () => get<Record<string, unknown>>('/tpm/capabilities'),
    getTPMPlatformAttributes: () => get<Record<string, unknown>>('/tpm/platform'),

    initTenantBarrier: (id: string) => post<unknown>(`/tenants/${seg(id)}/barrier/init`, {}),
  };
}

export type DaemonApi = ReturnType<typeof daemonApi>;
