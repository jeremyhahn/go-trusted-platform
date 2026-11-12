/**
 * The webservice serialises Tenant.state as the protojson enum name
 * (TENANT_STATE_SUSPENDED); older payloads and fixtures may carry the short
 * name (SUSPENDED). Both normalise to the short name.
 */
export function tenantStateName(state: unknown): string {
  const name = String(state ?? "").replace(/^TENANT_STATE_/, "");
  return name === "" ? "UNSPECIFIED" : name;
}
