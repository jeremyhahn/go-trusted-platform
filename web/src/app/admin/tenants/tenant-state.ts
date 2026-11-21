/**
 * Normalises a tenant state as the webservice sends it (protojson enum
 * names such as `TENANT_STATE_SUSPENDED`) to its short name (`SUSPENDED`).
 * A short name passes through unchanged; a missing state gives `UNSPECIFIED`.
 */
export function tenantStateName(state: unknown): string {
  const name = String(state ?? "").replace(/^TENANT_STATE_/, "");
  return name === "" ? "UNSPECIFIED" : name;
}
