const EAB_STATUS_PREFIX = "EAB_CREDENTIAL_STATUS_";

/**
 * Normalize an EAB credential status from the wire. The REST handlers
 * serialize protobuf enum names (EAB_CREDENTIAL_STATUS_ACTIVE); the pages
 * compare and display the short name (ACTIVE). A short name passes through.
 */
export function normalizeEABStatus(status: string | undefined): string {
  if (!status) return "";
  return status.startsWith(EAB_STATUS_PREFIX) ? status.slice(EAB_STATUS_PREFIX.length) : status;
}
