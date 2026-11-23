const PROTO_PREFIX = 'PROVISIONING_STATE_';

/**
 * Short name of a PXE provisioning state. The REST server writes the
 * protobuf enum name (PROVISIONING_STATE_DISCOVERED); the PXE pages key
 * their stats and badge colours on the short name (DISCOVERED). A short
 * name is kept as it is; a missing state reads as UNKNOWN.
 */
export function provisioningStateName(state?: string): string {
  if (!state) {
    return 'UNKNOWN';
  }
  const name = state.startsWith(PROTO_PREFIX) ? state.slice(PROTO_PREFIX.length) : state;
  return name || 'UNKNOWN';
}
