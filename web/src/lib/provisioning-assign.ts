/**
 * The Assign Template link between the provisioning sessions list and the
 * create-from-template page (#2046).
 *
 * The link carries identifiers a device reported, so every value is encoded:
 * a reported EK serial such as `EK&sessionId=other-session` stays one value
 * and cannot add a query key. The reader takes the session only when the link
 * names exactly one, so a link with an injected sessionId fulfils nothing.
 */

export interface AssignableSession {
  id: string;
  ek_serial?: string | null;
  mac_address?: string | null;
}

/** The create-from-template link that fulfils `session` with the new profile. */
export function assignTemplateHref(templateId: string, session: AssignableSession): string {
  const query = new URLSearchParams();
  if (session.ek_serial) query.set('ekSerial', session.ek_serial);
  if (session.mac_address) query.set('macAddress', session.mac_address);
  query.set('sessionId', session.id);
  return `/devices/templates/${encodeURIComponent(templateId)}/create-profile?${query.toString()}`;
}

/**
 * The session an Assign Template link names. `ambiguous` is true when the
 * link carries more than one sessionId; then no session is taken.
 */
export function assignedSessionId(
  params: { getAll(name: string): string[] } | null | undefined
): { sessionId: string; ambiguous: boolean } {
  const ids = params?.getAll('sessionId') ?? [];
  if (ids.length > 1) return { sessionId: '', ambiguous: true };
  return { sessionId: ids[0] ?? '', ambiguous: false };
}
