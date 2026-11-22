/**
 * The TCP ports of the real-server test daemon. platformd.test.yaml opens
 * two TLS webservices: the public one (the console and its API, written as
 * 18443 in the template) and the internal one (written as
 * INTERNAL_PORT_PLACEHOLDER). global-setup picks both from E2E_PORT here, so
 * the two listeners never bind one address (E2E_PORT=19443 used to put the
 * public listener on the internal listener's fixed 19443).
 */

/** The public TLS port the template is written with. */
export const TEMPLATE_PUBLIC_PORT = 18443;

/** The token platformd.test.yaml carries for the internal TLS port. */
export const INTERNAL_PORT_PLACEHOLDER = '__E2E_INTERNAL_PORT__';

/** How far the internal port sits from the public one. */
export const INTERNAL_PORT_OFFSET = 1000;

export interface DaemonPorts {
  publicPort: number;
  internalPort: number;
}

/**
 * The public and internal TLS ports for a public port: the internal port is
 * INTERNAL_PORT_OFFSET above it (19443 for the default 18443), or below it
 * when above would pass 65535. The two always differ.
 */
export function pickPorts(publicPort: number): DaemonPorts {
  if (!Number.isInteger(publicPort) || publicPort <= 0 || publicPort > 65535) {
    throw new Error(`public port ${publicPort} is not a TCP port`);
  }
  const up = publicPort + INTERNAL_PORT_OFFSET;
  const internalPort = up <= 65535 ? up : publicPort - INTERNAL_PORT_OFFSET;
  return { publicPort, internalPort };
}

/**
 * The daemon config for ports: every template public port becomes
 * ports.publicPort, then every placeholder becomes ports.internalPort (in
 * that order, so an internal port equal to the template public port stays).
 */
export function renderConfig(template: string, ports: DaemonPorts): string {
  return template
    .replace(new RegExp(String(TEMPLATE_PUBLIC_PORT), 'g'), String(ports.publicPort))
    .split(INTERNAL_PORT_PLACEHOLDER)
    .join(String(ports.internalPort));
}
