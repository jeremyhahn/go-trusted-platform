/**
 * Reading the vTPM replies in the real-server specs (#2072, epic #1665).
 *
 * GET /api/v1/capabilities and GET /api/v1/vtpm/bundles/{id}/state answer in
 * the {code, success, payload} envelope (unwrapPayload). A malformed reply
 * throws naming what is wrong: it never reads as an empty capability list or
 * a stopped vTPM.
 */
import { unwrapPayload } from './wire';

/** The ops the capabilities listing marks enabled. */
export function enabledOpsFrom(body: unknown): Set<string> {
  const payload = unwrapPayload<unknown>(body);
  const list = (payload as { capabilities?: unknown }).capabilities;
  if (!Array.isArray(list)) {
    throw new Error(`capabilities payload has no capabilities array: ${JSON.stringify(payload)}`);
  }
  const ops = new Set<string>();
  list.forEach((entry: unknown, i: number) => {
    const c = (typeof entry === 'object' && entry !== null ? entry : {}) as { op?: unknown; enabled?: unknown };
    if (typeof c.op !== 'string') {
      throw new Error(`capabilities[${i}].op is not a string: ${JSON.stringify(entry)}`);
    }
    if (typeof c.enabled !== 'boolean') {
      throw new Error(`capabilities[${i}].enabled is not a boolean: ${JSON.stringify(entry)}`);
    }
    if (c.enabled) ops.add(c.op);
  });
  return ops;
}

/** The running flag of a bundle state reply. */
export function runStateFrom(body: unknown): boolean {
  const payload = unwrapPayload<unknown>(body);
  const running = (payload as { running?: unknown }).running;
  if (typeof running !== 'boolean') {
    throw new Error(`state payload has no boolean running: ${JSON.stringify(payload)}`);
  }
  return running;
}
