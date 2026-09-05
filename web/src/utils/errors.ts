/**
 * errorMessage renders an unknown thrown value for display. Thrown values are
 * `unknown` under strict TypeScript; this is the one place that narrows them.
 */
export function errorMessage(err: unknown, fallback: string): string {
  if (err instanceof Error && err.message) return err.message;
  if (typeof err === "string" && err) return err;
  return fallback;
}
