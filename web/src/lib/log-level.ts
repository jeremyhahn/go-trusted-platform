import type { LogLevel } from "@/types/platform";

/**
 * Every level the platform log store writes, lowest first: the order the
 * Logs page offers them as a minimum-level filter. SECURITY is the
 * platform's security-event level (`logging.LevelSecurity`) and ranks
 * above FATAL, so it survives every filter (#169).
 */
export const LOG_LEVELS: readonly LogLevel[] = [
  "DEBUG",
  "INFO",
  "WARN",
  "ERROR",
  "FATAL",
  "SECURITY",
];

function isLogLevel(value: string): value is LogLevel {
  return (LOG_LEVELS as readonly string[]).includes(value);
}

/**
 * toLogLevel reads a wire level into one the console renders. slog names a
 * level it does not know as an offset from a standard one ("WARN+1",
 * "DEBUG-4"), so such a value is shown as that standard level; anything
 * else unreadable is shown as INFO rather than breaking the row.
 */
export function toLogLevel(raw: string | undefined): LogLevel {
  const level = (raw ?? "").trim().toUpperCase();
  if (isLogLevel(level)) {
    return level;
  }
  const base = level.split(/[+-]/, 1)[0];
  return isLogLevel(base) ? base : "INFO";
}
