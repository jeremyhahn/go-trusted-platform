"use client";

import { useSyncExternalStore } from "react";
import { getTokenFromCookie } from "@/utils/jwt";

const listeners = new Set<() => void>();

function subscribe(onChange: () => void): () => void {
  listeners.add(onChange);
  return () => {
    listeners.delete(onChange);
  };
}

function subscribeNever(): () => void {
  return () => {};
}

function readToken(): string | null {
  return getTokenFromCookie();
}

function readServerToken(): null {
  return null;
}

/**
 * notifySessionChanged tells every useSessionToken subscriber to re-read the
 * session cookie. Call it after writing or clearing the cookie.
 */
export function notifySessionChanged(): void {
  for (const onChange of listeners) {
    onChange();
  }
}

/**
 * useSessionToken returns the JWT from the session cookie, SSR-safe: null
 * during server render and hydration, the cookie value afterwards. Reading
 * the cookie through an external store replaces the copy-into-state-in-an-
 * effect pattern and cannot mismatch the server markup.
 */
export function useSessionToken(): string | null {
  return useSyncExternalStore(subscribe, readToken, readServerToken);
}

/**
 * useHydrated is false during server render and hydration and true after,
 * which is what "still verifying the session" means on the client.
 */
export function useHydrated(): boolean {
  return useSyncExternalStore(
    subscribeNever,
    () => true,
    () => false
  );
}
