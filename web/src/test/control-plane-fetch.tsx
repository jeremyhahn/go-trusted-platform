import type { ReactNode } from 'react';
import { vi } from 'vitest';
import { PlatformProvider } from 'trusted-platform-sdk';

import { useToast } from '@/hooks/use-toast';

/** One request the SDK client sent through the stubbed fetch. */
export interface SentRequest {
  method: string;
  path: string;
  body: unknown;
}

/** A canned control-plane answer: an HTTP status and its JSON body. */
export interface Answer {
  status: number;
  body: unknown;
}

/** The control plane's success envelope around payload. */
export function ok(payload: unknown): Answer {
  return { status: 200, body: { code: 200, success: true, payload } };
}

/** The control plane's error envelope carrying message. */
export function refused(status: number, message: string): Answer {
  return { status, body: { code: status, success: false, error: message } };
}

/**
 * stubControlPlane replaces fetch with a router over "METHOD /path" keys,
 * so a component test drives the real SDK client across the same boundary
 * the browser crosses. A request with no route answers 404. Every request
 * is recorded in the returned list.
 */
export function stubControlPlane(routes: Record<string, Answer>): SentRequest[] {
  const sent: SentRequest[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const method = (init?.method ?? 'GET').toUpperCase();
      const body = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
      sent.push({ method, path: url.pathname, body });

      const answer = routes[`${method} ${url.pathname}`] ?? refused(404, `no route for ${method} ${url.pathname}`);
      return new Response(JSON.stringify(answer.body), {
        status: answer.status,
        headers: { 'Content-Type': 'application/json' },
      });
    })
  );
  return sent;
}

/** ToastProbe renders the live toasts so a test can read what the operator saw. */
export function ToastProbe() {
  const { toasts } = useToast();
  return (
    <ul>
      {toasts.map((t) => (
        <li key={t.id} data-testid="toast" data-variant={t.variant ?? 'default'}>
          {t.title}: {t.description}
        </li>
      ))}
    </ul>
  );
}

/** withControlPlane mounts children on an SDK client pointed at the stub. */
export function withControlPlane(children: ReactNode) {
  return (
    <PlatformProvider config={{ baseUrl: 'https://control-plane.test/api' }}>
      <>
        {children}
        <ToastProbe />
      </>
    </PlatformProvider>
  );
}
