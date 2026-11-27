import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { type Answer, ok, type SentRequest, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { BMCCertCard } from './bmc-cert-card';

// The webservice's BMC certificate route ops. The capabilities stub offers all
// three, so the tests show the card holds every ceremony back on its own.
const ENROLL_OP = 'POST /api/v1/bmc/{profileID:[0-9]+}/enroll';
const RESTORE_OP = 'POST /api/v1/bmc/{profileID:[0-9]+}/cert/restore';
const REPLACE_OP = 'PUT /api/v1/bmc/{profileID:[0-9]+}/cert';

/** caps answers the capabilities listing: every op enabled unless it is a key of off (value = reason). */
function caps(off: Record<string, string> = {}): Answer {
  const capabilities = [ENROLL_OP, RESTORE_OP, REPLACE_OP].map((op) =>
    op in off ? { op, kind: 'route', enabled: false, reason: off[op] } : { op, kind: 'route', enabled: true }
  );
  return ok({
    capabilities,
    total: capabilities.length,
    enabled: capabilities.filter((c) => c.enabled).length,
  });
}

function stub(routes: Record<string, Answer>, off: Record<string, string> = {}): SentRequest[] {
  return stubControlPlane({ 'GET /api/v1/capabilities': caps(off), ...routes });
}

/** bmc drops the capabilities fetch, leaving the card's own requests. */
function bmc(sent: SentRequest[]): SentRequest[] {
  return sent.filter((r) => r.path !== '/api/v1/capabilities');
}

describe('BMCCertCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('offers no certificate control while the server cannot carry the trust pin across a change', async () => {
    const sent = stub({});
    render(withControlPlane(<BMCCertCard profileID="42" />));

    const heldBack = await screen.findByTestId('bmc-cert-held-back');
    expect(heldBack.textContent).toBe(
      'Enrolment, web certificate replacement and factory certificate restore are unavailable until the server carries the BMC trust pin across a certificate change.'
    );
    expect(screen.queryByRole('button', { name: 'Restore factory certificate' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Enroll' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Replace web certificate' })).toBeNull();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.querySelectorAll('[data-capability-op]').length).toBe(0);
    expect(bmc(sent)).toEqual([]);
  });
});
