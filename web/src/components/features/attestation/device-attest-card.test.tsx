import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { DeviceAttestCard } from './device-attest-card';

// #2048: the device page reaches IssueAttestationChallenge and AttestDevice
// through the real SDK client; both controls are capability-gated and a
// refusal reaches the operator verbatim.

const CHALLENGE_OP = 'POST /api/v1/devices/{id}/attest/challenge';
const ATTEST_OP = 'POST /api/v1/devices/{id}/attest';

// The server's capabilities listing for the two attestation ops.
function caps(enabled = true): Answer {
  const capabilities = [CHALLENGE_OP, ATTEST_OP].map((op) =>
    enabled ? { op, kind: 'route', enabled: true } : { op, kind: 'route', enabled: false, reason: 'unimplemented' },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

const CHALLENGE = ok({ challenge_id: 'ch-1', nonce: 'bm9uY2U=', expires_at: '2026-11-23T12:05:00Z' });

const VERDICT = ok({
  device_id: '7',
  verified: false,
  signature_valid: true,
  nonce_valid: true,
  pcrs_valid: false,
  ak_certificate_verified: true,
  attestation_status: 'failed',
  message: 'PCR 7 differs from the baseline',
  attested_at: '2026-11-23T12:01:00Z',
  pcr_baseline_captured: false,
});

function routes(overrides: Record<string, Answer> = {}): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
    'POST /api/v1/devices/7/attest/challenge': CHALLENGE,
    'POST /api/v1/devices/7/attest': VERDICT,
    ...overrides,
  };
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

async function issueChallenge() {
  const button = await screen.findByRole('button', { name: 'Issue challenge' });
  await waitFor(() => expect(button.hasAttribute('disabled')).toBe(false));
  await click('Issue challenge');
}

function enterEvidence(value: string) {
  fireEvent.change(screen.getByLabelText('Evidence (base64)'), { target: { value } });
}

describe('DeviceAttestCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('issues a challenge, then sends the evidence with its challenge_id and shows each check', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<DeviceAttestCard deviceId="7" />));

    await issueChallenge();
    expect((await screen.findByTestId('device-attest-nonce')).textContent).toBe('bm9uY2U=');
    expect(screen.getByTestId('device-attest-expires')).toBeTruthy();

    enterEvidence('ZXZpZGVuY2U=');
    await click('Verify evidence');

    expect(sent).toContainEqual({
      method: 'POST',
      path: '/api/v1/devices/7/attest',
      body: { evidence: 'ZXZpZGVuY2U=', challenge_id: 'ch-1' },
    });
    expect((await screen.findByTestId('device-attest-verdict')).textContent).toBe('Not verified');
    expect(screen.getByTestId('device-attest-check-signature').getAttribute('data-passed')).toBe('true');
    expect(screen.getByTestId('device-attest-check-nonce').getAttribute('data-passed')).toBe('true');
    expect(screen.getByTestId('device-attest-check-pcrs').getAttribute('data-passed')).toBe('false');
    expect(screen.getByTestId('device-attest-check-ak').getAttribute('data-passed')).toBe('true');
    expect(screen.getByText('PCR 7 differs from the baseline')).toBeTruthy();
  });

  it('keeps Verify evidence disabled until a challenge is issued and evidence is entered, and consumes the challenge', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<DeviceAttestCard deviceId="7" />));

    const verify = () => screen.getByRole('button', { name: 'Verify evidence' });
    await screen.findByRole('button', { name: 'Issue challenge' });
    expect(verify().hasAttribute('disabled')).toBe(true);

    await issueChallenge();
    await screen.findByTestId('device-attest-nonce');
    expect(verify().hasAttribute('disabled')).toBe(true);

    enterEvidence('ZXZpZGVuY2U=');
    await waitFor(() => expect(verify().hasAttribute('disabled')).toBe(false));
    await click('Verify evidence');

    await screen.findByTestId('device-attest-verdict');
    expect(screen.queryByTestId('device-attest-nonce')).toBeNull();
    expect(verify().hasAttribute('disabled')).toBe(true);
  });

  it('shows a refused challenge and sends no attest', async () => {
    const sent = stubControlPlane(
      routes({ 'POST /api/v1/devices/7/attest/challenge': refused(404, 'device 7 not found') }),
    );
    render(withControlPlane(<DeviceAttestCard deviceId="7" />));

    await issueChallenge();
    expect((await screen.findByTestId('device-attest-refusal')).textContent).toContain('device 7 not found');
    expect(sent.some((r) => r.path === '/api/v1/devices/7/attest')).toBe(false);
  });

  it('shows a refused verification and keeps no verdict', async () => {
    stubControlPlane(routes({ 'POST /api/v1/devices/7/attest': refused(400, 'challenge ch-1 expired') }));
    render(withControlPlane(<DeviceAttestCard deviceId="7" />));

    await issueChallenge();
    await screen.findByTestId('device-attest-nonce');
    enterEvidence('ZXZpZGVuY2U=');
    await click('Verify evidence');

    expect((await screen.findByTestId('device-attest-refusal')).textContent).toContain('challenge ch-1 expired');
    expect(screen.queryByTestId('device-attest-verdict')).toBeNull();
  });

  it("withholds both controls with the server's reason when the routes are not offered", async () => {
    const sent = stubControlPlane(routes({ 'GET /api/v1/capabilities': caps(false) }));
    render(withControlPlane(<DeviceAttestCard deviceId="7" />));

    const issue = await screen.findByRole('button', { name: 'Issue challenge' });
    await waitFor(() => expect(issue.getAttribute('title')).toBe('unimplemented'));
    expect(issue.hasAttribute('disabled')).toBe(true);
    expect(issue.getAttribute('data-capability-op')).toBe(CHALLENGE_OP);
    const verify = screen.getByRole('button', { name: 'Verify evidence' });
    expect(verify.getAttribute('data-capability-op')).toBe(ATTEST_OP);
    expect(verify.hasAttribute('disabled')).toBe(true);
    expect(sent.some((r) => r.method === 'POST')).toBe(false);
  });
});
