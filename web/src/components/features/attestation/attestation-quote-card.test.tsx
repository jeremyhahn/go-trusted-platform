import { act, cleanup, fireEvent, render, renderHook, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  ok,
  refused,
  stubControlPlane,
  withControlPlane,
  type Answer,
  type SentRequest,
} from '@/test/control-plane-fetch';
import { useToast } from '@/hooks';
import { AttestationQuoteCard } from './attestation-quote-card';

// #2038: GetAttestationQuote and VerifyAttestationQuote through the real SDK
// client on client.attestation, each control behind its capability.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/attestation/quotes',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const QUOTE_OP = 'POST /api/v1/attestation/quote';
const VERIFY_OP = 'POST /api/v1/attestation/quote/verify';

// The server's capabilities listing: both quote ops, off when off is set.
function caps(off = false): Answer {
  const capabilities = [QUOTE_OP, VERIFY_OP].map((op) =>
    off ? { op, kind: 'route', enabled: false, reason: 'not-configured: attestation' } : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

// The wire is protojson with lowerCamel names (protorest UseProtoNames false).
const QUOTE = {
  quoteData: 'cXVvdGU=',
  signature: 'c2ln',
  signatureAlgorithm: 'SHA256-RSAPSS',
  pcrValues: [],
  nonce: 'bm9uY2U=',
};

function routes(extra: Record<string, Answer> = {}, off = false): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(off),
    [QUOTE_OP]: ok({ status: 'ok', quote: QUOTE, channelBinding: 'Y2I=' }),
    [VERIFY_OP]: ok({ status: 'ok', verified: true }),
    ...extra,
  };
}

function posts(sent: SentRequest[], path: string) {
  return sent.filter((r) => r.method === 'POST' && r.path === path);
}

async function ready(name: string) {
  const button = await screen.findByRole('button', { name });
  await waitFor(() => expect(button.getAttribute('data-capability-enabled')).not.toBeNull());
  return button;
}

const PEM = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----';

describe('AttestationQuoteCard', () => {
  it('requests a quote with the nonce and PCR selection', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<AttestationQuoteCard />));

    const button = await ready('Get quote');
    await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('true'));
    fireEvent.change(screen.getByTestId('attestation-quote-nonce'), { target: { value: 'bm9uY2U=' } });
    fireEvent.change(screen.getByTestId('attestation-quote-pcrs'), { target: { value: '0,7' } });
    fireEvent.click(button);

    const result = await screen.findByTestId('attestation-quote-result');
    const quotes = posts(sent, '/api/v1/attestation/quote');
    expect(quotes).toHaveLength(1);
    const body = quotes[0].body as { nonce: string; config: { pcrIndices: number[] } };
    expect(body.nonce).toBe('bm9uY2U=');
    expect(body.config.pcrIndices).toEqual([0, 7]);
    expect(result.textContent).toContain('SHA256-RSAPSS');
    expect(result.textContent).toContain('Y2I=');
  });

  it('verifies a quote against the AK key and nonce', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<AttestationQuoteCard />));

    const button = await ready('Verify quote');
    await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('true'));
    fireEvent.change(screen.getByTestId('attestation-verify-quote'), { target: { value: JSON.stringify(QUOTE) } });
    fireEvent.change(screen.getByTestId('attestation-verify-ak-pem'), { target: { value: PEM } });
    fireEvent.change(screen.getByTestId('attestation-verify-nonce'), { target: { value: 'bm9uY2U=' } });
    fireEvent.click(button);

    const verdict = await screen.findByTestId('attestation-quote-verdict');
    const verifies = posts(sent, '/api/v1/attestation/quote/verify');
    expect(verifies).toHaveLength(1);
    const body = verifies[0].body as { quote: typeof QUOTE; akPublicKeyPem: string; expectedNonce: string };
    expect(body.quote).toEqual(QUOTE);
    // ak_public_key_pem is a proto bytes field: protojson wants it base64.
    expect(body.akPublicKeyPem).toBe(btoa(PEM));
    expect(body.expectedNonce).toBe('bm9uY2U=');
    expect('channelBinding' in body).toBe(false);
    expect(verdict.textContent).toContain('verified');
    expect(verdict.textContent).not.toContain('not verified');
  });

  it('shows a failed verification with the server message', async () => {
    stubControlPlane(routes({ [VERIFY_OP]: ok({ status: 'ok', verified: false, message: 'nonce mismatch' }) }));
    render(withControlPlane(<AttestationQuoteCard />));

    const button = await ready('Verify quote');
    await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('true'));
    fireEvent.change(screen.getByTestId('attestation-verify-quote'), { target: { value: JSON.stringify(QUOTE) } });
    fireEvent.change(screen.getByTestId('attestation-verify-ak-pem'), { target: { value: PEM } });
    fireEvent.change(screen.getByTestId('attestation-verify-nonce'), { target: { value: 'b3RoZXI=' } });
    fireEvent.click(button);

    const verdict = await screen.findByTestId('attestation-quote-verdict');
    expect(verdict.textContent).toContain('not verified');
    expect(verdict.textContent).toContain('nonce mismatch');
  });

  it('verifies a fetched quote with the nonce it was requested with, not the bound quote nonce', async () => {
    // The quote carries SHA-256(nonce || channelBinding); sending that bound
    // value as expectedNonce makes the server hash it again.
    const bound = { ...QUOTE, nonce: 'Ym91bmQ=' };
    const sent = stubControlPlane(routes({ [QUOTE_OP]: ok({ status: 'ok', quote: bound, channelBinding: 'Y2I=' }) }));
    render(withControlPlane(<AttestationQuoteCard />));

    const get = await ready('Get quote');
    await waitFor(() => expect(get.getAttribute('data-capability-enabled')).toBe('true'));
    fireEvent.change(screen.getByTestId('attestation-quote-nonce'), { target: { value: 'bm9uY2U=' } });
    fireEvent.click(get);
    await screen.findByTestId('attestation-quote-result');

    fireEvent.change(screen.getByTestId('attestation-verify-ak-pem'), { target: { value: PEM } });
    fireEvent.click(await ready('Verify quote'));
    await screen.findByTestId('attestation-quote-verdict');

    const verifies = posts(sent, '/api/v1/attestation/quote/verify');
    expect(verifies).toHaveLength(1);
    const body = verifies[0].body as { expectedNonce: string; channelBinding?: string };
    expect(body.expectedNonce).toBe('bm9uY2U=');
    expect(body.channelBinding).toBe('Y2I=');
  });

  it('sends the channel binding typed for an imported quote', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<AttestationQuoteCard />));

    const button = await ready('Verify quote');
    await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('true'));
    fireEvent.change(screen.getByTestId('attestation-verify-quote'), { target: { value: JSON.stringify(QUOTE) } });
    fireEvent.change(screen.getByTestId('attestation-verify-ak-pem'), { target: { value: PEM } });
    fireEvent.change(screen.getByTestId('attestation-verify-nonce'), { target: { value: 'bm9uY2U=' } });
    fireEvent.change(screen.getByTestId('attestation-verify-channel-binding'), { target: { value: 'Y2I=' } });
    fireEvent.click(button);
    await screen.findByTestId('attestation-quote-verdict');

    const verifies = posts(sent, '/api/v1/attestation/quote/verify');
    expect(verifies).toHaveLength(1);
    expect((verifies[0].body as { channelBinding?: string }).channelBinding).toBe('Y2I=');
  });

  it('keeps a fetched quote binding when the quote JSON is reformatted', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<AttestationQuoteCard />));

    const get = await ready('Get quote');
    await waitFor(() => expect(get.getAttribute('data-capability-enabled')).toBe('true'));
    fireEvent.change(screen.getByTestId('attestation-quote-nonce'), { target: { value: 'bm9uY2U=' } });
    fireEvent.click(get);
    await screen.findByTestId('attestation-quote-result');
    await waitFor(() =>
      expect((screen.getByTestId('attestation-verify-channel-binding') as HTMLInputElement).value).toBe('Y2I='),
    );

    const reordered = JSON.stringify({
      nonce: QUOTE.nonce,
      pcrValues: [],
      signatureAlgorithm: QUOTE.signatureAlgorithm,
      signature: QUOTE.signature,
      quoteData: QUOTE.quoteData,
    });
    fireEvent.change(screen.getByTestId('attestation-verify-quote'), { target: { value: reordered } });
    fireEvent.change(screen.getByTestId('attestation-verify-ak-pem'), { target: { value: PEM } });
    fireEvent.click(await ready('Verify quote'));
    await screen.findByTestId('attestation-quote-verdict');

    const verifies = posts(sent, '/api/v1/attestation/quote/verify');
    expect(verifies).toHaveLength(1);
    expect((verifies[0].body as { channelBinding?: string }).channelBinding).toBe('Y2I=');
  });

  it('reads the quote and binding from a pasted GetAttestationQuote answer', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<AttestationQuoteCard />));

    const button = await ready('Verify quote');
    await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('true'));
    fireEvent.change(screen.getByTestId('attestation-verify-quote'), {
      target: { value: JSON.stringify({ quote: QUOTE, channelBinding: 'Y2I=' }) },
    });
    fireEvent.change(screen.getByTestId('attestation-verify-ak-pem'), { target: { value: PEM } });
    fireEvent.change(screen.getByTestId('attestation-verify-nonce'), { target: { value: 'bm9uY2U=' } });
    expect((screen.getByTestId('attestation-verify-channel-binding') as HTMLInputElement).value).toBe('');
    fireEvent.click(button);
    await screen.findByTestId('attestation-quote-verdict');

    const verifies = posts(sent, '/api/v1/attestation/quote/verify');
    expect(verifies).toHaveLength(1);
    const body = verifies[0].body as { quote: typeof QUOTE; channelBinding?: string };
    expect(body.quote).toEqual(QUOTE);
    expect(body.channelBinding).toBe('Y2I=');
  });

  it('clears the previous verdict when an input changes or a verify is refused', async () => {
    const table = routes();
    stubControlPlane(table);
    render(withControlPlane(<AttestationQuoteCard />));

    const button = await ready('Verify quote');
    await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('true'));
    fireEvent.change(screen.getByTestId('attestation-verify-quote'), { target: { value: JSON.stringify(QUOTE) } });
    fireEvent.change(screen.getByTestId('attestation-verify-ak-pem'), { target: { value: PEM } });
    fireEvent.change(screen.getByTestId('attestation-verify-nonce'), { target: { value: 'bm9uY2U=' } });
    fireEvent.click(button);
    await screen.findByTestId('attestation-quote-verdict');

    // Editing an input makes the shown verdict stale.
    fireEvent.change(screen.getByTestId('attestation-verify-ak-pem'), { target: { value: `${PEM}\n` } });
    expect(screen.queryByTestId('attestation-quote-verdict')).toBeNull();

    // A verify again yields a verdict, then a refused verify must not leave it.
    fireEvent.click(button);
    await screen.findByTestId('attestation-quote-verdict');
    table[VERIFY_OP] = refused(400, 'bad key');
    fireEvent.click(button);
    await screen.findByTestId('toast');
    expect(screen.queryByTestId('attestation-quote-verdict')).toBeNull();

    // The toast store is global: dismiss this toast so it cannot leak into the next case.
    const toasts = renderHook(() => useToast()).result.current;
    act(() => toasts.toasts.forEach((t) => toasts.dismiss(t.id)));
  });

  it('withholds the controls the server does not offer', async () => {
    const sent = stubControlPlane(routes({}, true));
    render(withControlPlane(<AttestationQuoteCard />));

    for (const name of ['Get quote', 'Verify quote']) {
      const button = await ready(name);
      await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('false'));
      expect((button as HTMLButtonElement).disabled).toBe(true);
      expect(button.getAttribute('title')).toBe('not-configured: attestation');
      fireEvent.click(button);
    }
    expect(sent.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  it('shows a refused quote as a destructive toast', async () => {
    stubControlPlane(routes({ [QUOTE_OP]: refused(503, 'tpm unavailable') }));
    render(withControlPlane(<AttestationQuoteCard />));

    const button = await ready('Get quote');
    await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('true'));
    fireEvent.change(screen.getByTestId('attestation-quote-nonce'), { target: { value: 'bm9uY2U=' } });
    fireEvent.click(button);

    const toast = await screen.findByTestId('toast');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(toast.textContent).toContain('tpm unavailable');
    expect(screen.queryByTestId('attestation-quote-result')).toBeNull();
  });
});
