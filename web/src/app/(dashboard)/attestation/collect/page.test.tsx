import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import CollectAttestationPage from './page';

// #2038: the collect page sends CollectHostAttestation,
// CollectVMAttestation and CollectContainerAttestation through the real SDK
// client on client.attestation, each button gated on its server route.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/attestation/collect',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const HOST = 'POST /api/v1/attestation/host';
const VM = 'POST /api/v1/attestation/vm/{id}';
const CONTAINER = 'POST /api/v1/attestation/container/{id}';

// The server's capabilities listing: the three collect ops, those in off turned off.
function caps(off: string[] = []): Answer {
  const capabilities = [HOST, VM, CONTAINER].map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: attestation' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function routes(extra: Record<string, Answer> = {}, off: string[] = []): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(off),
    'POST /api/v1/attestation/host': ok({
      status: { success: true, message: 'ok' },
      attestation: {
        quoteData: 'cXVvdGU=',
        signature: 'c2ln',
        signatureAlgorithm: 'ES256',
        pcrs: [{ index: 0, value: 'AAAA', algorithm: 'sha256' }],
        pcrDigest: 'ZGln',
        nonce: 'bm9uY2U=',
        timestamp: '2026-11-01T00:00:00Z',
        akPublicKey: 'YWs=',
        hashAlgorithm: 'sha256',
      },
    }),
    'POST /api/v1/attestation/vm/vm-1': ok({
      status: { success: true, message: 'ok' },
      attestation: {
        vmId: 'vm-1',
        hostId: 'host-1',
        quoteData: 'cXVvdGU=',
        signature: 'c2ln',
        signatureAlgorithm: 'ES256',
        pcrs: [],
        pcrDigest: 'ZGln',
        nonce: 'bm9uY2U=',
        timestamp: '2026-11-01T00:00:00Z',
        hashAlgorithm: 'ATTESTATION_HASH_ALGORITHM_SHA256',
      },
    }),
    'POST /api/v1/attestation/container/c-1': ok({
      status: { success: true, message: 'ok' },
      attestation: {
        containerId: 'c-1',
        imageId: 'img-1',
        imageDigest: 'sha256:00',
        digest: 'ZGln',
        pcrValue: 'cGNy',
        timestamp: '2026-11-01T00:00:00Z',
      },
    }),
    ...extra,
  };
}

function posts(sent: { method: string; path: string }[]) {
  return sent.filter((r) => r.method === 'POST' && r.path.startsWith('/api/v1/attestation/'));
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

async function enabled(name: string): Promise<HTMLButtonElement> {
  const b = (await screen.findByRole('button', { name })) as HTMLButtonElement;
  await waitFor(() => expect(b.getAttribute('data-capability-enabled')).toBe('true'));
  return b;
}

function type(card: HTMLElement, label: string, value: string) {
  fireEvent.change(within(card).getByLabelText(label), { target: { value } });
}

describe('CollectAttestationPage', () => {
  it('collects the host attestation with the nonce and PCR selection', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<CollectAttestationPage />));

    const go = await enabled('Collect host attestation');
    const card = screen.getByTestId('attestation-collect-host');
    type(card, 'Nonce (base64)', 'bm9uY2U=');
    type(card, 'PCR indices', '0,7');
    fireEvent.click(go);

    const result = await screen.findByTestId('attestation-collect-host-result');
    const host = posts(sent).filter((r) => r.path === '/api/v1/attestation/host');
    expect(host).toHaveLength(1);
    const body = (host[0] as unknown as { body: { nonce: string; config: { pcrIndices: number[] } } }).body;
    expect(body.nonce).toBe('bm9uY2U=');
    expect(body.config.pcrIndices).toEqual([0, 7]);
    expect(result.textContent).toContain('ZGln');
    expect(result.textContent).toContain('ES256');
    expect(within(result).getAllByTestId('attestation-collect-host-pcr')).toHaveLength(1);
  });

  it('collects a VM attestation by id', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<CollectAttestationPage />));

    const go = await enabled('Collect VM attestation');
    const card = screen.getByTestId('attestation-collect-vm');
    type(card, 'VM ID', 'vm-1');
    type(card, 'Nonce (base64)', 'bm9uY2U=');
    fireEvent.click(go);

    const result = await screen.findByTestId('attestation-collect-vm-result');
    expect(posts(sent).filter((r) => r.path === '/api/v1/attestation/vm/vm-1')).toHaveLength(1);
    expect(result.textContent).toContain('vm-1');
    expect(result.textContent).toContain('host-1');
    expect(result.textContent).toContain('ZGln');
    // Collecting evidence is not verifying it: the answer has no verdict.
    expect(result.textContent).not.toContain('erified');
  });

  it('collects a container attestation by id', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<CollectAttestationPage />));

    const go = await enabled('Collect container attestation');
    const card = screen.getByTestId('attestation-collect-container');
    type(card, 'Container ID', 'c-1');
    fireEvent.click(go);

    const result = await screen.findByTestId('attestation-collect-container-result');
    expect(posts(sent).filter((r) => r.path === '/api/v1/attestation/container/c-1')).toHaveLength(1);
    expect(result.textContent).toContain('c-1');
    expect(result.textContent).toContain('sha256:00');
    expect(result.textContent).toContain('cGNy');
    expect(result.textContent).not.toContain('erified');
  });

  it('needs an id and a nonce before it sends', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<CollectAttestationPage />));

    await enabled('Collect host attestation');
    const vm = button('Collect VM attestation');
    const container = button('Collect container attestation');
    const vmCard = screen.getByTestId('attestation-collect-vm');
    const containerCard = screen.getByTestId('attestation-collect-container');

    expect(vm.disabled).toBe(true);
    type(vmCard, 'VM ID', 'vm-1');
    expect(vm.disabled).toBe(true);
    fireEvent.click(vm);
    type(vmCard, 'Nonce (base64)', 'bm9uY2U=');
    await waitFor(() => expect(vm.disabled).toBe(false));

    expect(container.disabled).toBe(true);
    fireEvent.click(container);
    type(containerCard, 'Container ID', 'c-1');
    await waitFor(() => expect(container.disabled).toBe(false));

    expect(posts(sent)).toHaveLength(0);
  });

  it('withholds each control the server does not offer', async () => {
    const sent = stubControlPlane(routes({}, [HOST, VM, CONTAINER]));
    render(withControlPlane(<CollectAttestationPage />));

    for (const name of ['Collect host attestation', 'Collect VM attestation', 'Collect container attestation']) {
      const b = (await screen.findByRole('button', { name })) as HTMLButtonElement;
      await waitFor(() => expect(b.getAttribute('data-capability-enabled')).toBe('false'));
      expect(b.disabled).toBe(true);
      expect(b.getAttribute('title')).toBe('not-configured: attestation');
    }
    type(screen.getByTestId('attestation-collect-vm'), 'VM ID', 'vm-1');
    type(screen.getByTestId('attestation-collect-vm'), 'Nonce (base64)', 'bm9uY2U=');
    type(screen.getByTestId('attestation-collect-container'), 'Container ID', 'c-1');
    fireEvent.click(button('Collect host attestation'));
    fireEvent.click(button('Collect VM attestation'));
    fireEvent.click(button('Collect container attestation'));
    expect(posts(sent)).toHaveLength(0);
  });

  it('shows a refused collect as the server message', async () => {
    stubControlPlane(routes({ 'POST /api/v1/attestation/vm/vm-1': refused(404, 'vm not found') }));
    render(withControlPlane(<CollectAttestationPage />));

    const go = await enabled('Collect VM attestation');
    const card = screen.getByTestId('attestation-collect-vm');
    type(card, 'VM ID', 'vm-1');
    type(card, 'Nonce (base64)', 'bm9uY2U=');
    fireEvent.click(go);

    const alert = await within(card).findByRole('alert');
    expect(alert.textContent).toContain('vm not found');
    expect(screen.queryByTestId('attestation-collect-vm-result')).toBeNull();
  });
});
