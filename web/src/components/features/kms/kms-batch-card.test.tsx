import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { KmsBatchCard } from './kms-batch-card';

// #2057: the last KeyManagementService operations without a UI. The card runs
// BatchEncrypt, BatchDecrypt and Rewrap through the SDK KMSService, each
// control wrapped in the capability gate on the route it calls.

const BATCH_ENCRYPT = 'POST /api/v1/kms/batch-encrypt';
const BATCH_DECRYPT = 'POST /api/v1/kms/batch-decrypt';
const REWRAP = 'POST /api/v1/kms/rewrap';
const KMS_OPS = [BATCH_ENCRYPT, BATCH_DECRYPT, REWRAP] as const;
const REASON = 'not-configured: kms';

// The server's capabilities listing: every op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = KMS_OPS.map((op) =>
    off.includes(op) ? { op, kind: 'route', enabled: false, reason: REASON } : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderCard(routes: Record<string, Answer> = {}, off: string[] = []) {
  const sent = stubControlPlane({ 'GET /api/v1/capabilities': caps(off), ...routes });
  render(withControlPlane(<KmsBatchCard />));
  return sent;
}

const button = (name: string) => screen.getByRole('button', { name }) as HTMLButtonElement;
const fill = (label: string, value: string) =>
  fireEvent.change(screen.getByLabelText(label), { target: { value } });

async function clickWhenOffered(name: string, op: string) {
  await waitFor(() => {
    const b = button(name);
    expect(b.getAttribute('data-capability-op')).toBe(op);
    expect(b.getAttribute('data-capability-enabled')).toBe('true');
    expect(b.disabled).toBe(false);
  });
  fireEvent.click(button(name));
}

describe('KmsBatchCard (#2057)', () => {
  it('batch-encrypts one item per line', async () => {
    const sent = renderCard({
      [BATCH_ENCRYPT]: ok({
        key_id: 'payments',
        results: [
          { item_id: 'item-1', ciphertext: 'Y3Qx', nonce: 'bjE=' },
          { item_id: 'item-2', error: 'refused' },
        ],
        success_count: 1,
        failure_count: 1,
      }),
    });
    fill('Key name', 'payments');
    fill('Items (one per line)', 'alpha\nbeta');
    await clickWhenOffered('Batch encrypt', BATCH_ENCRYPT);

    await screen.findByText('1 succeeded, 1 failed');
    expect(screen.getByText('Y3Qx')).toBeTruthy();
    expect(screen.getByText('refused')).toBeTruthy();
    const call = sent.find((s) => s.method === 'POST' && s.path === '/api/v1/kms/batch-encrypt');
    expect(call?.body).toEqual({
      key_id: 'payments',
      items: [
        { item_id: 'item-1', plaintext: btoa('alpha') },
        { item_id: 'item-2', plaintext: btoa('beta') },
      ],
    });
  });

  it('batch-decrypts ciphertext and nonce lines', async () => {
    const sent = renderCard({
      [BATCH_DECRYPT]: ok({
        key_id: 'payments',
        results: [{ item_id: 'item-1', plaintext: 'YWxwaGE=' }],
        success_count: 1,
        failure_count: 0,
      }),
    });
    fill('Key name', 'payments');
    fill('Items (one per line)', 'Y3Qx bjE=');
    await clickWhenOffered('Batch decrypt', BATCH_DECRYPT);

    await screen.findByText('1 succeeded, 0 failed');
    expect(screen.getByText('alpha')).toBeTruthy();
    const call = sent.find((s) => s.method === 'POST' && s.path === '/api/v1/kms/batch-decrypt');
    expect(call?.body).toEqual({
      key_id: 'payments',
      items: [{ item_id: 'item-1', ciphertext: 'Y3Qx', nonce: 'bjE=' }],
    });
  });

  it("rewraps a ciphertext under the key's current version", async () => {
    const sent = renderCard({
      [REWRAP]: ok({
        source_key_id: 'payments',
        destination_key_id: 'payments',
        source_key_version: 1,
        dest_key_version: 2,
        ciphertext: 'bmV3Y3Q=',
        nonce: 'bjI=',
      }),
    });
    fill('Key name', 'payments');
    fill('Ciphertext', 'Y3Qx');
    fill('Nonce (optional)', 'bjE=');
    await clickWhenOffered('Rewrap', REWRAP);

    await screen.findByText('bmV3Y3Q=');
    expect(screen.getByTestId('kms-rewrap-version').textContent).toContain('2');
    const call = sent.find((s) => s.method === 'POST' && s.path === '/api/v1/kms/rewrap');
    expect(call?.body).toEqual({ source_key_id: 'payments', ciphertext: 'Y3Qx', source_nonce: 'bjE=' });
  });

  it('withholds the operations the server does not offer', async () => {
    const sent = renderCard({}, [...KMS_OPS]);
    fill('Key name', 'payments');
    fill('Items (one per line)', 'alpha');
    fill('Ciphertext', 'Y3Qx');
    const controls: Array<[string, string]> = [
      ['Batch encrypt', BATCH_ENCRYPT],
      ['Batch decrypt', BATCH_DECRYPT],
      ['Rewrap', REWRAP],
    ];
    await waitFor(() => {
      for (const [name, op] of controls) {
        const b = button(name);
        expect(b.getAttribute('data-capability-op')).toBe(op);
        expect(b.getAttribute('data-capability-enabled')).toBe('false');
        expect(b.disabled).toBe(true);
        expect(b.title).toBe(REASON);
      }
    });
    for (const [name] of controls) fireEvent.click(button(name));
    expect(sent.filter((s) => s.path.startsWith('/api/v1/kms/'))).toEqual([]);
  });

  it('shows a refused batch as a destructive toast', async () => {
    renderCard({ [BATCH_ENCRYPT]: refused(400, 'item context is not supported') });
    fill('Key name', 'payments');
    fill('Items (one per line)', 'alpha');
    await clickWhenOffered('Batch encrypt', BATCH_ENCRYPT);

    const toast = await screen.findByTestId('toast');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(toast.textContent).toContain('KMS request failed');
    expect(toast.textContent).toContain('item context is not supported');
  });
});
