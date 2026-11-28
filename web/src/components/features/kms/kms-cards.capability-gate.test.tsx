import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactElement } from 'react';
import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { KmsDigestCard } from './kms-digest-card';
import { KmsKeyAdminCard } from './kms-key-admin-card';
import { DataKeyCard } from '@/app/(dashboard)/kms/data-keys/data-key-card';
import { WrappedDataKeyCard } from '@/app/(dashboard)/kms/data-keys/wrapped-data-key-card';

// #2057: every KMS control is wrapped in the capability gate on the route it
// calls, disabled with the server's reason when GET /api/v1/capabilities does
// not offer that op.

const HASH = 'POST /api/v1/kms/hash';
const HMAC = 'POST /api/v1/kms/hmac/{name}';
const VERIFY = 'POST /api/v1/kms/hmac/{name}/verify';
const STATUS = 'PUT /api/v1/kms/keys/{name}/status';
const IMPORT = 'POST /api/v1/kms/keys/import';
const DATA_KEY = 'POST /api/v1/kms/data-keys';
const WRAPPED = 'POST /api/v1/kms/data-keys/wrapped';
const KMS_OPS = [HASH, HMAC, VERIFY, STATUS, IMPORT, DATA_KEY, WRAPPED] as const;
const REASON = 'not-configured: kms';

// The server's capabilities listing: every KMS op enabled except those in off.
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

function renderCard(card: ReactElement, off: string[] = []) {
  const sent = stubControlPlane({ 'GET /api/v1/capabilities': caps(off) });
  render(withControlPlane(card));
  return sent;
}

const button = (name: string) => screen.getByRole('button', { name }) as HTMLButtonElement;
const fill = (label: string, value: string) =>
  fireEvent.change(screen.getByLabelText(label), { target: { value } });

async function expectWithheld(controls: Array<[string, string]>) {
  await waitFor(() => {
    for (const [name, op] of controls) {
      const b = button(name);
      expect(b.getAttribute('data-capability-op')).toBe(op);
      expect(b.getAttribute('data-capability-enabled')).toBe('false');
      expect(b.disabled).toBe(true);
      expect(b.title).toBe(REASON);
    }
  });
}

async function expectOffered(controls: Array<[string, string]>) {
  await waitFor(() => {
    for (const [name, op] of controls) {
      const b = button(name);
      expect(b.getAttribute('data-capability-op')).toBe(op);
      expect(b.getAttribute('data-capability-enabled')).toBe('true');
    }
  });
}

type Sent = Array<{ method: string; path: string }>;

function expectNoKmsCall(sent: Sent) {
  expect(sent.filter((s) => s.path.startsWith('/api/v1/kms/'))).toEqual([]);
}

function clickAll(controls: Array<[string, string]>) {
  for (const [name] of controls) fireEvent.click(button(name));
}

describe('KMS cards capability gate (#2057)', () => {
  it('KmsDigestCard withholds Hash the server does not offer', async () => {
    // Compute HMAC and Verify HMAC are withheld outright until the backend
    // uses a stable MAC key (#2180 round 9); kms-digest-card.hmac.test.tsx.
    const controls: Array<[string, string]> = [['Hash', HASH]];
    const fillDigest = () => {
      fill('Text to hash', 'hi');
    };

    const sent = renderCard(<KmsDigestCard />, [HASH, HMAC, VERIFY]) as Sent;
    fillDigest();
    await expectWithheld(controls);
    clickAll(controls);
    expectNoKmsCall(sent);
    cleanup();

    renderCard(<KmsDigestCard />);
    fillDigest();
    await expectOffered(controls);
  });

  it('KmsKeyAdminCard withholds Update status and Import key', async () => {
    const controls: Array<[string, string]> = [
      ['Update status', STATUS],
      ['Import key', IMPORT],
    ];
    const fillAdmin = () => {
      fill('Key name', 'k1');
      fill('New key name', 'k2');
      fill('Key material (base64)', 'AAAA');
    };

    const sent = renderCard(<KmsKeyAdminCard />, [STATUS, IMPORT]) as Sent;
    fillAdmin();
    await expectWithheld(controls);
    clickAll(controls);
    expectNoKmsCall(sent);
    cleanup();

    renderCard(<KmsKeyAdminCard />);
    fillAdmin();
    await expectOffered(controls);
  });

  it('DataKeyCard withholds Generate data key', async () => {
    const controls: Array<[string, string]> = [['Generate data key', DATA_KEY]];

    const sent = renderCard(<DataKeyCard />, [DATA_KEY]) as Sent;
    fill('Key ID', 'k1');
    await expectWithheld(controls);
    clickAll(controls);
    expectNoKmsCall(sent);
    cleanup();

    renderCard(<DataKeyCard />);
    fill('Key ID', 'k1');
    await expectOffered(controls);
  });

  it('WrappedDataKeyCard withholds Generate wrapped data key', async () => {
    const controls: Array<[string, string]> = [['Generate wrapped data key', WRAPPED]];

    const sent = renderCard(<WrappedDataKeyCard />, [WRAPPED]) as Sent;
    fill('Wrapping key ID', 'k1');
    await expectWithheld(controls);
    clickAll(controls);
    expectNoKmsCall(sent);
    cleanup();

    renderCard(<WrappedDataKeyCard />);
    fill('Wrapping key ID', 'k1');
    await expectOffered(controls);
  });
});
