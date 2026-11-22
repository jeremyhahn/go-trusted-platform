import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { KmsKeyAdminCard } from './kms-key-admin-card';

// #2057: the KMS key admin card imports base64 key material as a new key
// through the API client at the served POST /v1/kms/keys/import route; a
// refusal is toasted verbatim and keeps every field.

const IMPORT_PATH = 'POST /api/v1/kms/keys/import';
const MATERIAL = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

async function clickImport() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Import key' }));
  });
}

describe('KmsKeyAdminCard import', () => {
  it('imports a key', async () => {
    const sent = stubControlPlane({
      [IMPORT_PATH]: ok({ key_id: 'imported-1', version: 1, algorithm: 'AES-256-GCM' }),
    });
    render(withControlPlane(<KmsKeyAdminCard />));

    type('New key name', 'imported-1');
    type('Key material (base64)', MATERIAL);
    type('Usage (comma separated)', 'encrypt, decrypt');
    await clickImport();

    const toast = await screen.findByText('Key imported: imported-1 v1');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(sent).toEqual([
      {
        method: 'POST',
        path: '/api/v1/kms/keys/import',
        body: {
          name: 'imported-1',
          algorithm: 'AES-256-GCM',
          key_material: MATERIAL,
          usage: ['ENCRYPT', 'DECRYPT'],
        },
      },
    ]);
    const result = screen.getByTestId('kms-import-result');
    expect(result.textContent).toContain('imported-1');
    expect(result.textContent).toContain('AES-256-GCM');
    expect((screen.getByLabelText('Key material (base64)') as HTMLTextAreaElement).value).toBe('');
  });

  it('sends the picked algorithm and the wrapping key', async () => {
    const sent = stubControlPlane({
      [IMPORT_PATH]: ok({ key_id: 'imported-2', version: 1, algorithm: 'ED25519' }),
    });
    render(withControlPlane(<KmsKeyAdminCard />));

    type('New key name', 'imported-2');
    fireEvent.change(screen.getByLabelText('Algorithm'), { target: { value: 'ED25519' } });
    type('Key material (base64)', MATERIAL);
    type('Wrapping key ID (optional)', 'kek-1');
    await clickImport();

    await screen.findByText('Key imported: imported-2 v1');
    expect(sent).toHaveLength(1);
    const body = sent[0].body as Record<string, unknown>;
    expect(body.algorithm).toBe('ED25519');
    expect(body.wrapping_key_id).toBe('kek-1');
    expect(body).not.toHaveProperty('usage');
  });

  it('keeps Import key disabled until name and material are set', () => {
    const sent = stubControlPlane({});
    render(withControlPlane(<KmsKeyAdminCard />));

    const button = screen.getByRole('button', { name: 'Import key' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    type('New key name', 'imported-3');
    expect(button.disabled).toBe(true);
    fireEvent.click(button);
    expect(sent).toEqual([]);
  });

  it('shows an import refusal verbatim and keeps the fields', async () => {
    stubControlPlane({ [IMPORT_PATH]: refused(400, 'invalid request: unknown usage SEAL') });
    render(withControlPlane(<KmsKeyAdminCard />));

    type('New key name', 'imported-4');
    type('Key material (base64)', MATERIAL);
    type('Usage (comma separated)', 'seal');
    await clickImport();

    const toast = await screen.findByText('Import failed: invalid request: unknown usage SEAL');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect((screen.getByLabelText('Key material (base64)') as HTMLTextAreaElement).value).toBe(MATERIAL);
    expect(screen.queryByTestId('kms-import-result')).toBeNull();
  });
});
