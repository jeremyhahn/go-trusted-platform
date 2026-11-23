import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { ManifestDeleteButton } from './manifest-delete-button';

// #2038: DeleteManifest (DELETE /api/v1/attestation/manifests/{id}) is sent
// through the real SDK client on client.attestation, only after a confirm,
// and only when the server offers the route.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/attestation/manifests',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const OP = 'DELETE /api/v1/attestation/manifests/{id}';

// The server's capabilities listing: the delete op, off when off is set.
function caps(off = false): Answer {
  const capabilities = [
    off ? { op: OP, kind: 'route', enabled: false, reason: 'not-configured: attestation' } : { op: OP, kind: 'route', enabled: true },
  ];
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function routes(extra: Record<string, Answer> = {}, off = false): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(off),
    'DELETE /api/v1/attestation/manifests/m-1': ok({ status: 'deleted' }),
    ...extra,
  };
}

function deletes(sent: { method: string; path: string }[]) {
  return sent.filter((r) => r.method === 'DELETE');
}

async function enabledButton() {
  const button = await screen.findByRole('button', { name: 'Delete manifest' });
  await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('true'));
  return button;
}

describe('ManifestDeleteButton', () => {
  it('deletes only after the confirm', async () => {
    const sent = stubControlPlane(routes());
    const onDeleted = vi.fn();
    render(withControlPlane(<ManifestDeleteButton id="m-1" label="host-a" onDeleted={onDeleted} />));

    fireEvent.click(await enabledButton());
    expect(await screen.findByText('Delete manifest?')).toBeTruthy();
    expect(screen.getByRole('dialog').textContent).toContain('host-a');
    expect(deletes(sent)).toHaveLength(0);

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(onDeleted).toHaveBeenCalledTimes(1));
    expect(deletes(sent).map((r) => r.path)).toEqual(['/api/v1/attestation/manifests/m-1']);
    const toast = await screen.findByTestId('toast');
    expect(toast.getAttribute('data-variant')).not.toBe('destructive');
    expect(toast.textContent).toContain('Manifest deleted');
  });

  it('encodes the manifest id in the path', async () => {
    const sent = stubControlPlane(routes({ 'DELETE /api/v1/attestation/manifests/a%2Fb': ok({ status: 'deleted' }) }));
    const onDeleted = vi.fn();
    render(withControlPlane(<ManifestDeleteButton id="a/b" label="host-b" onDeleted={onDeleted} />));

    fireEvent.click(await enabledButton());
    fireEvent.click(await screen.findByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(onDeleted).toHaveBeenCalledTimes(1));
    expect(deletes(sent).map((r) => r.path)).toEqual(['/api/v1/attestation/manifests/a%2Fb']);
  });

  it('withholds the control the server does not offer', async () => {
    const sent = stubControlPlane(routes({}, true));
    const onDeleted = vi.fn();
    render(withControlPlane(<ManifestDeleteButton id="m-1" label="host-a" onDeleted={onDeleted} />));

    const button = await screen.findByRole('button', { name: 'Delete manifest' });
    await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('false'));
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(button.getAttribute('title')).toBe('not-configured: attestation');
    fireEvent.click(button);
    expect(screen.queryByText('Delete manifest?')).toBeNull();
    expect(deletes(sent)).toHaveLength(0);
    expect(onDeleted).not.toHaveBeenCalled();
  });

  it('shows a refused delete as a destructive toast', async () => {
    stubControlPlane(routes({ 'DELETE /api/v1/attestation/manifests/m-1': refused(404, 'manifest not found') }));
    const onDeleted = vi.fn();
    render(withControlPlane(<ManifestDeleteButton id="m-1" label="host-a" onDeleted={onDeleted} />));

    fireEvent.click(await enabledButton());
    fireEvent.click(await screen.findByRole('button', { name: 'Delete' }));
    const toast = await screen.findByTestId('toast');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(toast.textContent).toContain('manifest not found');
    expect(onDeleted).not.toHaveBeenCalled();
  });
});
