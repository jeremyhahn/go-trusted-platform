import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_POST_ENROLLMENT_NETWORK } from 'trusted-platform-sdk';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { assignTemplateHref } from '@/lib/provisioning-assign';
import CreateProfileClient from './create-profile-client';

// #413: every input the create-from-template page collects reaches the
// POST /device/templates/{id}/create-profile body. A field the route cannot
// carry (the old Hostname input) is not rendered at all.
// #2046: opened from the sessions list's Assign Template with a session in the
// query, the page prefills the identifiers, gates its submit on the fulfil,
// and fulfils the session with the created profile.

const { query, push } = vi.hoisted(() => ({ query: { value: '' }, push: vi.fn() }));

// The submit is gated on the create-profile route; the server offers it here.
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: () => ({ enabled: true }),
  }),
}));

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: '42' }),
  usePathname: () => '/devices/templates/42/create-profile',
  useRouter: () => ({ push, back: vi.fn() }),
  useSearchParams: () => new URLSearchParams(query.value),
}));

const CREATE_PATH = '/api/v1/device/templates/42/create-profile';
const FULFIL_PATH = '/api/v1/provisioning/sessions/sess-1/fulfill';
const FULFIL_OP = 'POST /api/v1/provisioning/sessions/{sessionID}/fulfill';
const SUBMIT_SESSION = 'Create Profile and Provision Device';
const NOT_CONFIGURED = 'not-configured: provisioning';
const SESSION_QUERY = 'ekSerial=EK-0007&macAddress=02%3A00%3A00%3A00%3A00%3A07&sessionId=sess-1';

// The capabilities answer over the fulfil op; an op in `off` is offered
// disabled, with the reason a server gives for an unconfigured service.
function caps(off: string[] = []): Answer {
  const capabilities = [FULFIL_OP].map((op) =>
    off.includes(op) ? { op, kind: 'route', enabled: false, reason: NOT_CONFIGURED } : { op, kind: 'route', enabled: true }
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

async function renderPage() {
  const sent = stubControlPlane({
    'GET /api/v1/device/templates/42': ok({ id: 42, name: 'edge-node', role: 'edge' }),
    [`POST ${CREATE_PATH}`]: ok({ id: 9 }),
  });
  const { container } = render(withControlPlane(<CreateProfileClient />));
  await screen.findByRole('heading', { level: 1, name: 'Create Profile from Template' });
  return { sent, form: container.querySelector('form') as HTMLFormElement };
}

describe('CreateProfileClient request body', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    query.value = '';
    push.mockReset();
  });

  it('sends every value the form collects', async () => {
    const { sent, form } = await renderPage();

    // A distinct value per input, so each one can be found in the body.
    const inputs = Array.from(form.querySelectorAll('input'));
    expect(inputs.map((input) => input.id).sort()).toEqual(['ekSerial', 'macAddress', 'staticIp']);
    for (const input of inputs) {
      fireEvent.change(input, { target: { value: `value-of-${input.id}` } });
    }

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Create Profile' }));
    });
    await screen.findByRole('heading', { name: 'Profile Created' });

    const create = sent.find((r) => r.method === 'POST' && r.path === CREATE_PATH);
    expect(create?.body).toEqual({
      templateId: '42',
      overrides: {
        ek_serial: 'value-of-ekSerial',
        mac_address: 'value-of-macAddress',
        networks: { [DEFAULT_POST_ENROLLMENT_NETWORK]: { static_ip: 'value-of-staticIp' } },
        post_enrollment_network: DEFAULT_POST_ENROLLMENT_NETWORK,
      },
    });
    const body = JSON.stringify(create?.body);
    for (const input of inputs) {
      expect(body).toContain(`value-of-${input.id}`);
    }
  });

  it('renders no Hostname input, which the route has no field for', async () => {
    await renderPage();

    expect(screen.queryByLabelText('Hostname')).toBeNull();
    expect(screen.getByLabelText('Static IP Address')).toBeDefined();
  });

  it('sends no fulfil and no capability read without a session', async () => {
    const { sent } = await renderPage();

    expect(screen.getByRole('button', { name: 'Create Profile' })).toBeDefined();
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Create Profile' }));
    });
    await screen.findByRole('heading', { name: 'Profile Created' });

    expect(sent.some((r) => r.method === 'POST' && r.path === CREATE_PATH)).toBe(true);
    expect(sent.some((r) => r.path.endsWith('/fulfill'))).toBe(false);
    expect(sent.some((r) => r.path === '/api/v1/capabilities')).toBe(false);
  });
});

// The toast store outlives a test, so a test compares the count of success
// toasts before and after its submit rather than expecting none at all.
function provisionedToasts() {
  return screen.queryAllByTestId('toast').filter((t) => (t.textContent ?? '').startsWith('Device provisioned'))
    .length;
}

async function renderSessionPage(routes: Record<string, Answer> = {}, q = SESSION_QUERY) {
  query.value = q;
  const sent = stubControlPlane({
    'GET /api/v1/device/templates/42': ok({ id: 42, name: 'edge-node', role: 'edge' }),
    'GET /api/v1/capabilities': caps(),
    [`POST ${CREATE_PATH}`]: ok({ id: '42' }),
    ...routes,
  });
  render(withControlPlane(<CreateProfileClient />));
  await screen.findByRole('heading', { level: 1, name: 'Create Profile from Template' });
  return sent;
}

async function submitSession() {
  const button = await screen.findByRole('button', { name: SUBMIT_SESSION });
  await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('true'));
  await act(async () => {
    fireEvent.click(button);
  });
}

describe('CreateProfileClient for a provisioning session', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    query.value = '';
    push.mockReset();
  });

  it('prefills the identifiers the session reported', async () => {
    await renderSessionPage();

    expect((screen.getByLabelText('EK Serial Number') as HTMLInputElement).value).toBe('EK-0007');
    expect((screen.getByLabelText('MAC Address') as HTMLInputElement).value).toBe('02:00:00:00:00:07');
    expect(screen.getByTestId('create-profile-session').textContent).toContain('sess-1');
    expect(screen.getByRole('button', { name: SUBMIT_SESSION })).toBeDefined();
  });

  it('creates the profile, then fulfils the session with its id', async () => {
    const sent = await renderSessionPage({ [`POST ${FULFIL_PATH}`]: ok({ status: 'fulfilled' }) });

    await submitSession();

    await waitFor(() =>
      expect(sent).toContainEqual({ method: 'POST', path: FULFIL_PATH, body: { session_id: 'sess-1', profile_id: '42' } })
    );
    const createAt = sent.findIndex((r) => r.method === 'POST' && r.path === CREATE_PATH);
    const fulfilAt = sent.findIndex((r) => r.method === 'POST' && r.path === FULFIL_PATH);
    expect(createAt).toBeGreaterThanOrEqual(0);
    expect(createAt).toBeLessThan(fulfilAt);
    const create = sent[createAt].body as { overrides?: { ek_serial?: string; mac_address?: string } };
    expect(create.overrides?.ek_serial).toBe('EK-0007');
    expect(create.overrides?.mac_address).toBe('02:00:00:00:00:07');
    await waitFor(() => expect(provisionedToasts()).toBeGreaterThan(0));
    await waitFor(() => expect(push).toHaveBeenCalledWith('/provisioning/sessions/sess-1'));
  });

  it('shows a refused fulfilment as a destructive toast, not as a provisioned device', async () => {
    await renderSessionPage({
      [`POST ${FULFIL_PATH}`]: refused(400, 'configdelivery: session already fulfilled: sess-1'),
    });
    const provisionedBefore = provisionedToasts();
    const message =
      'Profile 42 was created, but the session was not fulfilled: configdelivery: session already fulfilled: sess-1';

    await submitSession();

    const toast = await screen.findByText(`Error provisioning device: ${message}`);
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(provisionedToasts()).toBe(provisionedBefore);
    expect(push).not.toHaveBeenCalledWith('/provisioning/sessions/sess-1');
    await screen.findByRole('heading', { name: 'Profile Created' });
    const alert = screen.getByTestId('create-profile-session-not-fulfilled');
    expect(alert.textContent).toContain(message);
  });

  it('fulfils nothing when the created profile has no id', async () => {
    const sent = await renderSessionPage({ [`POST ${CREATE_PATH}`]: ok({}) });
    const provisionedBefore = provisionedToasts();

    await submitSession();

    const toast = await screen.findByText(
      'Error provisioning device: The server returned no profile id, so the session was not fulfilled.'
    );
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(sent.some((r) => r.path.endsWith('/fulfill'))).toBe(false);
    expect(provisionedToasts()).toBe(provisionedBefore);
  });

  it('withholds the submit when the server does not offer the fulfil', async () => {
    const sent = await renderSessionPage({ 'GET /api/v1/capabilities': caps([FULFIL_OP]) });

    const button = await screen.findByRole('button', { name: SUBMIT_SESSION });
    await waitFor(() => {
      expect(button.getAttribute('data-capability-op')).toBe(FULFIL_OP);
      expect(button.getAttribute('data-capability-enabled')).toBe('false');
      expect(button.getAttribute('title')).toBe(NOT_CONFIGURED);
    });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    await act(async () => {
      fireEvent.click(button);
    });

    expect(sent.some((r) => r.method === 'POST')).toBe(false);
  });

  // Codex P1 on #2367: a reported EK serial with reserved characters must not
  // steer the fulfil to another session.
  it('prefills a reserved-character EK serial and still fulfils the one session', async () => {
    const href = assignTemplateHref('42', {
      id: 'sess-1',
      ek_serial: 'EK&sessionId=other-session',
      mac_address: '02:00:00:00:00:07',
    });
    const sent = await renderSessionPage(
      { [`POST ${FULFIL_PATH}`]: ok({ status: 'fulfilled' }) },
      new URL(href, 'http://x').search.slice(1)
    );

    expect((screen.getByLabelText('EK Serial Number') as HTMLInputElement).value).toBe('EK&sessionId=other-session');
    await submitSession();

    await waitFor(() => expect(sent.some((r) => r.method === 'POST' && r.path === FULFIL_PATH)).toBe(true));
    expect(sent.some((r) => r.path.includes('other-session'))).toBe(false);
  });

  it('refuses a link that names more than one session', async () => {
    const sent = await renderSessionPage({}, 'ekSerial=EK-0007&sessionId=other-session&sessionId=sess-1');

    expect(screen.getByTestId('create-profile-session-ambiguous')).toBeDefined();
    expect(screen.queryByTestId('create-profile-session')).toBeNull();
    const button = screen.getByRole('button', { name: SUBMIT_SESSION }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    await act(async () => {
      fireEvent.click(button);
      fireEvent.submit(button.closest('form') as HTMLFormElement);
    });

    expect(sent.some((r) => r.method === 'POST')).toBe(false);
  });
});
