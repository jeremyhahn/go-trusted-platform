import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import SessionDetailClient from './session-detail-client';

// #2046: the session page reads the session through GET
// /provisioning/sessions/{id} and fulfils it through POST
// /provisioning/sessions/{id}/fulfill with the profile it created. A refused
// fulfilment, or a created profile without an id, reaches the operator as a
// destructive toast, not as a provisioned device.

vi.mock('next/navigation', () => ({
  useParams: () => ({ sessionId: 'sess-1' }),
  usePathname: () => '/provisioning/sessions/sess-1',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

// Radix Select does not open in jsdom, so the test picks a template through a
// native select carrying the same value and onValueChange.
vi.mock('@/components/ui/select', () => ({
  Select: ({
    value,
    onValueChange,
    children,
  }: {
    value?: string;
    onValueChange?: (value: string) => void;
    children?: ReactNode;
  }) => (
    <select value={value} onChange={(e) => onValueChange?.(e.target.value)}>
      <option value="" />
      {children}
    </select>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: { children?: ReactNode }) => <>{children}</>,
  SelectItem: ({ value, children }: { value: string; children?: ReactNode }) => (
    <option value={value}>{children}</option>
  ),
}));

const SESSION_PATH = 'GET /api/v1/provisioning/sessions/sess-1';
const PROFILES_PATH = 'POST /api/v1/device/profiles';
const FULFIL_PATH = 'POST /api/v1/provisioning/sessions/sess-1/fulfill';
const SUBMIT = 'Create Profile and Provision Device';
const TEMPLATES_PATH = 'GET /api/v1/device/templates';
const FROM_TEMPLATE_PATH = 'POST /api/v1/device/templates/7/create-profile';
const READ_OP = 'GET /api/v1/provisioning/sessions/{sessionID}';
const FULFIL_OP = 'POST /api/v1/provisioning/sessions/{sessionID}/fulfill';
const NOT_CONFIGURED = 'not-configured: provisioning';

// The capabilities answer over the two ops this page uses; an op in `off` is
// offered disabled, with the reason a server gives for an unconfigured service.
function caps(off: string[] = []): Answer {
  const capabilities = [READ_OP, FULFIL_OP].map((op) =>
    off.includes(op) ? { op, kind: 'route', enabled: false, reason: NOT_CONFIGURED } : { op, kind: 'route', enabled: true }
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function storedSession(fulfilled: boolean): Answer {
  return ok({
    id: 'sess-1',
    ek_serial: 'EK-0007',
    mac_address: 'aa:bb:cc:dd:ee:07',
    fulfilled,
    created_at: '2026-11-20T00:00:00Z',
    expires_at: '2999-01-01T00:00:00Z',
  });
}

function baseRoutes(): Record<string, Answer> {
  return {
    [SESSION_PATH]: storedSession(false),
    [TEMPLATES_PATH]: ok([]),
    'GET /api/v1/capabilities': caps(),
  };
}

function templateRoutes(): Record<string, Answer> {
  return {
    ...baseRoutes(),
    [TEMPLATES_PATH]: ok({ templates: [{ id: '7', name: 'edge-gw', role: 'gateway' }] }),
  };
}

/** The control plane's Success201 envelope around payload. */
function created(payload: unknown): Answer {
  return { status: 201, body: { code: 201, success: true, payload } };
}

async function renderPage() {
  render(withControlPlane(<SessionDetailClient />));
  await screen.findByRole('heading', { level: 1, name: 'Provisioning Session' });
}

async function submitCustomProfile() {
  fireEvent.mouseDown(screen.getByRole('tab', { name: 'Custom Profile' }), { button: 0 });
  fireEvent.change(await screen.findByLabelText('Profile Name'), { target: { value: 'rack-07' } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: SUBMIT }));
  });
}

// The template tab is the default one.
async function submitTemplate() {
  await screen.findByRole('option', { name: 'edge-gw — gateway' });
  fireEvent.change(screen.getByRole('combobox'), { target: { value: '7' } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: SUBMIT }));
  });
}

// The toast store outlives a test, so a test compares the count of success
// toasts before and after its submit rather than expecting none at all.
function provisionedToasts() {
  return screen.queryAllByTestId('toast').filter((t) => (t.textContent ?? '').startsWith('Device provisioned'))
    .length;
}

describe('SessionDetailClient', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('reads the session through GET /provisioning/sessions/{id} and shows what the device reported', async () => {
    const sent = stubControlPlane(baseRoutes());
    await renderPage();

    expect(screen.getAllByText('EK-0007').length).toBeGreaterThan(0);
    expect(screen.getAllByText('aa:bb:cc:dd:ee:07').length).toBeGreaterThan(0);
    expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/provisioning/sessions/sess-1', body: undefined });
  });

  it('creates the custom profile, then fulfils the session with its id', async () => {
    const routes: Record<string, Answer> = {
      ...baseRoutes(),
      [PROFILES_PATH]: ok({ status: 'active', profile: { id: '42', name: 'rack-07' } }),
      [FULFIL_PATH]: ok({ status: 'fulfilled' }),
    };
    const sent = stubControlPlane(routes);
    await renderPage();

    // The control plane records the fulfilment; the re-read returns it.
    routes[SESSION_PATH] = storedSession(true);
    await submitCustomProfile();

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'POST',
        path: '/api/v1/device/profiles',
        body: expect.objectContaining({ name: 'rack-07', ek_serial: 'EK-0007' }),
      })
    );
    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'POST',
        path: '/api/v1/provisioning/sessions/sess-1/fulfill',
        body: { session_id: 'sess-1', profile_id: '42' },
      })
    );
    expect(await screen.findByRole('heading', { name: 'Device Provisioned' })).toBeDefined();
    expect(screen.getByRole('button', { name: 'View Profile' })).toBeDefined();
  });

  it('shows a refused fulfilment as a destructive toast, not as a provisioned device', async () => {
    stubControlPlane({
      ...baseRoutes(),
      [PROFILES_PATH]: ok({ status: 'active', profile: { id: '42', name: 'rack-07' } }),
      [FULFIL_PATH]: refused(400, 'configdelivery: session already fulfilled: sess-1'),
    });
    await renderPage();
    const provisionedBefore = provisionedToasts();

    await submitCustomProfile();

    const toast = await screen.findByText(
      'Error creating profile: Profile 42 was created, but the session was not fulfilled: configdelivery: session already fulfilled: sess-1'
    );
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByRole('heading', { name: 'Device Provisioned' })).toBeNull();
    expect(provisionedToasts()).toBe(provisionedBefore);
    expect(screen.getByRole('button', { name: SUBMIT })).toBeDefined();
  });

  it('fulfils nothing and says so when the created profile has no id', async () => {
    const sent = stubControlPlane({
      ...baseRoutes(),
      [PROFILES_PATH]: ok({ status: 'active' }),
    });
    await renderPage();
    const provisionedBefore = provisionedToasts();

    await submitCustomProfile();

    const toast = await screen.findByText(
      'Error creating profile: The server returned no profile id, so the session was not fulfilled.'
    );
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(sent.some((r) => r.path.endsWith('/fulfill'))).toBe(false);
    expect(screen.queryByRole('heading', { name: 'Device Provisioned' })).toBeNull();
    expect(provisionedToasts()).toBe(provisionedBefore);
  });

  it('creates the profile from the selected template, then fulfils the session with its id', async () => {
    const routes: Record<string, Answer> = {
      ...templateRoutes(),
      [FROM_TEMPLATE_PATH]: created({ id: '43', name: 'edge-gw-1' }),
      [FULFIL_PATH]: ok({ status: 'fulfilled' }),
    };
    const sent = stubControlPlane(routes);
    await renderPage();

    // The control plane records the fulfilment; the re-read returns it.
    routes[SESSION_PATH] = storedSession(true);
    await submitTemplate();

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'POST',
        path: '/api/v1/device/templates/7/create-profile',
        body: { templateId: '7', overrides: { ek_serial: 'EK-0007', mac_address: 'aa:bb:cc:dd:ee:07' } },
      })
    );
    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'POST',
        path: '/api/v1/provisioning/sessions/sess-1/fulfill',
        body: { session_id: 'sess-1', profile_id: '43' },
      })
    );
    expect(await screen.findByRole('heading', { name: 'Device Provisioned' })).toBeDefined();
    expect(screen.getByRole('button', { name: 'View Profile' })).toBeDefined();
  });

  it('shows a refused fulfilment of a template profile as a destructive toast, not as a provisioned device', async () => {
    const sent = stubControlPlane({
      ...templateRoutes(),
      [FROM_TEMPLATE_PATH]: created({ id: '43', name: 'edge-gw-1' }),
      [FULFIL_PATH]: refused(400, 'configdelivery: session already fulfilled: sess-1'),
    });
    await renderPage();
    const provisionedBefore = provisionedToasts();

    await submitTemplate();

    const toast = await screen.findByText(
      'Error provisioning device: Profile 43 was created, but the session was not fulfilled: configdelivery: session already fulfilled: sess-1'
    );
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(sent).toContainEqual({
      method: 'POST',
      path: '/api/v1/provisioning/sessions/sess-1/fulfill',
      body: { session_id: 'sess-1', profile_id: '43' },
    });
    expect(screen.queryByRole('heading', { name: 'Device Provisioned' })).toBeNull();
    expect(provisionedToasts()).toBe(provisionedBefore);
    expect(screen.getByRole('button', { name: SUBMIT })).toBeDefined();
  });

  it('fulfils nothing and says so when the profile created from a template has no id', async () => {
    const sent = stubControlPlane({
      ...templateRoutes(),
      [FROM_TEMPLATE_PATH]: created({ name: 'edge-gw-1' }),
    });
    await renderPage();
    const provisionedBefore = provisionedToasts();

    await submitTemplate();

    const toast = await screen.findByText(
      'Error provisioning device: The server returned no profile id, so the session was not fulfilled.'
    );
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(sent.some((r) => r.path.endsWith('/fulfill'))).toBe(false);
    expect(screen.queryByRole('heading', { name: 'Device Provisioned' })).toBeNull();
    expect(provisionedToasts()).toBe(provisionedBefore);
  });

  it('withholds both provision buttons when the server does not offer the fulfil', async () => {
    const sent = stubControlPlane({ ...baseRoutes(), 'GET /api/v1/capabilities': caps([FULFIL_OP]) });
    await renderPage();

    await waitFor(() => {
      const button = screen.getByRole('button', { name: SUBMIT });
      expect(button.getAttribute('data-capability-op')).toBe(FULFIL_OP);
      expect(button.getAttribute('data-capability-enabled')).toBe('false');
      expect(button.getAttribute('title')).toBe(NOT_CONFIGURED);
    });

    fireEvent.mouseDown(screen.getByRole('tab', { name: 'Custom Profile' }), { button: 0 });
    fireEvent.change(await screen.findByLabelText('Profile Name'), { target: { value: 'rack-07' } });
    const custom = screen.getByRole('button', { name: SUBMIT });
    expect(custom.getAttribute('data-capability-op')).toBe(FULFIL_OP);
    expect((custom as HTMLButtonElement).disabled).toBe(true);
    expect(custom.getAttribute('title')).toBe(NOT_CONFIGURED);
    await act(async () => {
      fireEvent.click(custom);
    });

    expect(sent.some((r) => r.path.endsWith('/fulfill'))).toBe(false);
    expect(sent.some((r) => r.path === '/api/v1/device/profiles')).toBe(false);
  });

  it('sends no session read and says so when the server does not offer it', async () => {
    const sent = stubControlPlane({ ...baseRoutes(), 'GET /api/v1/capabilities': caps([READ_OP]) });
    render(withControlPlane(<SessionDetailClient />));

    const notice = await screen.findByTestId('session-not-enabled');
    expect(notice.textContent).toContain(NOT_CONFIGURED);
    expect(sent.some((r) => r.path === '/api/v1/provisioning/sessions/sess-1')).toBe(false);
  });
});
