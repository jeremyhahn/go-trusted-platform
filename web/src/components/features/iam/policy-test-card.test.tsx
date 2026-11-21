import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { PolicyTestCard } from './policy-test-card';

// The policies page tests an access decision through
// PlatformIAMService.TestPolicy (#2054): the card collects a subject, an
// action, a resource and roles, and reports the decision the server makes.

function fill(subject: string, action: string, resource: string, roles = '') {
  fireEvent.change(screen.getByLabelText('Subject'), { target: { value: subject } });
  fireEvent.change(screen.getByLabelText('Action'), { target: { value: action } });
  fireEvent.change(screen.getByLabelText('Resource'), { target: { value: resource } });
  fireEvent.change(screen.getByLabelText('Roles'), { target: { value: roles } });
}

function runButton(): HTMLButtonElement {
  return screen.getByRole('button', { name: 'Run test' }) as HTMLButtonElement;
}

describe('PolicyTestCard', () => {
  // The runner has no globals, so nothing unmounts a rendered tree for us.
  afterEach(cleanup);

  it('disables Run test until subject, action and resource are filled', () => {
    render(<PolicyTestCard test={vi.fn()} />);
    expect(runButton().disabled).toBe(true);

    fill('user-1', 'read', '   ');
    expect(runButton().disabled).toBe(true);

    fill('user-1', 'read', 'kv://config/*');
    expect(runButton().disabled).toBe(false);
  });

  it('sends the request with the roles split and trimmed', async () => {
    const test = vi.fn().mockResolvedValue({ allowed: true });
    render(<PolicyTestCard test={test} />);

    fill('user-1', 'read', 'kv://config/*', 'admin, viewer, ');
    fireEvent.click(runButton());

    await waitFor(() => expect(test).toHaveBeenCalledTimes(1));
    expect(test).toHaveBeenCalledWith({
      subjectId: 'user-1',
      action: 'read',
      resource: 'kv://config/*',
      roles: ['admin', 'viewer'],
    });
  });

  it('reports an allowed decision with the matched policy', async () => {
    const test = vi
      .fn()
      .mockResolvedValue({ allowed: true, matchedPolicy: 'allow-read', matchedRule: 'rule-1' });
    render(<PolicyTestCard test={test} />);

    fill('user-1', 'read', 'kv://config/*');
    fireEvent.click(runButton());

    const status = await screen.findByRole('status');
    expect(status.textContent).toContain('Allowed');
    expect(status.textContent).toContain('allow-read');
    expect(status.textContent).toContain('rule-1');
  });

  it('reports a denied decision', async () => {
    const test = vi.fn().mockResolvedValue({ allowed: false });
    render(<PolicyTestCard test={test} />);

    fill('user-1', 'write', 'kv://config/*');
    fireEvent.click(runButton());

    const status = await screen.findByRole('status');
    expect(status.textContent).toContain('Denied');
  });

  it('shows the error of a failed test', async () => {
    const test = vi.fn().mockRejectedValue(new Error('policy engine unavailable'));
    render(<PolicyTestCard test={test} />);

    fill('user-1', 'read', 'kv://config/*');
    fireEvent.click(runButton());

    expect(await screen.findByText('policy engine unavailable')).toBeDefined();
    expect(screen.queryByRole('status')).toBeNull();
  });
});
