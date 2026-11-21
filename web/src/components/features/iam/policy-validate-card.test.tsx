import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { PolicyValidateCard } from './policy-validate-card';

// The policy detail page validates its spec through the SDK
// validatePolicy (#2054): the card reports the server's verdict and the
// rule errors it returns, or the failure of the call itself.

const spec = 'rules:\n  - effect: allow\n';

describe('PolicyValidateCard', () => {
  afterEach(() => {
    cleanup();
  });

  it('calls validate once with the spec YAML', async () => {
    const validate = vi.fn().mockResolvedValue({ valid: true });
    render(<PolicyValidateCard specYaml={spec} validate={validate} />);

    fireEvent.click(screen.getByRole('button', { name: 'Validate' }));

    await waitFor(() => expect(validate).toHaveBeenCalledTimes(1));
    expect(validate).toHaveBeenCalledWith(spec);
  });

  it('shows a valid policy', async () => {
    const validate = vi.fn().mockResolvedValue({ valid: true });
    render(<PolicyValidateCard specYaml={spec} validate={validate} />);

    fireEvent.click(screen.getByRole('button', { name: 'Validate' }));

    expect(await screen.findByText('Policy is valid')).toBeTruthy();
  });

  it('lists the errors of an invalid policy', async () => {
    const validate = vi.fn().mockResolvedValue({ valid: false, errors: ['bad rule'] });
    render(<PolicyValidateCard specYaml={spec} validate={validate} />);

    fireEvent.click(screen.getByRole('button', { name: 'Validate' }));

    const item = await screen.findByText('bad rule');
    expect(item.tagName).toBe('LI');
    expect(screen.queryByText('Policy is valid')).toBeNull();
  });

  it('shows the message of a failed call', async () => {
    const validate = vi.fn().mockRejectedValue(new Error('server unreachable'));
    render(<PolicyValidateCard specYaml={spec} validate={validate} />);

    fireEvent.click(screen.getByRole('button', { name: 'Validate' }));

    expect(await screen.findByText(/server unreachable/)).toBeTruthy();
    expect(screen.queryByText('Policy is valid')).toBeNull();
  });

  it('disables Validate when there is no spec', () => {
    render(<PolicyValidateCard specYaml="" validate={vi.fn()} />);

    expect((screen.getByRole('button', { name: 'Validate' }) as HTMLButtonElement).disabled).toBe(true);
  });
});
