import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

// The write controls are capability-gated (#2054); these cases run with
// every op offered.
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: () => ({ enabled: true }),
  }),
}));

import { PolicyEditCard } from './policy-edit-card';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function renderCard(overrides: {
  save?: (input: { description: string; priority: number; specYaml: string }) => Promise<void>;
  onSaved?: () => void;
  onCancel?: () => void;
} = {}) {
  const save = overrides.save ?? vi.fn().mockResolvedValue(undefined);
  const onSaved = overrides.onSaved ?? vi.fn();
  const onCancel = overrides.onCancel ?? vi.fn();
  render(
    <PolicyEditCard
      initialDescription="old desc"
      initialPriority={3}
      initialSpecYaml={'rules:\n  - allow\n'}
      save={save}
      onSaved={onSaved}
      onCancel={onCancel}
    />,
  );
  return { save, onSaved, onCancel };
}

const description = () => screen.getByLabelText('Description') as HTMLInputElement;
const priority = () => screen.getByLabelText('Priority') as HTMLInputElement;
const spec = () => screen.getByLabelText('Spec (YAML)') as HTMLTextAreaElement;
const saveButton = () => screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement;

describe('PolicyEditCard', () => {
  it('starts the fields with the initial values', () => {
    renderCard();
    expect(description().value).toBe('old desc');
    expect(priority().type).toBe('number');
    expect(priority().value).toBe('3');
    expect(spec().value).toBe('rules:\n  - allow\n');
  });

  it('saves the edited description, priority and spec and then reports saved', async () => {
    const { save, onSaved } = renderCard();
    fireEvent.change(description(), { target: { value: 'new desc' } });
    fireEvent.change(priority(), { target: { value: '7' } });
    fireEvent.change(spec(), { target: { value: 'rules: []\n' } });
    fireEvent.click(saveButton());
    await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1));
    expect(save).toHaveBeenCalledTimes(1);
    expect(save).toHaveBeenCalledWith({ description: 'new desc', priority: 7, specYaml: 'rules: []\n' });
  });

  it('shows a refused save in place and keeps the edited spec', async () => {
    const save = vi.fn().mockRejectedValue(new Error('policy spec is invalid'));
    const { onSaved } = renderCard({ save });
    fireEvent.change(spec(), { target: { value: 'rules: bad' } });
    fireEvent.click(saveButton());
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('policy spec is invalid');
    expect(onSaved).not.toHaveBeenCalled();
    expect(spec().value).toBe('rules: bad');
  });

  it('disables Save when the spec is empty or only spaces', () => {
    const { save } = renderCard();
    fireEvent.change(spec(), { target: { value: '' } });
    expect(saveButton().disabled).toBe(true);
    fireEvent.change(spec(), { target: { value: '   ' } });
    expect(saveButton().disabled).toBe(true);
    fireEvent.click(saveButton());
    expect(save).not.toHaveBeenCalled();
  });

  it('cancels without saving', () => {
    const { save, onCancel } = renderCard();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(save).not.toHaveBeenCalled();
  });
});
