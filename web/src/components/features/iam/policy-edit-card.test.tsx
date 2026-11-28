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
  save?: (input: { description: string; priority: number }) => Promise<void>;
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
// The server refuses every non-empty spec_yaml on update, so the card offers
// no spec field to edit.
const expectNoSpecField = () => expect(screen.queryByLabelText('Spec (YAML)')).toBeNull();
const saveButton = () => screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement;

describe('PolicyEditCard', () => {
  it('starts the fields with the initial values and offers no spec field', () => {
    renderCard();
    expect(description().value).toBe('old desc');
    expect(priority().type).toBe('number');
    expect(priority().value).toBe('3');
    expectNoSpecField();
    expect(screen.getByText('To change the spec, delete and re-create the policy')).toBeTruthy();
  });

  it('saves the edited description and priority only, then reports saved', async () => {
    const { save, onSaved } = renderCard();
    fireEvent.change(description(), { target: { value: 'new desc' } });
    fireEvent.change(priority(), { target: { value: '7' } });
    fireEvent.click(saveButton());
    await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1));
    expect(save).toHaveBeenCalledTimes(1);
    expect(save).toHaveBeenCalledWith({ description: 'new desc', priority: 7 });
  });

  it('shows a refused save in place and keeps the edited description', async () => {
    const save = vi.fn().mockRejectedValue(new Error('policy update refused'));
    const { onSaved } = renderCard({ save });
    fireEvent.change(description(), { target: { value: 'edited desc' } });
    fireEvent.click(saveButton());
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('policy update refused');
    expect(onSaved).not.toHaveBeenCalled();
    expect(description().value).toBe('edited desc');
  });

  it('enables Save with the fields unchanged', async () => {
    const { save, onSaved } = renderCard();
    expect(saveButton().disabled).toBe(false);
    fireEvent.click(saveButton());
    await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1));
    expect(save).toHaveBeenCalledTimes(1);
    expect(save).toHaveBeenCalledWith({ description: 'old desc', priority: 3 });
  });

  it('cancels without saving', () => {
    const { save, onCancel } = renderCard();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(save).not.toHaveBeenCalled();
  });
});
