'use client';

import { useEffect, useState } from 'react';

import { Button, Input, Label } from '@/components/ui';
import { Gated } from '@/components/features/capabilities/gated';

export interface AppRenameFormProps {
  /** The application's current name. */
  name: string;
  /** True while the update request is in flight. */
  saving: boolean;
  /** Called with the trimmed new name when Save is clicked. */
  onSave: (name: string) => void;
}

/**
 * AppRenameForm edits an IAM application's name. Save stays disabled
 * until the trimmed draft is non-empty and differs from the current name.
 */
/** The server's op the rename Save button performs (#2054). */
export const UPDATE_APP_OP = 'PUT /api/v1/iam/tenants/{tenant}/apps/{id}';

export function AppRenameForm({ name, saving, onSave }: AppRenameFormProps) {
  const [draft, setDraft] = useState(name);

  useEffect(() => {
    setDraft(name);
  }, [name]);

  const trimmed = draft.trim();
  const unchanged = trimmed === '' || trimmed === name.trim();

  return (
    <form
      className="space-y-2"
      onSubmit={(e) => {
        e.preventDefault();
        if (!unchanged && !saving) onSave(trimmed);
      }}
    >
      <Label htmlFor="app-rename-input">Application name</Label>
      <div className="flex gap-2">
        <Input
          id="app-rename-input"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
        />
        <Gated op={UPDATE_APP_OP}>
          <Button type="submit" disabled={unchanged || saving}>
            {saving ? 'Saving…' : 'Save'}
          </Button>
        </Gated>
      </div>
    </form>
  );
}
