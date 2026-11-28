'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Gated } from '@/components/features/capabilities/gated';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

export interface PolicyEditInput {
  description: string;
  priority: number;
}

export interface PolicyEditCardProps {
  initialDescription: string;
  initialPriority: number;
  initialSpecYaml: string;
  save: (input: PolicyEditInput) => Promise<void>;
  onSaved: () => void;
  onCancel: () => void;
}

/**
 * Edits a policy's description and priority; the caller's save reaches the SDK
 * updatePolicy. The server refuses every non-empty spec_yaml on update, so the
 * spec is shown read-only: to change it, delete and re-create the policy.
 */
/** The server's op the Save button performs (#2054). */
export const UPDATE_POLICY_OP = 'PUT /api/v1/iam/tenants/{tenant}/policies/{id}';

export function PolicyEditCard({
  initialDescription,
  initialPriority,
  initialSpecYaml,
  save,
  onSaved,
  onCancel,
}: PolicyEditCardProps) {
  const [description, setDescription] = useState(initialDescription);
  const [priority, setPriority] = useState(String(initialPriority));
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSave = !pending;

  const handleSave = async () => {
    if (!canSave) return;
    setPending(true);
    setError(null);
    try {
      const parsed = priority.trim() === '' ? 0 : Number(priority);
      await save({ description, priority: parsed });
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update policy');
    } finally {
      setPending(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Edit policy</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="policy-edit-description">Description</Label>
          <Input
            id="policy-edit-description"
            value={description}
            disabled={pending}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="policy-edit-priority">Priority</Label>
          <Input
            id="policy-edit-priority"
            type="number"
            value={priority}
            disabled={pending}
            onChange={(e) => setPriority(e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <p id="policy-edit-spec-label" className="text-sm font-medium">
            Spec (YAML, read-only)
          </p>
          <pre
            aria-labelledby="policy-edit-spec-label"
            className="font-mono text-xs whitespace-pre-wrap rounded-md border bg-muted p-3"
          >
            {initialSpecYaml}
          </pre>
          <p className="text-xs text-muted-foreground">
            To change the spec, delete and re-create the policy
          </p>
        </div>
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
      </CardContent>
      <CardFooter className="flex justify-end gap-2">
        <Button variant="outline" onClick={onCancel} disabled={pending}>
          Cancel
        </Button>
        <Gated op={UPDATE_POLICY_OP}>
          <Button onClick={() => void handleSave()} disabled={!canSave}>
            {pending ? 'Saving' : 'Save'}
          </Button>
        </Gated>
      </CardFooter>
    </Card>
  );
}
