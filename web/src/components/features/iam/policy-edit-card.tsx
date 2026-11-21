'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';

export interface PolicyEditInput {
  description: string;
  priority: number;
  specYaml: string;
}

export interface PolicyEditCardProps {
  initialDescription: string;
  initialPriority: number;
  initialSpecYaml: string;
  save: (input: PolicyEditInput) => Promise<void>;
  onSaved: () => void;
  onCancel: () => void;
}

/** Edits a policy's description, priority and spec; the caller's save reaches the SDK updatePolicy. */
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
  const [specYaml, setSpecYaml] = useState(initialSpecYaml);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSave = specYaml.trim() !== '' && !pending;

  const handleSave = async () => {
    if (!canSave) return;
    setPending(true);
    setError(null);
    try {
      const parsed = priority.trim() === '' ? 0 : Number(priority);
      await save({ description, priority: parsed, specYaml });
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
          <Label htmlFor="policy-edit-spec">Spec (YAML)</Label>
          <Textarea
            id="policy-edit-spec"
            className="font-mono text-xs min-h-[240px]"
            value={specYaml}
            disabled={pending}
            onChange={(e) => setSpecYaml(e.target.value)}
          />
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
        <Button onClick={() => void handleSave()} disabled={!canSave}>
          {pending ? 'Saving' : 'Save'}
        </Button>
      </CardFooter>
    </Card>
  );
}
