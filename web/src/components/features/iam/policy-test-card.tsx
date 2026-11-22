'use client';

import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

export interface PolicyTestRequest {
  subjectId: string;
  action: string;
  resource: string;
  roles: string[];
}

export interface PolicyTestResult {
  allowed: boolean;
  matchedPolicy?: string;
  matchedRule?: string;
}

export interface PolicyTestCardProps {
  /** Evaluates the tenant's policies for one request (PlatformIAMService.TestPolicy). */
  test: (req: PolicyTestRequest) => Promise<PolicyTestResult>;
}

/**
 * PolicyTestCard asks the server whether a subject may perform an action on
 * a resource under the tenant's policies, and shows the decision with the
 * policy and rule that made it (#2054).
 */
export function PolicyTestCard({ test }: PolicyTestCardProps) {
  const [subjectId, setSubjectId] = useState('');
  const [action, setAction] = useState('');
  const [resource, setResource] = useState('');
  const [roles, setRoles] = useState('');
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<PolicyTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const ready = subjectId.trim() !== '' && action.trim() !== '' && resource.trim() !== '';

  const run = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!ready || pending) return;
    setPending(true);
    setResult(null);
    setError(null);
    try {
      const decision = await test({
        subjectId: subjectId.trim(),
        action: action.trim(),
        resource: resource.trim(),
        roles: roles
          .split(',')
          .map((role) => role.trim())
          .filter((role) => role !== ''),
      });
      setResult(decision);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setPending(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Test policy</CardTitle>
        <CardDescription>
          Check whether a subject may perform an action on a resource under this tenant&apos;s policies.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form className="space-y-4" onSubmit={run}>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="policy-test-subject">Subject</Label>
              <Input
                id="policy-test-subject"
                value={subjectId}
                onChange={(e) => setSubjectId(e.target.value)}
                placeholder="user-1"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="policy-test-action">Action</Label>
              <Input
                id="policy-test-action"
                value={action}
                onChange={(e) => setAction(e.target.value)}
                placeholder="read"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="policy-test-resource">Resource</Label>
              <Input
                id="policy-test-resource"
                value={resource}
                onChange={(e) => setResource(e.target.value)}
                placeholder="kv://config/*"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="policy-test-roles">Roles</Label>
              <Input
                id="policy-test-roles"
                value={roles}
                onChange={(e) => setRoles(e.target.value)}
                placeholder="admin, viewer"
              />
            </div>
          </div>
          <Button type="submit" disabled={!ready || pending}>
            {pending ? 'Testing' : 'Run test'}
          </Button>
          {error && <p className="text-sm text-destructive">{error}</p>}
          {result && (
            <div role="status" className="space-y-1 text-sm">
              <p className="font-medium">{result.allowed ? 'Allowed' : 'Denied'}</p>
              {result.matchedPolicy && <p>Policy: {result.matchedPolicy}</p>}
              {result.matchedRule && <p>Rule: {result.matchedRule}</p>}
            </div>
          )}
        </form>
      </CardContent>
    </Card>
  );
}
