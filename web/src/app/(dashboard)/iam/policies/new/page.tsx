'use client';

/**
 * Create Policy page — minimal form that builds a canonical IAM Policy
 * YAML from the entered rules and POSTs it to the platform IAM REST
 * endpoint, then routes back to /iam/policies.
 */

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useIAM, useToast, useMutation } from '@/hooks';
import { useAuth } from '@/contexts/AuthContext';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Loader2 } from 'lucide-react';

import type { CreateIAMPolicyRequest } from 'trusted-platform-sdk';

export default function NewPolicyPage() {
  const router = useRouter();
  const { toast } = useToast();
  const iam = useIAM();
  const { tenantId, isLoading: authLoading } = useAuth();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [effect, setEffect] = useState('allow');
  const [actions, setActions] = useState('read');
  const [resources, setResources] = useState('*');

  const createMutation = useMutation(
    async () => {
      if (!tenantId) throw new Error('No tenant available');
      const ruleActions = actions
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      const ruleResources = resources
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      const yaml = [
        'apiVersion: v1',
        'kind: Policy',
        'metadata:',
        `  name: ${name}`,
        `  tenant: ${tenantId}`,
        `  description: ${description || ''}`,
        'spec:',
        '  rules:',
        '    - name: rule-1',
        `      effect: ${effect}`,
        `      actions: [${ruleActions.join(', ')}]`,
        `      resources: [${ruleResources.map((r) => `"${r}"`).join(', ')}]`,
      ].join('\n');
      // The platform IAM REST handler reads the YAML from the
      // snake_case `spec_yaml` field; send all three known names so
      // the call works regardless of how the SDK serializes the
      // request shape.
      // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
      // The SDK request plus the spec keys the REST API also reads.
      const request: CreateIAMPolicyRequest & { spec: string; spec_yaml: string } = {
        tenantId, name, description, specYaml: yaml, spec: yaml, spec_yaml: yaml,
      };
      return iam.createPolicy(request);
    },
    {
      onSuccess: () => {
        toast({ title: 'Policy created', variant: 'success' });
        router.push('/iam/policies');
      },
      onError: (err) => {
        toast({
          title: 'Failed to create policy',
          description: err instanceof Error ? err.message : 'Unknown error',
          variant: 'destructive',
        });
      },
    },
  );

  if (authLoading) {
    return (
      <div className="container mx-auto py-6">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );
  }

  return (
    <div className="container mx-auto py-6 max-w-2xl">
      <Card>
        <CardHeader>
          <CardTitle>Create Policy</CardTitle>
          <CardDescription>
            Define an ABAC policy with one rule. Use the YAML editor for
            multi-rule policies after creation.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="name">Name *</Label>
            <Input
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="allow-read"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="description">Description</Label>
            <Input
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Allow all reads"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="effect">Effect</Label>
            <Select value={effect} onValueChange={setEffect}>
              <SelectTrigger id="effect">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="allow">Allow</SelectItem>
                <SelectItem value="deny">Deny</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="actions">Actions (comma-separated)</Label>
            <Input
              id="actions"
              value={actions}
              onChange={(e) => setActions(e.target.value)}
              placeholder="read, write"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="resources">Resources (comma-separated)</Label>
            <Textarea
              id="resources"
              value={resources}
              onChange={(e) => setResources(e.target.value)}
              placeholder='*, "kv://config/*"'
              rows={3}
            />
          </div>
          <div className="flex gap-2 justify-end">
            <Button variant="outline" onClick={() => router.push('/iam/policies')}>
              Cancel
            </Button>
            <Button
              onClick={() => createMutation.mutate(undefined)}
              disabled={!name || createMutation.isLoading}
            >
              {createMutation.isLoading && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Create Policy
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
