'use client';

/**
 * IAM policy hooks for the policy create and detail pages (#2054).
 *
 * The REST wire shape differs from the SDK/proto declaration (#445): a
 * policy may come back nested under `policy` or flat, with camelCase or
 * snake_case keys, so these hooks normalise it once for the pages.
 */

import {
  useApi,
  useIAM,
  useMutation,
  type CreateIAMPolicyRequest,
  type UseMutationOptions,
} from 'trusted-platform-sdk';

/** The one-rule policy the create form collects. */
export interface PolicyDraft {
  name: string;
  description: string;
  effect: string;
  /** Comma-separated actions. */
  actions: string;
  /** Comma-separated resources. */
  resources: string;
}

/** A policy as the detail page shows it. */
export interface PolicyDetail {
  description?: string;
  priority: number;
  yaml: string;
}

interface PolicyWire {
  description?: string;
  priority?: number;
  spec_yaml?: string;
  specYaml?: string;
  spec?: string;
}

function splitList(value: string): string[] {
  return value
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** Renders the one-rule policy YAML the create page submits. */
export function buildPolicyYaml(tenantId: string, draft: PolicyDraft): string {
  const actions = splitList(draft.actions);
  const resources = splitList(draft.resources);
  return [
    'apiVersion: v1',
    'kind: Policy',
    'metadata:',
    `  name: ${draft.name}`,
    `  tenant: ${tenantId}`,
    `  description: ${draft.description || ''}`,
    'spec:',
    '  rules:',
    '    - name: rule-1',
    `      effect: ${draft.effect}`,
    `      actions: [${actions.join(', ')}]`,
    `      resources: [${resources.map((r) => `"${r}"`).join(', ')}]`,
  ].join('\n');
}

/** Creates a policy from a draft through the SDK; refuses without a tenant. */
export function useCreatePolicy(
  tenantId: string | null | undefined,
  options?: UseMutationOptions<unknown, PolicyDraft>,
) {
  const iam = useIAM();
  return useMutation<unknown, PolicyDraft>(async (draft: PolicyDraft) => {
    if (!tenantId) throw new Error('No tenant available');
    const yaml = buildPolicyYaml(tenantId, draft);
    // The platform IAM REST handler reads the YAML from the snake_case
    // `spec_yaml` field; send all three known names so the call works
    // however the SDK serialises the request.
    const request: CreateIAMPolicyRequest & { spec: string; spec_yaml: string } = {
      tenantId,
      name: draft.name,
      description: draft.description,
      specYaml: yaml,
      spec: yaml,
      spec_yaml: yaml,
    };
    return iam.createPolicy(request);
  }, options);
}

/** Normalises the GetPolicy wire response. */
export function toPolicyDetail(raw: unknown): PolicyDetail | null {
  const wire = raw as (PolicyWire & { policy?: PolicyWire }) | null | undefined;
  const p = wire?.policy ?? wire ?? null;
  if (!p) return null;
  return {
    description: p.description,
    priority: p.priority ?? 0,
    yaml: p.spec_yaml ?? p.specYaml ?? p.spec ?? '',
  };
}

/** Loads one policy by name for the tenant. */
export function usePolicyDetail(tenantId: string | null | undefined, policyName: string) {
  const iam = useIAM();
  const result = useApi(() => {
    if (!tenantId) return Promise.reject(new Error('No tenant ID'));
    return iam.getPolicy(tenantId, policyName);
  }, [tenantId, policyName]);
  return { ...result, policy: toPolicyDetail(result.data) };
}
